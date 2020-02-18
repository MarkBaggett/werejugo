from collections import UserList
import pxpowershell
import re
import resolver
import datetime
from Registry.Registry import Registry
import codecs

class LocationItem:
    def __init__(self,timestamp, latitude, longitude, accuracy, source, notes):
        self.timestamp = timestamp
        self.latitude = latitude
        self.longitude = longitude
        self.accuracy = accuracy
        self.source = source
        self.notes = notes

    def __repr__(self):
        date = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"LocationItem(datetime={date}, latitude={self.latitude}, longitude={self.longitude}, accuracy={self.accuracy},source={self.source}, notes={self.notes})"


class LocationList(UserList):
    def load_wifi_diagnostics(self, path_to_evtx):
        powershell_cmd = 'get-winevent  -filterHashTable @{path="%s"; id=6100 } | ForEach-Object {if ($_.Message.Contains("Details about wireless connectivity diagnosis:")) {Write-output $_.Message }}' % (path_to_evtx)
        diagnostic_events_text = pxpowershell.powershell_output(powershell_cmd)
        #finds event 6100 in specified event logs and appends items list
        #Typically located here c:\windows\system32\Winevt\Logs\System.evtx        
        items =  diagnostic_events_text.count(b"Details about wireless connectivity diagnosis:")
        if not items:
            return
        for eachentry in diagnostic_events_text.split(b"Details about wireless connectivity diagnosis:")[1:]:
            constart = re.search(rb"Connection status summary\s+Connection started at: (.*)", eachentry)
            if not constart:
                continue
            constart = datetime.datetime.strptime(constart.group(1).decode(), "%Y-%m-%d %H:%M:%S-%f")
            access_points = re.findall(rb"(\w\w-\w\w-\w\w-\w\w-\w\w-\w\w).*?Infra.*?(-\d+)\s+(\S+)",eachentry)
            print(constart)
            print(access_points)
            lat,long,accuracy = resolver.google_sids_to_location(access_points)
            self.data.append(LocationItem(constart, lat,long,accuracy, "Wireless Diagnostic 6100", ""))
        return

    def load_wlan_autoconfig(self, path_to_reg = ".\sof1", path_to_evtx = 'c:\windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx'):
        for eventid in [8001, 11004, 11005, 11010, 11006, 12011, 12012, 12013]:
            powershell_cmd = "get-winevent  -filterHashTable @{path='%s'; id=%d } | Select-Object -Property Message,TimeCreated | fl" % (path_to_evtx,eventid)
            psoutput = pxpowershell.powershell_output(powershell_cmd)
            items = psoutput.count(b"Message     :")
            if not items:
                return
            for eachentry in psoutput.split(rb"Message     :")[1:]:
                #import pdb;pdb.set_trace()
                data = re.search(rb"Profile Name: (\S+).*?TimeCreated : ([\d/: ]+) [AP]M", eachentry, re.DOTALL)
                if not data:
                    continue    
                ssid = data.group(1).decode()
                tstamp = datetime.datetime.strptime(data.group(2).decode(), "%m/%d/%Y %H:%M:%S")
                options = {'ssid':ssid}
                mac_address = resolver.registry_wifi_to_BSSID(ssid, path_to_reg)
                if mac_address:
                    options['netid'] = mac_address.decode()
                wigle_data = resolver.wigle_search(netid=mac_address.decode())
                if wigle_data and len(wigle_data['results']) > 1:
                    wigle_data = resolver.wigle_search(**options)
                if wigle_data and wigle_data.get("resultCount")==1:
                    lat = wigle_data.get("results").get("trilat")
                    long = wigle_data.get("results").get("trilong")
                    self.data.append(LocationItem(tstamp, lat,long, 0, f"wlan-{eventid}", "retrieved from wigle" ))
    
    def load_reg_history(self, path_to_reg):
        reg_handle = Registry(path_to_reg)
        for eachsubkey in reg_handle.open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged").subkeys():
            reg_mac = eachsubkey.value("DefaultGatewayMac").value()
            if not reg_mac:
                continue
            BSSID = b':'.join(codecs.encode(reg_mac[i:i+1],"hex") for i in range(0,6))
            Description = eachsubkey.value("Description").value()
            DnsSuffix = eachsubkey.value("DnsSuffix").value()
            SSID = eachsubkey.value("FirstNetwork").value()
            ProfileGuid = eachsubkey.value("ProfileGuid").value()
            notes = f"'{Description},{SSID},{DnsSuffix}'"
            nettype,first,last = resolver.get_profile_info(reg_handle, ProfileGuid)
            if nettype=="Wireless":
                result = resolver.wigle_search(netid=BSSID.decode())
                if result and len(result['results']) > 1:
                    result = resolver.wigle_search(netid=BSSID.decode(), ssid=SSID)
                if result and len(result['results'])==1:
                    self.data.append(LocationItem(first, result['results'][0]['trilat'], result['results'][0]['trilong'], 0, "History-First", notes))
                    self.data.append(LocationItem(last, result['results'][0]['trilat'], result['results'][0]['trilong'], 0, "History-Last", notes))
        return


mylist = LocationList()
mylist.load_wifi_diagnostics(".\sys.evtx")
mylist.load_wlan_autoconfig(".\wlan.evtx")
mylist.load_reg_history(".\sof1")
mac = resolver.registry_wifi_to_BSSID("marimba", ".\sof1")
print(resolver.wigle_search(ssid="fn2178"))
print(resolver.wigle_search(netid=mac, ssid="marimba"))
print(mylist)