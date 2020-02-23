import logging
from collections import UserList, defaultdict
import pxpowershell
import re
import resolver
import datetime
from Registry.Registry import Registry
import codecs
import pathlib
import pickle
import pyesedb
import config
import webbrowser


class LocationItem:
    def __init__(self,latitude, longitude, accuracy, source, notes):
        self.latitude = latitude
        self.longitude = longitude
        self.accuracy = accuracy
        self.source = source
        self.notes = notes

    def __eq__(self,compare_to):
        equal = self.latitude == compare_to.latitude
        equal = equal and self.longitude == compare_to.longitude
        equal = equal and self.accuracy == compare_to.accuracy
        equal = equal and self.source == compare_to.source

    def __repr__(self):
        #date = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"LocationItem(latitude={self.latitude}, longitude={self.longitude}, accuracy={self.accuracy},source={self.source}, notes={self.notes})"

class LocationList(UserList):
    def __init__(self, *args,**kwargs):
        self.ap_ssids = defaultdict(lambda :[])
        self.ap_bssids = defaultdict(lambda :[])
        super().__init__(*args,**kwargs)

    def save(self, fname):
        print(f"Dumping cache to file {fname}")
        data = (list(self.ap_bssids.items()), list(self.ap_ssids.items()), self.data)
        with open(fname,"wb") as fhandle:
            pickle.dump(data, fhandle, protocol=pickle.HIGHEST_PROTOCOL)

    def load(self, fname):
        with open(fname, "rb") as fhandle:
            data = pickle.load(fhandle)
            self.ap_bssids.update(data[0])
            self.ap_ssids.update(data[1])
            self.data.extend(data[2])
            
    def best_ssid_location(self,tgt_ssid):
        best_location = None
        best_accuracy = 999999999999999999999
        for eachloc in self.ap_ssids.get(tgt_ssid, []):
            if eachloc.accuracy < best_accuracy:
                best_location = eachloc
                best_accuracy = eachloc.accuracy
        return best_location

    def best_bssid_location(self,tgt_bssid):
        best_location = None
        best_accuracy = 999999999999999999999
        for eachloc in self.ap_bssids.get(tgt_bssid, []):
            if eachloc.accuracy < best_accuracy:
                best_location = eachloc
                best_accuracy = eachloc.accuracy
        return best_location

    def load_registry_wigle(self, reg_path:str):
        all_registry = resolver.registry_all_wireless(reg_path)
        num_items = len(all_registry)
        row_num = 0
        for ssid, mac_address in all_registry:
            if (row_num % (int(num_items*.01) or 1)) == 0:
                print("\r|{0:-<50}| {1:3.2f}% {2}/{3}".format("X"*( 50 * row_num//num_items), 100*row_num/num_items, row_num,num_items ),end="")
            row_num += 1
            wig_results = resolver.wigle_search(mac_address)
            if isinstance(mac_address,bytes):
                mac_address.decode().upper()
            if "-" in mac_address:
                mac_address = mac_address.replace("-",":")
            if wig_results:
                location = LocationItem(wig_results[0], wig_results[1], 0, "registry history", f"wigle search {str(wig_results)}")
                if location not in self.data:
                    self.data.append(location)
                if ssid not in self.ap_ssids:
                    self.ap_ssids[ssid].append(location)
                if mac_address not in self.ap_bssids:
                    self.ap_bssids[mac_address].append(location)

    def load_registry_triangulations(self, reg_path:str):
        all_wireless = resolver.registry_all_wireless(".\sof1")
        #all_wireless = [ (mac,mac) for mac,_,_ in verified_aps][:3]
        triangulated_locations = resolver.google_triangulate_ap(all_wireless)
        for lat,long,accuracy, combo in triangulated_locations:
            new_location = LocationItem(lat,long, accuracy, f"Registry-PNL", "Triangulation with Google")
            self.data.append(new_location)
            for ssid,bssid in combo:
                if isinstance(bssid,bytes):
                    bssid.decode().upper()
                if "-" in bssid:
                    bssid = bssid.replace("-",":")
                self.ap_bssids[bssid].append(new_location)
        self.data = list(set(self.data))
  
class Event:
    def __init__(self, timestamp, location, source):
        self.timestamp=timestamp
        self.location=location
        self.source=source

    def __repr__(self):
        return f"Event(timestamp={self.timestamp}, location={self.location}, source={self.source})"


class EventList(UserList):
    def __init__(self,locations, *args,**kwargs):
        self.Locations = locations
        print("Please wait while I find all locations.  This will take a long time.")
        super().__init__(*args,**kwargs)

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
            access_points = re.findall(rb"(\w\w-\w\w-\w\w-\w\w-\w\w-\w\w).*?Infra.*?(-\d+)\s*(\S+)\s*(\S+)",eachentry)
            location_data = [(mac,sig,chan) for mac,sig,chan,ssid in access_points]
            macs = [mac for mac,sig,chan,ssid in access_points]
            ssids = [ssid for mac,sig,chan,ssid in access_points]
            lat,long,accuracy = resolver.google_networks_to_location(location_data)
            note = ",".join(list(set([x.decode() for x in ssids])))
            newlocation = LocationItem(lat,long,accuracy, "Google Network Triangulation", f"{note}")
            if not newlocation in self.Locations.data:
                self.Locations.append(newlocation)
            for ssid in ssids:
                if not ssid.decode() in self.Locations.ap_ssids:
                    self.Locations.ap_ssids[ssid.decode()].append(newlocation)
            for mac in macs:
                if isinstance(mac,bytes):
                    mac = mac.decode().upper()
                if "-" in mac:
                    mac = mac.replace("-",":")
                if not mac in self.Locations.ap_bssids:
                    self.Locations.ap_bssids[mac].append(newlocation)
            self.data.append(Event(constart, newlocation, "Windows Diagnostice Event 6100"))
        return

    def load_wlan_autoconfig(self, path_to_reg = ".\sof1", path_to_evtx = 'c:\windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx'):
        known_unknown_ssids = []
        for eventid in [8001, 11004, 11005, 11010, 11006, 12011, 12012, 12013]:
            powershell_cmd = "get-winevent  -filterHashTable @{path='%s'; id=%d } | Select-Object -Property Message,TimeCreated | fl" % (path_to_evtx,eventid)
            psoutput = pxpowershell.powershell_output(powershell_cmd)
            items = psoutput.count(b"Message     :")
            if not items:
                return
            for eachentry in psoutput.split(rb"Message     :")[1:]:
                data = re.search(rb"Profile Name: (\S+).*?TimeCreated : ([\d/: ]+) [AP]M", eachentry, re.DOTALL)
                if not data:
                    continue    
                ssid = data.group(1).decode()
                tstamp = datetime.datetime.strptime(data.group(2).decode(), "%m/%d/%Y %H:%M:%S")
                location = self.Locations.best_ssid_location(ssid)
                if location:
                    self.append(Event(tstamp, location, f"WLAN Event {eventid} {ssid}"))
                    continue

    def load_reg_history(self, path_to_reg):
        reg_handle = Registry(path_to_reg)
        for eachsubkey in reg_handle.open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged").subkeys():
            reg_mac = eachsubkey.value("DefaultGatewayMac").value()
            if not reg_mac:
                continue
            BSSID = b':'.join(codecs.encode(reg_mac[i:i+1],"hex") for i in range(0,6)).decode().upper()
            SSID = eachsubkey.value("FirstNetwork").value()
            ProfileGuid = eachsubkey.value("ProfileGuid").value()
            nettype,first,last = resolver.get_profile_info(reg_handle, ProfileGuid)
            location = None
            if nettype=="Wireless":
                if SSID in self.Locations.ap_ssids:
                    location = self.Locations.best_ssid_location(SSID)
                elif BSSID in self.Locations.ap_bssids:
                    location = self.Locations.best_bssid_location(BSSID)
                assert not isinstance(location, list)
                if location:
                    self.data.append(Event(first, location, f"{SSID} {BSSID}-First-Connect"))
                    self.data.append(Event(last, location , f"{SSID} {BSSID}-Last-Connect"))
        return

    def load_srum_wifi(self,srum_path, software_hive):
        srum_events = resolver.process_srum(srum_path, software_hive)
        for tstamp, bssid, ssid in srum_events:
            if ssid in self.Locations.ap_ssids:
                location = self.Locations.best_ssid_location(ssid)
            elif bssid in self.Locations.ap_bssids:
                location = self.Locations.best_bssid_location(bssid)
            if location:
                self.data.append(Event(tstamp, location, f"SRUM-Application-Activity {ssid} {bssid}"))

    def to_html(self,output,template="template.html"):
        result = open(template,"rb").read()
        rows= ""
        for event in self.data:
            rows += f"""<tr class="result_row"><td>{event.timestamp}</td><td>{event.source}</td><td>{event.location.latitude},{event.location.longitude}</td><td><div class="switch"><label>Off<input type="checkbox"><span class="lever"></span>On</label></div></td>"""
            #rows += f"""<td><iframe class="result_map" width="250" height="200" frameborder="0" src="https://www.bing.com/maps/embed?h250&w=200&cp={event.location.latitude}~{event.location.longitude}&lvl=11&typ=d&sty=r&src=SHELL&FORM=MBEDV8" scrolling="no"></iframe></td>"""
            rows += f"""<td><a href="https://www.google.com/maps/@{event.location.latitude},{event.location.longitude},19z">Show on Google Maps</a></td>"""
            rows += "</tr>"
        fh = open(output,"wb")
        fh.write(result.replace(b"!!!DATA!!!", rows.encode()))
        fh.close()

        
verified_aps = [(b'F8-2C-18-07-20-19', b'-88', b'1'), (b'A6-04-60-0D-F9-E7', b'-55', b'3'), (b'10-9A-DD-8B-29-1C', b'-79', b'5745000'), (b'A0-04-60-0D-68-AD', b'-67', b'5220000'), (b'A6-04-60-0D-68-AB', b'-53', b'3'), (b'A0-04-60-0D-F9-E9', b'-69', b'5220000'), (b'F8-2C-18-07-20-1B', b'-90', b'1'), (b'9C-3D-CF-73-E0-A8', b'-61', b'8'), (b'AA-04-60-0D-68-AB', b'-54', b'3')]


# F8-2C-18-07-20-19	Infra	 <unknown>	-88		1	 ATT6XFI278
# A6-04-60-0D-F9-E7	Infra	 <unknown>	-55		3	 FN2187
# 10-9A-DD-8B-29-1C	Infra	 <unknown>	-79		5745000	 BaggettGuest5GHz
# A0-04-60-0D-68-AD	Infra	 <unknown>	-67		5220000	 FN2187
# A6-04-60-0D-68-AB	Infra	 <unknown>	-53		3	 FN2187
# A0-04-60-0D-F9-E9	Infra	 <unknown>	-69		5220000	 FN2187
# F8-2C-18-07-20-1B	Infra	 <unknown>	-90		1	 ATT123
# 9C-3D-CF-73-E0-A8	Infra	 <unknown>	-61		8	 NETGEAR36
# AA-04-60-0D-68-AB	Infra	 <unknown>	-54		3	 (Unnamed Network)

if __name__ == "__main__":
    config = config.config("werejugo.yaml")
    resolver.config = config
    mylocations = LocationList()
    myevents = EventList(mylocations)

    #if pathlib.Path("locations.cache").exists() and input("A cache of locations was found from a previous run of this tool. Would you like to reload that information?").lower().startswith("y"):
    #    myevents.Locations.load("locations.cache")

    print("Discovering networks via wifi diagnostic logs...")
    myevents.load_wifi_diagnostics(".\sys.evtx")
   
    if input(f"\n{len(mylocations)} locations discovered.  Would you like to discover more locations by performing Wigle lookups of known Wireless (PNL)?").lower().startswith("y"):
        mylocations.load_registry_wigle(".\sof1")
    if input(f"\n{len(mylocations)} locations discovered.  Would you like to discover more locations by performing an exaustive (very slow) location search? ").lower().startswith("y"):
        mylocations.load_registry_triangulations(".\sof1")

    #myevents.Locations.save("locations.cache")

    print(f"Working with {len(mylocations)} locations")

    #Begin Loading Events
    myevents.load_srum_wifi(".\sr1.dat", ".\sof1")
    myevents.load_wlan_autoconfig(".\sof1", ".\wlan.evtx")
    myevents.load_reg_history(".\sof1")
    myevents.to_html("results.html")
    webbrowser.open("results.html")
    print("EVENTS: \n", myevents)
    #print("LOCATIONS \n",myevents.Locations)