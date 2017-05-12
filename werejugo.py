from Registry import Registry
import requests
import json
import struct
import openpyxl
import glob
import sys
import argparse
import datetime
import re
import lxml.etree
import Evtx.Evtx
import Evtx.Views
import Evtx.Nodes
import os

def xml_records(filename):
    #Code based on https://raw.githubusercontent.com/williballenthin/python-evtx/master/scripts/evtx_filter_records
    """
    If the second return value is not None, then it is an
      Exception encountered during parsing.  The first return value
      will be the XML string.

    @type filename str
    @rtype: generator of (etree.Element or str), (None or Exception)
    """
    with Evtx.Evtx.Evtx(filename) as evtx:
        for xml, record in Evtx.Views.evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield lxml.etree.fromstring(b"<?xml version=\"1.0\" standalone=\"yes\" ?>%s" % xml), None
            except lxml.etree.XMLSyntaxError as e:
                yield xml, e

def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    #Code based on https://raw.githubusercontent.com/williballenthin/python-evtx/master/scripts/evtx_filter_records
    """
    @type node: etree.Element
    @type tag: str
    @type ns: str
    """
    return node.find("%s%s" % (ns, tag))

def google_cheat(networks):
    #cheats using a google api key by looking up the data directly with the browser location service
    url = 'https://maps.googleapis.com/maps/api/browserlocation/json?browser=firefox&sensor=true'
    for eachnetwork in networks:
        url += '&wifi=mac:{0}|ssid:{2}|ss:{1}'.format(*eachnetwork)
    x = requests.get(url).json()
    accuracy =  "Accuracy of %s square meters" % (x['accuracy'])
    geourl =  "http://maps.google.com/maps?q=%.9f,%.9f&z=15" % (x['location']['lat'], x['location']['lng'])
    return (accuracy, geourl)

def parse_6100(path_to_evtx):
    results = []
    for node, err in xml_records(path_to_evtx):
        if err is not None:
            continue
        EventMetadata = get_child(node, "System")
        EventData = get_child(node, "EventData")
        if 6100 == int(get_child(EventMetadata, "EventID").text):
            SystemTime = get_child(EventMetadata, "TimeCreated").attrib
            #import pdb;pdb.set_trace()
            EventDescription = "".join([x.text for x in EventData])
            sids = re.findall(r"(\w\w-\w\w-\w\w-\w\w-\w\w-\w\w).*?Infra.*?&lt;\s+(-\d{1,3})\s+\d{1,8}\s+([()\w]+)",EventDescription)
            if not sids:
                continue
            accuracy,url = google_cheat(sids)
            results.append((str(SystemTime), EventDescription, accuracy, url))
    return results

def get_reg_value(path_to_file, path, key):
    rh = Registry.Registry(path_to_file)
    rk = rh.open(path)
    return rk.value(key).value()

def wigle_search(**kwargs):
    #Lookup like this  wigle_search(netid="ff:ff:ff:ff:ff")
    url = "https://api.wigle.net/api/v2/network/search"
    return requests.get(url, auth = (options.WIGLE_USER,options.WIGLE_PASS), params = kwargs).json()

def reg_date(dateblob):
    weekday = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
    year,month,day,date,hour,minute,sec,micro = struct.unpack('<8H', dateblob)
    dt =  "%s, %02d/%02d/%04d %02d:%02d:%02d.%s"  % (weekday[day], month,date,year,hour,minute,sec,micro)
    dtp = datetime.datetime.strptime(dt,"%A, %m/%d/%Y %H:%M:%S.%f")
    return dtp

def get_profile_info(reg_handle, ProfileGuid):
    nametypes = {'47':"Wireless", "06":"Wired", "17":"Broadband"}
    guid = "Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\%s" % (ProfileGuid)
    regkey = reg_handle.open(guid)
    NameType ="%02x"  % regkey.value("NameType").value()
    nettype = nametypes.get(str(NameType), "Unknown Type"+str(NameType))
    FirstConnect = reg_date(regkey.value("DateCreated").value())
    LastConnect  = reg_date(regkey.value("DateLastConnected").value())
    return nettype, FirstConnect, LastConnect

def network_history(reg_handle):
    reg_results = []
    for eachsubkey in reg_handle.open("Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged").subkeys():
        DefaultGatewayMac = eachsubkey.value("DefaultGatewayMac").value()
        BSSID = ':'.join(DefaultGatewayMac.encode("HEX")[i:i+2] for i in range(0,12,2))
        Description = eachsubkey.value("Description").value()
        DnsSuffix = eachsubkey.value("DnsSuffix").value()
        SSID = eachsubkey.value("FirstNetwork").value()
        ProfileGuid = eachsubkey.value("ProfileGuid").value()
        nettype,first,last = get_profile_info(reg_handle, ProfileGuid)
        mapurl="Not found"
        #print "TYPE:",nettype, " SSID:",SSID, "Description:", Description, "DNS SUFFIX", DnsSuffix, "MAC ADDRESS:", BSSID
        if nettype=="Wireless":
            result= wigle_search(netid=BSSID)
            if len(result['results']):
                for eachresult in result['results']:
                    print "Found: ", SSID, BSSID
                    print "First connected: ",first
                    print "Last Connected : ",last  
                    mapurl =  "http://maps.google.com/maps?q=%.9f,%.9f&z=15" % (eachresult['trilat'], eachresult['trilong'])
            #print google_cheat(BSSID, SSID)
        reg_results.append((BSSID,SSID,Description,DnsSuffix,nettype,first,last,mapurl))
    return reg_results

def reg_basic_info():
    #Retreive basic computer data
    print("Enumerating Basic Computer Data")
    osversion = get_reg_value("SOFTWARE", "Microsoft\Windows NT\CurrentVersion", "CurrentVersion")
    which_control_set = get_reg_value("SYSTEM","Select","Current")
    ControlSet = "ControlSet%03d" % (which_control_set)
    comp_name = get_reg_value("SYSTEM",ControlSet+"\Control\ComputerName\ComputerName","ComputerName")
    time_zone = get_reg_value("SYSTEM",ControlSet+"\Control\TimeZoneInformation","DayLightName")
    print osversion, which_control_set, comp_name, time_zone

def reg_interface_info():
    #Retrieve local area network connections
    print("Enumerating Local Network Interface Data")
    rh = Registry.Registry("SYSTEM")
    interfaces = rh.open(ControlSet+"\Services\Tcpip\Parameters\Interfaces").subkeys()
    for eachinterface in interfaces:
        try:
            print eachinterface.value("DhcpIPAddress").value()
            print eachinterface.value("DhcpDomain").value()
        except:
            pass

parser = argparse.ArgumentParser(description="Given a directory of SOFTWARE registry hives it will enumerate all the wireless.")
parser.add_argument("--IMAGE_MOUNT_POINT","-i",default='', help ="Geolocate all sources searching the SYSTEM volume of this mounted Windows Images . example: z:\image\C:")
#parser.add_argument("--recurse", help = "Recursively, Exhaustively search the entire drive for any usable file instead of looking in default locatoins.", action="store_true", )
parser.add_argument("--SOFTWARE_REGISTRY","-r", default="\Windows\System32\Config\SOFTWARE", help ="Location of the SOFTWARE registry keys. (Supports Wildcards) example: c:\windows\system32\config\SYSTEM*")
parser.add_argument("--SYSTEM_EVENTS","-e", default="\Windows\System32\Winevt\Logs\System.evtx", help ="Location of System Event Log specified. (Support Wildcards) Example: c:\windows\system32\Winevt\Logs\System.evtx)")
parser.add_argument("--OUTPUT","-o", default="wireless_output.xlsx", help ="Path and filename of the XLSX file to create.")
parser.add_argument("--WIGLE_USER", "-u", help="Wigle.net API Username.  Required for geolocating SOFTWARE_REGISTRY.  See https://wigle.net/account")
parser.add_argument("--WIGLE_PASS", "-p", help="Wigle.net API Password.  Required for geolocating SOFTWARE_REGISTRY.  See https://wigle.net/account")

options = parser.parse_args()

#if options.recurse:
#    print("Exhaustive search not implemented yet.")

reg_files = os.path.join(options.IMAGE_MOUNT_POINT,options.SOFTWARE_REGISTRY) 
evt_files = os.path.join(options.IMAGE_MOUNT_POINT,options.SYSTEM_EVENTS) 
if "*" in reg_files:
    reg_files = glob.glob(reg_files)
else:
    reg_files = [reg_files]
if "*" in evt_files:
    evt_files = glob.glob(evt_files)
else:
    evt_files = [evt_files]

if reg_files:
    if not options.WIGLE_USER or not options.WIGLE_PASS:
        print("A Wigle API username and password is required for Registry geolocation resolution.  Obtain one https://wigle.net/account.")
        sys.exit(1)

#Retrieve Wifi history
print("Enumerating Wireless History and GPS Locations")
target_wb = openpyxl.Workbook()

#Do the wireless Data sheet
xls_sheet = target_wb.create_sheet(title="Wireless Data")
columns = ['BSSID', 'SSID','Description', 'DNSSufix', 'Type', 'First Seen', 'Last Seen', 'Geolocation URL']
for column, value in enumerate(columns):
    xls_sheet.cell(row = 1, column = column+1).value = value
for eachfile in reg_files:
    try:
        reg_handle = Registry.Registry(eachfile)
        reg_handle.open("Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged")
    except Exception as e:
        print("Unable to process file {0} : {1} ".format(eachfile,e))
        continue
    reg_data = network_history(reg_handle)
    for row, row_data in enumerate(reg_data):
        for column, value in enumerate(row_data):
            xls_sheet.cell(row = row+2, column = column+1).value = value

#Do the Event 6100 sheet
print("Enumerating Event 6100 data")
xls_sheet = target_wb.create_sheet(title="Event 6100 Data")
columns = ['System Time', 'Data','Geolocation Accuracy', 'Geolocation URL']
for column, value in enumerate(columns):
    xls_sheet.cell(row = 1, column = column+1).value = value
for eachfile in evt_files:
    try:
        evt_data  = parse_6100(eachfile)
    except Exception as e:
        print("Unable to process file {0} : {1} ".format(eachfile,e))
        continue
    for row, row_data in enumerate(evt_data):
        for column, value in enumerate(row_data):
            xls_sheet.cell(row = row+2, column = column+1).value = value

firstsheet=target_wb.get_sheet_by_name("Sheet")
target_wb.remove_sheet(firstsheet)
target_wb.save(options.OUTPUT)