import requests
import json
import functools
from Registry.Registry import Registry
import codecs
import logging
import struct
import datetime
from collections import defaultdict
import itertools
import time
import pyesedb
import sys

logging.basicConfig(filename='werejugo.log',level=logging.DEBUG)
log = logging.getLogger()

def google_networks_to_location(networks, key=None):
    #cheats using a google api key by looking up the data directly with the browser location service
    #returns lat,long,accuracy
    delay = 0
    url = config.get("google_api_url").format(key = config.get("google_api_key"))
    #url = 'https://a.radiocells.org/geolocate'
    aps = []
    for mac,sig,name in networks:
        if b"-" in mac:
            mac = mac.replace(b"-",b":")
        aps.append( {'macAddress':mac.decode() , 'signalStrength': sig.decode(), 'channel': name.decode()} )
    try:
        response = requests.post(url=url, json= {"considerIP": "false", "wifiAccessPoints": aps}, headers={'Content-Type': 'application/json'})
    except (requests.ConnectTimeout, requests.HTTPError, requests.ReadTimeout, requests.Timeout, requests.ConnectionError) as e:
        delay += 0.5
        print("exception {str(e)}")
    except Exception as e:
        print("exception {str(e)}")
    else:
        time.sleep(delay)
        if response.status_code != 200:
            print(response.text)
        json_data = response.json()
        return (json_data['location']['lat'], json_data['location']['lng'], json_data['accuracy'])

def google_triangulate_ap(ap_list, key=None):
    #cheats using a google api key by looking up the data directly with the browser location service
    #List of AP MAC Addresses in
    #returns dictionary of AP and accuracy
    if not key:
        key = config.get("google_api_key")
    assert len(ap_list) > 2
    delay = 0 
    locations_found = []
    url = config.get("google_api_url").format(key = config.get("google_api_key"))
    #url = 'https://a.radiocells.org/geolocate'
    bad_aps = [{'macAddress':'11:11:11:11:11:11'},{'macAddress':'22:22:22:22:22:22'} ]
    response = requests.post(url=url, json= {"considerIP": "false", "wifiAccessPoints": bad_aps}, headers={'Content-Type': 'application/json'})
    if response.status_code != 200:
         print(f"Error during detection of IP based resolution. {response.text}")
         return
    ip_based_detection = response.json().get("accuracy")
    results = defaultdict(lambda : [])
    num_combos = len(list(itertools.combinations(ap_list,2)))
    print(f"Triangulating {num_combos} historical Access Points pairs to determine locations.")
    for row_num, combo in enumerate(itertools.combinations(ap_list, 2)):
        if (row_num % (int(num_combos*.01) or 1)) == 0:
            print("\r|{0:-<50}| {1:3.2f}%".format("X"*( 50 * row_num//num_combos), 100*row_num/num_combos ),end="")
        aps = []
        for name,mac in combo:
            if b"-" in mac:
                mac = mac.replace(b"-",b":")
            aps.append( {'macAddress':mac.decode(), "signalStrength": -50 } )
        try:
            response = requests.post(url=url, json= {"considerIP": "false", "wifiAccessPoints": aps}, headers={'Content-Type': 'application/json'})
        except (requests.ConnectTimeout, requests.HTTPError, requests.ReadTimeout, requests.Timeout, requests.ConnectionError) as e:
            delay += 0.5
            print("exception {str(e)}")
        except Exception as e:
            print("exception {str(e)}")
        if delay > 10:
            print("Too many connection errors. Skipping the rest of the locations")
            break
        time.sleep(delay)
        if response.status_code != 200:
            print(response.text)
        else:
            json_data = response.json()
            if json_data['accuracy'] == ip_based_detection:
                continue
            for name,mac in combo:
                results[name].append((json_data['location']['lat'], json_data['location']['lng'], json_data['accuracy'], combo))
    newcombos = []
    for ssid, records in results.items():
        if len(records)==1:
            continue
        apset = set(records[0][-1])
        #If len(records) > 1 then (current,ap2) (current,ap3)  we should triangulate (current,ap2,ap3)
        for eachrec in records[1:]:
            apset.update(eachrec[-1])
        newcombos.append(tuple(apset))
    newcombos = list(set(newcombos))
    for eachcombo in newcombos:
        aps = []
        for name,mac in eachcombo:
            aps.append( {'macAddress':mac.decode(), "signalStrength": -50 } )
        try:
            response = requests.post(url=url, json= {"considerIP": "false", "wifiAccessPoints": aps}, headers={'Content-Type': 'application/json'}, verify=False)
        except (requests.ConnectTimeout, requests.HTTPError, requests.ReadTimeout, requests.Timeout, requests.ConnectionError) as e:
            delay += 0.5
            print(f"exception {str(e)}")
        except Exception as e:
            print(f"exception {str(e)}")
        time.sleep(delay)
        if response.status_code != 200:
            print(response.text)
        else:
            json_data = response.json()
            if json_data['accuracy'] == ip_based_detection:
                continue
    locations_found.append((json_data['location']['lat'], json_data['location']['lng'], json_data['accuracy'], combo))
    for eachloc in results.values():
        locations_found.extend(eachloc)
    locations_found = list(set(locations_found))
    return locations_found

def reg_date(dateblob):
    weekday = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
    year,month,day,date,hour,minute,sec,micro = struct.unpack('<8H', dateblob)
    dt = "%s, %02d/%02d/%04d %02d:%02d:%02d.%s" % (weekday[day],month,date,year,hour,minute,sec,micro)
    dtp = datetime.datetime.strptime(dt,"%A, %m/%d/%Y %H:%M:%S.%f")
    return dtp

def get_profile_info(reg_handle, ProfileGuid):
    nametypes = {'47':"Wireless", "06":"Wired", "17":"Broadband"}
    guid = r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\%s" % (ProfileGuid)
    regkey = reg_handle.open(guid)
    NameType ="%02x"  % regkey.value("NameType").value()
    nettype = nametypes.get(str(NameType), "Unknown Type"+str(NameType))
    FirstConnect = reg_date(regkey.value("DateCreated").value())
    LastConnect  = reg_date(regkey.value("DateLastConnected").value())
    return nettype, FirstConnect, LastConnect

@functools.lru_cache
def registry_wifi_to_BSSID(wifi_name, reg_path = r"c:\Windows\system32\config\SOFTWARE"):
    reg_handle = Registry(reg_path)
    subkeys = reg_handle.open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged").subkeys()
    for eachkey in subkeys:
        if eachkey.value("FirstNetwork").value().lower() == wifi_name.lower():
            reg_mac = eachkey.value("DefaultGatewayMac").value()
            BSSID = b':'.join(codecs.encode(reg_mac[i:i+1],"hex") for i in range(0,6)).decode().upper()
            return BSSID

def registry_all_wireless(reg_path = r"c:\Windows\system32\config\SOFTWARE"):
    reg_handle = Registry(reg_path)
    subkeys = reg_handle.open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged").subkeys()
    result = []
    for eachkey in subkeys:
        name = eachkey.value("FirstNetwork").value()
        reg_mac = eachkey.value("DefaultGatewayMac").value()
        if not int.from_bytes(reg_mac, "big"):
            continue
        BSSID = b':'.join(codecs.encode(reg_mac[i:i+1],"hex") for i in range(0,6)).decode().upper()
        result.append( (name,BSSID) )
    return result

def load_interfaces(reg_file):
    try:
        reg_handle = Registry(reg_file)
    except Exception as e:
        print("I could not open the specified SOFTWARE registry key. It is usually located in \Windows\system32\config.  This is an optional value.  If you cant find it just dont provide one.")
        print("WARNING : ", str(e))
        return {}
    try:
        int_keys = reg_handle.open('Microsoft\\WlanSvc\\Interfaces')
    except Exception as e:
        print("There doesn't appear to be any wireless interfaces in this registry file.")
        print("WARNING : ", str(e))
        return {}
    ssid2bssid = {}
    for eachsubkey in reg_handle.open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged").subkeys():
        DefaultGatewayMac = eachsubkey.value("DefaultGatewayMac").value()
        BSSID =  b':'.join(codecs.encode(DefaultGatewayMac[i:i+1],"hex") for i in range(0,6)).decode().upper()
        if BSSID == "00:00:00:00:00:00":
            continue
        SSID = eachsubkey.value("FirstNetwork").value()
        ssid2bssid[SSID]=BSSID    
    profile_lookup = {}
    for eachinterface in int_keys.subkeys():
        if len(eachinterface.subkeys())==0:
            continue
        for eachprofile in eachinterface.subkey("Profiles").subkeys():
            profileid = eachprofile.value("ProfileIndex").value()
            try:
                channelhintraw = eachprofile.subkey("MetaData").value("Channel Hints").value()
            except:
                continue
            hintlength = struct.unpack("I", channelhintraw[0:4])[0]
            ssid = channelhintraw[4:hintlength+4].decode()
            bssid = ssid2bssid.get(ssid)
            if bssid:
                profile_lookup[str(profileid)] = (bssid,ssid)
    return profile_lookup

def smart_retrieve(ese_table, ese_record_num, column_number):
    ese_column_types = {0: 'NULL', 1: 'BOOLEAN', 2: 'INTEGER_8BIT_UNSIGNED', 3: 'INTEGER_16BIT_SIGNED', 4: 'INTEGER_32BIT_SIGNED', 5: 'CURRENCY', 6: 'FLOAT_32BIT', 7: 'DOUBLE_64BIT', 8: 'DATE_TIME', 9: 'BINARY_DATA', 10: 'TEXT', 11: 'LARGE_BINARY_DATA', 12: 'LARGE_TEXT', 13: 'SUPER_LARGE_VALUE', 14: 'INETEGER_32BIT_UNSIGNED', 15: 'INTEGER_64BIT_SIGNED', 16: 'GUID', 17: 'INTEGER_16BIT_UNSIGNED'}
    rec = ese_table.get_record(ese_record_num)
    col_type = rec.get_column_type(column_number)
    col_data = rec.get_value_data(column_number)
    if col_type == pyesedb.column_types.DATE_TIME:
        col_data = ole_timestamp(col_data)
    elif col_type == pyesedb.column_types.INTEGER_32BIT_SIGNED:
        col_data =  0 if not col_data else struct.unpack('i',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_32BIT_UNSIGNED:
        col_data = 0 if not col_data else struct.unpack('I',col_data)[0]
    elif col_type == pyesedb.column_types.INTEGER_64BIT_SIGNED:
        col_data = 0 if not col_data else struct.unpack('q',col_data)[0]
    return col_data

def ole_timestamp(binblob):
    """converts a hex encoded OLE time stamp to a time string"""
    try:
        td,ts = str(struct.unpack("<d",binblob)[0]).split(".")
        dt = datetime.datetime(1899,12,30,0,0,0) + datetime.timedelta(days=int(td),seconds=86400 * float("0.{}".format(ts)))
    except:
        dt = "This field is incorrectly identified as an OLE timestamp in the template."
    return dt

def file_timestamp(binblob):
    """converts a hex encoded windows file time stamp to a time string"""
    import pdb;pdb.set_trace()
    try:
        dt = datetime.datetime(1601,1,1,0,0,0) + datetime.timedelta(microseconds=binblob/10)
    except:
        dt = "This field is incorrectly identified as a file timestamp in the template"
    return dt


def process_srum(srum, software, tablename = '{DD6636C4-8929-4683-974E-22C046A43763}'):
    #This method must commit pin locations to the database
    #Do the wireless Data sheet
    print(f"\nProcessing SRUM events in table {tablename}", end="")
    row_num = 1 #Init to 1, first row will be 2 in spreadsheet (1 is headers)
    entries = []
    ese_db = pyesedb.file()
    ese_db.open(srum)
    lookups = load_interfaces(software)
    ese_table = ese_db.get_table_by_name(tablename)
    #If the table is not found it returns None
    if not ese_table:
        print("Unable to find network connections table in SRUM file provided")
        raise Exception("Unable to find network connections table in SRUM file provided")
    reverse_column_lookup = dict([(x.name,index) for index,x in enumerate(ese_table.columns)])
    count = 0
    for ese_row_num in range(ese_table.number_of_records):
        count += 1
        #"L2ProfileId=6, connectstart = 8"
        profile = smart_retrieve(ese_table, ese_row_num, reverse_column_lookup['L2ProfileId'] )
        connected = smart_retrieve(ese_table, ese_row_num, reverse_column_lookup['TimeStamp'] )
        if count%10==0:
            sys.stdout.write(".")
            #sys.stdout.flush()
        if profile:
            bssid,ssid = lookups.get(str(profile),(None,'the profile could not be resolved'))
            if bssid:
                entries.append((connected,bssid, ssid))
    print("\n")
    return entries


wigle_cache={}
def wigle_search(bssid, wigle_user = None, wigle_pass = None):
    #Lookup like this  wigle_search(netid="ff:ff:ff:ff:ff")
    wigle_user = config.get("wigle_api_user")
    wigle_pass = config.get("wigle_api_pass")
    url = config.get("wigle_api_url")
    result = ""
    if isinstance(bssid, bytes):
        bssid = bssid.decode()
    if "-" in bssid:
        bssid = bssid.replace("-",":")
    if bssid in wigle_cache:
        print("Repetative search (Retrieving {} from cache.)".format(bssid))
        return wigle_cache.get(bssid)

    try:
        webresp = requests.get(url, auth = (wigle_user,wigle_pass), params = {'netid' : bssid } )
    except (requests.ConnectTimeout, requests.HTTPError, requests.ReadTimeout, requests.Timeout, requests.ConnectionError) as e:
        print(f"Web communications error {str(e)}")
    except Exception as e:
        print(f"Error {str(e)}")
    if webresp.status_code != 200:
        print("{} There was an error from Wigle. {}".format("*"*25, webresp.reason))
        return None
    wigle_data = webresp.json()
    if wigle_data.get("totalResults", 0):
        lat = wigle_data.get("results")[0].get("trilat")
        long = wigle_data.get("results")[0].get("trilong")
        chan = wigle_data.get("results")[0].get("channel")
        ssid = wigle_data.get("results")[0].get("ssid")
        wigle_cache[bssid] = (lat,long,chan,ssid)
        return lat,long,chan,ssid

def load_srumid_lookups(database):
    """loads the SRUMID numbers from the SRUM database"""
    id_lookup = {}
    #Note columns  0 = Type, 1 = Index, 2 = Value
    lookup_table = database.get_table_by_name('SruDbIdMapTable')
    column_lookup = dict([(x.name,index) for index,x in enumerate(lookup_table.columns)]) 
    for rec_entry_num in range(lookup_table.number_of_records):
        bin_blob = smart_retrieve(lookup_table,rec_entry_num, column_lookup['IdBlob'])
        if smart_retrieve(lookup_table,rec_entry_num, column_lookup['IdType'])==3:
            bin_blob = BinarySIDtoStringSID(bin_blob)
        elif not bin_blob == "Empty":
            bin_blob = blob_to_string(bin_blob)
        id_lookup[smart_retrieve(lookup_table,rec_entry_num, column_lookup['IdIndex'])] = bin_blob
    return id_lookup