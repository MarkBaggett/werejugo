import requests
import json
import functools
from Registry.Registry import Registry
import codecs
import logging
import struct
import datetime

logging.basicConfig(filename='werejugo.log',level=logging.DEBUG)
log = logging.getLogger()


def google_sids_to_location(networks, key='AIzaSyATQd-AdGoVJiStNB_8y7Pet_s1X_KFTJo'):
    #cheats using a google api key by looking up the data directly with the browser location service
    #returns lat,long,accuracy
    url = f'https://www.googleapis.com/geolocation/v1/geolocate?key={key}'
    aps = []
    for mac,sig,name in networks:
        if b"-" in mac:
            mac = mac.replace(b"-",b":")
        aps.append( {'macAddress':mac.decode() , 'signalStrength': sig.decode(), 'channel': name.decode()} )
    response = requests.post(url=url, json= {"considerIP": "false", "wifiAccessPoints": aps}, headers={'Content-Type': 'application/json'})
    if response.status_code != 200:
        print(response.text)
    json_data = response.json()
    return (json_data['location']['lat'], json_data['location']['lng'], json_data['accuracy'])

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
            BSSID = b':'.join(codecs.encode(reg_mac[i:i+1],"hex") for i in range(0,6))
            return BSSID

wigle_cache={}
def wigle_search(wigle_user = 'AIDb228917a02ff001abbd7c718bb17e511', wigle_pass = '5254be2a287a9fd696dd086a4d825bca', **kwargs):
    #Lookup like this  wigle_search(netid="ff:ff:ff:ff:ff")
    print(f"Looking up ", dict(**kwargs))
    if not kwargs:
        return 
    if str(kwargs) in wigle_cache:
        print("Retrieving {} from cache.".format(dict(kwargs)))
        return wigle_cache.get(str(kwargs))
    url = "https://api.wigle.net/api/v2/network/search"
    try:
        webresp = requests.get(url, auth = (wigle_user,wigle_pass), params = kwargs )
        if webresp.status_code != 200:
            log.critical("{} There was an error from Wigle. {}".format("*"*25, webresp.reason))
            return None
        result = webresp.json()
        wigle_cache[str(kwargs)] = result
    except Exception as e:
        cont = input("Bad things happened while talking to Wigle. {0}, {1}  Continue? [Y/N] ".format(webresp.reason, str(e)))
        if cont.lower()=="n":
            raise(Exception("Wigle connection error. {0} {1} {2}".format(webresp.status_code,webresp.reason,str(e))))
    return result