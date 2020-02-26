# werejugo

Version 0.9 - beta

Identifies physical locations where a laptop has been based upon multiple forensics artifacts on host. Including

    - Wireless Profiles in SOFTWARE registry hive

    - Wireless SSID from WLAN_AUTOCONFIG Application Event logs

    - Wireless Diagnostic Event ID 6100 in SYSTEM.EVTX 

    - Wireless Profile Names from SRUM.DAT


This tool requires that you provide both a wigle.net API key and a Google Geolocation API key.   Place those keys in the werejugo.yaml configuration file.

Run the tool with administrative privileges on the target laptop for live aquistion of required files.   

If you have a forensics image with unlocked files then you can browse to those files manually.

