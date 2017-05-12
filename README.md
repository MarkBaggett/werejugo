# werejugo

Version 0.1 - prebeta

Identifies physical locations where a laptop has been based upon wireless profiles and wireless data recorded in event logs.

Resolving geolocation of the Wireless profiles stored in the SOFTWARE registry hive is done with Wigle.net's API.  You have to obtain a wigle.net API username and password.   The API username and password are differnt than your normal API username and password.   After creating a free account go to http://wigle.net/account and click the "SHOW MY TOKEN".  Then use API NAME (username) and API TOKEN (password).  These are passed as the -u and -p arguments

If you don't havea wigle.net account you can still use the Event Log based resolution.  The event log resolution looks for Microsoft Diagnotic Code 6100 event logs.  It finds Wifi information in the event log and geolocates it.


Example 1 - Assume default locations of artifacts and create a spreadsheet called results.xlsx: 
werejugo.exe -i z:\C: -u "wigleapiuser" -p "wigleapipassword" -o results.xlsx

Example 2 - Geolocate any 6100 event logs entries in the System event log.
werejugo.exe -e z:\c\windows\system32\Winevt\Logs\System.evtx -o eventsonly.xlsx

Example 3 - Geolocate the Wireless APs in multiple software registry hive files all starting with the word SOFTWARE in the current directory.
werejugo.exe -r SOFTWARE*.* -u "wigleapiuser" -p "wigleapipassword" -o results.xlsx

(Note: attemping to analyze either the System.evtx or SOFTWARE registry hive on live systems probably wont work because of file locks)


usage: werejugo.exe [-h] [--IMAGE_MOUNT_POINT IMAGE_MOUNT_POINT]
                    [--SOFTWARE_REGISTRY SOFTWARE_REGISTRY]
                    [--SYSTEM_EVENTS SYSTEM_EVENTS] [--OUTPUT OUTPUT]
                    [--WIGLE_USER WIGLE_USER] [--WIGLE_PASS WIGLE_PASS]

Given a directory of SOFTWARE registry hives it will enumerate all the
wireless.

optional arguments:
  -h, --help            show this help message and exit
  --IMAGE_MOUNT_POINT IMAGE_MOUNT_POINT, -i IMAGE_MOUNT_POINT
                        Geolocate all sources searching the SYSTEM volume of
                        this mounted Windows Images . example: z:\image\C:
  --SOFTWARE_REGISTRY SOFTWARE_REGISTRY, -r SOFTWARE_REGISTRY
                        Location of the SOFTWARE registry keys. (Supports
                        Wildcards) example: c:\windows\system32\config\SYSTEM*
  --SYSTEM_EVENTS SYSTEM_EVENTS, -e SYSTEM_EVENTS
                        Location of System Event Log specified. (Support
                        Wildcards) Example:
                        c:\windows\system32\Winevt\Logs\System.evtx)
  --OUTPUT OUTPUT, -o OUTPUT
                        Path and filename of the XLSX file to create.
  --WIGLE_USER WIGLE_USER, -u WIGLE_USER
                        Wigle.net API Username. Required for geolocating
                        SOFTWARE_REGISTRY. See https://wigle.net/account
  --WIGLE_PASS WIGLE_PASS, -p WIGLE_PASS
                        Wigle.net API Password. Required for geolocating
                        SOFTWARE_REGISTRY. See https://wigle.net/account

