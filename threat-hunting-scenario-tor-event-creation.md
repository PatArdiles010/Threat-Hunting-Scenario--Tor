Threat Hunt Report (Unauthorized TOR Usage)

Detection of Unauthorized TOR Browser Installation and Use on Workstation: mr2-btc-p62

Investigation Scenario:

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
Query to locate events: 
DeviceFileEvents
| where DeviceName =="mr2-btc-p62"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "toborrm"
| where Timestamp >= datetime(2026-08-18T23:40:51.1848608Z)
|order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256 = InitiatingProcessAccountName

`Query used to locate events: 

DeviceProcessEvents
| where DeviceName =="mr2-btc-p62"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.20.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName,FolderPath,SHA256, ProcessCommandLine
DeviceProcessEvents
| where DeviceName =="mr2-btc-p62"
| where FileName  has_any ("tor.exe", "firefox", "tor-browser.exe")
| project Timestamp, DeviceName,AccountName, ActionType, FileName,FolderPath,SHA256, ProcessCommandLine
| order by Timestamp desc
``DeviceNetworkEvents
| where DeviceName =="mr2-btc-p62"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, RemoteIP, RemoteUrl,RemotePort, InitiatingProcessFolderPath
| order by Timestamp desc


---

## Created By:
- **Author Name**: Patricio Ardiles
- **Author Contact**: https://www.linkedin.com/in/patricio-ardiles/
- **Date**: August 25, 2026

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August 25, 2026`  | `Patricio Ardiles`   
