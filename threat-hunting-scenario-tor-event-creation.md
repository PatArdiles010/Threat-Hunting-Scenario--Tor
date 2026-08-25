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
```

Timeline of Events
Time (Local)
Event
6:35:14 PM
User "toborrm" executed tor-browser-windows-x86_64-portable-15.0.20.exe from the Downloads folder (initial run, no silent flag).
6:41:48 PM
Installer executed again from the Downloads folder.
6:43:13 PM
Installer executed with the /S switch, triggering a silent installation (no user-facing prompts).
6:45:19 PM
Installer executed again from the Downloads folder.
6:47:13 PM
Installer executed a final time with the /S switch, again triggering a silent installation.
6:48:22 PM
firefox.exe (Tor Browser) launched for the first time from C:\Users\Toborrm\Desktop\Tor Browser\Browser\firefox.exe, confirming the browser was opened.
6:48:24 PM
tor.exe spawned from C:\Users\Toborrm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, initializing the Tor client/proxy process.
6:48:56 PM
Network connection successfully established from firefox.exe to 127.0.0.1 on port 9150 — the local SOCKS port Tor Browser uses to route traffic through the Tor network, confirming the browser was actively using Tor.
6:49:02 PM – 6:56:07 PM
Multiple additional firefox.exe child processes spawned continuously, consistent with an active, ongoing Tor browsing session (tabs/content processes).
7:40:51 PM
A shortcut file, tor-shopping-list.txt.lnk, was created in the user's Recent Items folder, indicating a file named tor-shopping-list.txt was created and/or opened on the Desktop.
7:53:41 PM
storage.sqlite and storage-sync-v2.sqlite (Tor Browser profile data files) were modified, consistent with browser session/state data being saved during continued use.

Summary

Summary
On August 18, 2026, the user "toborrm" on device mr2-btc-p62 downloaded and repeatedly executed the Tor Browser installer
(tor-browser-windows-x86_64-portable-15.0.20.exe) from their Downloads folder, ultimately triggering a silent installation
using the /S switch — a method that suppresses standard installation prompts and reduces visibility into the install. Within
 roughly one minute of the final silent install, the user launched Tor Browser and its underlying tor.exe process, and a
confirmed network connection to the local Tor SOCKS proxy (127.0.0.1:9150) verified the browser was actively routing traffic
 over the Tor network. The user continued an active browsing session for approximately eight minutes. Later, at 7:40 PM,
evidence shows the user created a file named tor-shopping-list.txt on the Desktop, and by 7:53 PM, Tor Browser profile data
was still being actively modified, indicating continued use of the browser. Taken together, the sequence — silent installation,
 immediate active use over Tor, and creation of a file named "tor-shopping-list.txt" — indicates deliberate, intentional
installation and use of Tor Browser by the user, warranting further review of the contents of tor-shopping-list.txt and any
additional file or network activity tied to this session.


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
