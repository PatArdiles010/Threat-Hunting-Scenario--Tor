# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/PatArdiles010/Threat-Hunting-Scenario--Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

Steps Taken
...Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop. These events began at :2026-08-18T23:53:41.4030658Z

Query to locate events: 

DeviceFileEvents
| where DeviceName == "mr2-btc-p62"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "toborrm"
| where Timestamp >= datetime(2026-08-18T23:40:51.1848608Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256 = InitiatingProcessAccountName


Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at 2026-08-18T22:47:13.201577Z, an employee on the "threat-hunt-lab" device ran the file tor-browser-windows-x86_64-portable-14.0.1.exe from their Downloads folder, using a command that triggered a silent installation. 

DeviceProcessEvents
| where DeviceName =="mr2-btc-p62"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.20.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName,FolderPath,SHA256, ProcessCommandLine


Searched the DeviceProcessEvents table for any indication that user "employee" actually opened the tor browser. There was evidence that they did open it at 2026-08-18T22:48:22.2526278Z.
There were several other instances of firefox.exe(TOR) as well as tor.exe spawned afterwards.

DeviceProcessEvents
| where DeviceName =="mr2-btc-p62"
| where FileName  has_any ("tor.exe", "firefox", "tor-browser.exe")
| project Timestamp, DeviceName,AccountName, ActionType, FileName,FolderPath,SHA256, ProcessCommandLine
| order by Timestamp desc


Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. 2026-08-18T22:48:56.5710445Z, an employee on the "mr2-btc-p62" device successfully established a connection to the remote IP address 127.0.0.1  on port 9150. The connection was initiated by the process tor.exe, located in the folder c:\users\toborrm\desktop\tor browser\browser\firefox.exe 

DeviceNetworkEvents
| where DeviceName =="mr2-btc-p62"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, RemoteIP, RemoteUrl,RemotePort, InitiatingProcessFolderPath
| order by Timestamp desc


## Chronological Events

Timeline of Events


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
On August 18, 2026, the user "toborrm" on device mr2-btc-p62 downloaded and repeatedly executed the Tor Browser installer (tor-browser-windows-x86_64-portable-15.0.20.exe) from their Downloads folder, ultimately triggering a silent installation using the /S switch — a method that suppresses standard installation prompts and reduces visibility into the install. Within roughly one minute of the final silent install, the user launched Tor Browser and its underlying tor.exe process, and a confirmed network connection to the local Tor SOCKS proxy (127.0.0.1:9150) verified the browser was actively routing traffic over the Tor network. The user continued an active browsing session for approximately eight minutes. Later, at 7:40 PM, evidence shows the user created a file named tor-shopping-list.txt on the Desktop, and by 7:53 PM, Tor Browser profile data was still being actively modified, indicating continued use of the browser. Taken together, the sequence — silent installation, immediate active use over Tor, and creation of a file named "tor-shopping-list.txt" — indicates deliberate, intentional installation and use of Tor Browser by the user, warranting further review of the contents of tor-shopping-list.txt and any additional file or network activity tied to this session.



## Response Taken
TOR usage was confirmed on endpoint mr2-btc-p62. The device was isolated and the user's direct manager was notified.
