# 🧅 Threat Hunt Report: Unauthorized TOR Usage

<p align="center">
  <img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and crosshair">
</p>

<p align="center">
  Detection and investigation of unauthorized TOR Browser installation and usage on a Windows endpoint
</p>

---

## 📋 Executive Summary

A threat hunt was conducted to determine whether employees were using **TOR Browser** to bypass organizational network security controls.

The investigation identified **confirmed TOR Browser installation and active usage** on endpoint `mr2-btc-p62` by user `toborrm`.

Evidence showed that the user:

* Downloaded and repeatedly executed the TOR Browser installer.
* Executed the installer using the `/S` silent-install switch.
* Successfully installed TOR Browser.
* Launched `firefox.exe` from the TOR Browser directory.
* Spawned the underlying `tor.exe` process.
* Established a connection to the local TOR SOCKS proxy on `127.0.0.1:9150`.
* Continued running multiple TOR Browser processes consistent with an active browsing session.
* Created a file named `tor-shopping-list.txt` on the Desktop.
* Continued modifying TOR Browser profile data after the browsing session began.

### 🔴 Verdict

**CONFIRMED — Unauthorized TOR Browser Usage**

The combination of installation activity, execution of TOR processes, and a successful connection to the TOR Browser SOCKS proxy provides strong evidence that TOR Browser was actively being used on the endpoint.

### Response

The endpoint `mr2-btc-p62` was isolated and the user's direct manager was notified.

---

# 🎯 Scenario

Management suspected that employees may be using TOR Browser to bypass organizational network security controls.

Recent network telemetry showed unusual encrypted traffic patterns and connections associated with known TOR infrastructure. Additionally, anonymous reports indicated that employees may have been discussing methods to access restricted websites during work hours.

The objective of this hunt was to:

1. Identify evidence of TOR Browser installation.
2. Identify execution of TOR-related processes.
3. Identify network connections associated with TOR.
4. Establish whether TOR was actively being used.
5. Identify additional artifacts generated during the session.
6. Notify management if unauthorized TOR usage was confirmed.

---

# 🛠️ Platforms & Technologies

| Category             | Technology                      |
| -------------------- | ------------------------------- |
| Endpoint OS          | Windows 11                      |
| Cloud Platform       | Microsoft Azure                 |
| EDR                  | Microsoft Defender for Endpoint |
| Query Language       | Kusto Query Language (KQL)      |
| Browser              | TOR Browser                     |
| Primary Data Sources | `DeviceFileEvents`              |
|                      | `DeviceProcessEvents`           |
|                      | `DeviceNetworkEvents`           |

---

# 🔎 Threat Hunting Methodology

The investigation followed a layered approach across endpoint file, process, and network telemetry.

### 1. File Activity

Searched `DeviceFileEvents` for files containing TOR-related naming patterns.

**Objective:**

* Identify TOR Browser installers.
* Identify extracted TOR Browser files.
* Identify TOR-related artifacts created on the endpoint.
* Establish the initial installation timeframe.

### 2. Process Activity

Searched `DeviceProcessEvents` for:

* TOR Browser installers
* `firefox.exe`
* `tor.exe`
* `tor-browser.exe`
* TOR-related command-line arguments

**Objective:**

Determine whether TOR Browser was executed and whether the installation was performed silently.

### 3. Network Activity

Searched `DeviceNetworkEvents` for connections involving ports commonly associated with TOR.

**Ports investigated:**

`9001`, `9030`, `9040`, `9050`, `9051`, `9150`

Particular attention was given to **TCP/9150**, which is commonly used by TOR Browser as its local SOCKS proxy.

---

# 🧪 Investigation Findings

## Finding 1 — TOR Browser Files Were Created

A search of `DeviceFileEvents` identified numerous TOR-related file events associated with user `toborrm` on endpoint `mr2-btc-p62`.

The activity included TOR-related files being copied to the user's Desktop and the creation of a file named:

```text
tor-shopping-list.txt
```

### KQL Query

```kusto
DeviceFileEvents
| where DeviceName == "mr2-btc-p62"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "toborrm"
| where Timestamp >= datetime(2026-08-18T23:40:51.1848608Z)
| order by Timestamp desc
| project Timestamp,
          DeviceName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          InitiatingProcessAccountName
```

### Assessment

The file telemetry established the presence of TOR-related artifacts on the endpoint and provided the initial timeframe for the investigation.

---

# Finding 2 — TOR Browser Installer Executed

`DeviceProcessEvents` was searched for execution of the TOR Browser installer.

Evidence showed that the user executed:

```text
tor-browser-windows-x86_64-portable-15.0.20.exe
```

from the Downloads directory.

The installer was executed multiple times, including executions using the:

```text
/S
```

switch.

The `/S` switch triggered a silent installation, suppressing normal installation prompts.

### KQL Query

```kusto
DeviceProcessEvents
| where DeviceName == "mr2-btc-p62"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.20.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          ProcessCommandLine
| order by Timestamp asc
```

### Assessment

Repeated execution of the installer followed by execution using the silent-install switch indicates deliberate installation activity rather than an accidental file download.

---

# Finding 3 — TOR Browser Was Successfully Launched

Process telemetry showed that TOR Browser was subsequently executed.

The primary browser process was:

```text
firefox.exe
```

located within the TOR Browser installation directory:

```text
C:\Users\toborrm\Desktop\Tor Browser\Browser\firefox.exe
```

The underlying TOR client was also launched:

```text
C:\Users\toborrm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
```

### KQL Query

```kusto
DeviceProcessEvents
| where DeviceName == "mr2-btc-p62"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp,
          DeviceName,
          AccountName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          ProcessCommandLine
| order by Timestamp asc
```

### Assessment

The execution of `firefox.exe` from the TOR Browser directory and the subsequent launch of `tor.exe` provides strong evidence that the TOR Browser application was actively launched.

---

# Finding 4 — Active TOR Proxy Connection Confirmed

Network telemetry provided the strongest confirmation of active TOR usage.

At:

**2026-08-18 22:48:56.5710445 UTC**

the endpoint established a connection to:

```text
127.0.0.1:9150
```

The connection was associated with the TOR Browser process.

Port **9150** is commonly used by TOR Browser as its local SOCKS proxy.

### KQL Query

```kusto
DeviceNetworkEvents
| where DeviceName == "mr2-btc-p62"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          ActionType,
          RemoteIP,
          RemoteUrl,
          RemotePort,
          InitiatingProcessFolderPath
| order by Timestamp asc
```

### Assessment

The successful connection to `127.0.0.1:9150` from the TOR Browser process provides strong evidence that the browser was actively using the TOR local proxy.

This moves the finding beyond simple TOR installation and establishes **active TOR Browser usage**.

---

# 🕐 Chronological Timeline

| Time (UTC)      | Event                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------ |
| **22:47:13**    | `tor-browser-windows-x86_64-portable-15.0.20.exe` executed from the Downloads folder.            |
| **22:41–22:47** | Multiple executions of the TOR Browser installer were observed.                                  |
| **22:43:13**    | Installer executed using the `/S` silent-install switch.                                         |
| **22:47:13**    | Installer executed again using the `/S` switch.                                                  |
| **22:48:22**    | `firefox.exe` launched from the TOR Browser installation directory.                              |
| **22:48:24**    | `tor.exe` spawned from the TOR Browser directory.                                                |
| **22:48:56**    | `firefox.exe` established a connection to `127.0.0.1:9150`.                                      |
| **22:49–22:56** | Multiple additional `firefox.exe` processes spawned, consistent with an active browsing session. |
| **23:40+**      | Additional TOR-related file activity observed.                                                   |
| **23:53:41**    | TOR-related files were created/copied and `tor-shopping-list.txt` activity was observed.         |
| **00:00+**      | TOR Browser profile databases continued to be modified.                                          |

> **Note:** Timeline timestamps are normalized to UTC.

---

# 🧩 Key Investigation Artifacts

| Artifact              | Value                                                            |
| --------------------- | ---------------------------------------------------------------- |
| **Host**              | `mr2-btc-p62`                                                    |
| **User**              | `toborrm`                                                        |
| **Installer**         | `tor-browser-windows-x86_64-portable-15.0.20.exe`                |
| **Browser Process**   | `firefox.exe`                                                    |
| **TOR Process**       | `tor.exe`                                                        |
| **Local Proxy**       | `127.0.0.1:9150`                                                 |
| **Suspicious File**   | `tor-shopping-list.txt`                                          |
| **Browser Directory** | `C:\Users\toborrm\Desktop\Tor Browser\`                          |
| **Relevant Tables**   | `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents` |

---

# 🧠 Analysis

The collected telemetry demonstrates a clear progression:

```text
TOR Browser Installer
        │
        ▼
Repeated Execution
        │
        ▼
Silent Installation (/S)
        │
        ▼
TOR Browser Launched
        │
        ▼
firefox.exe + tor.exe
        │
        ▼
127.0.0.1:9150 Connection
        │
        ▼
Active TOR Session
        │
        ▼
TOR Browser Artifacts Created
```

The activity is significant because the telemetry does not merely indicate that a TOR installer existed on the endpoint.

Multiple independent telemetry sources corroborate the same activity:

* **File telemetry** confirms TOR-related artifacts.
* **Process telemetry** confirms installation and execution.
* **Command-line telemetry** confirms use of the silent-install switch.
* **Process path information** confirms execution from the TOR Browser directory.
* **Network telemetry** confirms communication with the local TOR SOCKS proxy.
* **Browser profile artifacts** indicate continued browser activity.
* **User-created file activity** provides additional context surrounding the session.

Taken together, the evidence strongly supports the conclusion that TOR Browser was intentionally installed and actively used by the user.

---

# 🚨 Conclusion

## Confirmed Unauthorized TOR Usage

The investigation confirmed that user **`toborrm`** actively installed and used TOR Browser on endpoint **`mr2-btc-p62`**.

The most significant evidence was the successful connection from the TOR Browser process to:

```text
127.0.0.1:9150
```

This is consistent with the TOR Browser's local SOCKS proxy and provides strong evidence that the browser was actively routing traffic through TOR.

The presence of `tor-shopping-list.txt` also warrants additional investigation to determine whether the file contains information relevant to the original security concern.

---

# 🛡️ Response Taken

Following confirmation of unauthorized TOR activity:

* 🔒 **Endpoint `mr2-btc-p62` was isolated.**
* 👤 **The user's direct manager was notified.**
* 🔎 **Additional investigation of TOR-related artifacts is recommended.**

---

# 🔬 Recommended Follow-Up Investigation

* [ ] Review the contents and metadata of `tor-shopping-list.txt`.
* [ ] Search `DeviceNetworkEvents` for additional outbound connections initiated by TOR processes.
* [ ] Review DNS activity surrounding the TOR Browser session.
* [ ] Search for additional TOR installations across the environment.
* [ ] Search for other endpoints associated with the same user account.
* [ ] Review browser artifacts for additional evidence of activity.
* [ ] Determine whether TOR Browser was used to access restricted or prohibited resources.
* [ ] Review Defender alerts associated with the endpoint and user.
* [ ] Consider blocking unauthorized TOR Browser installation and execution through endpoint controls.
* [ ] Establish a detection rule for future TOR Browser installation and execution.

---

# 🎯 Detection Opportunities

This investigation can be converted into several reusable detections.

### TOR Browser Installation

Detect execution of known TOR Browser installers.

### TOR Process Execution

Detect:

```text
tor.exe
firefox.exe
tor-browser.exe
```

when executed from TOR Browser installation directories.

### TOR SOCKS Proxy Usage

Detect connections to:

```text
127.0.0.1:9150
127.0.0.1:9050
```

especially when initiated by non-standard browser processes.

### TOR-Related File Activity

Detect creation or modification of files containing TOR-related naming patterns.

---

# 📚 Related Documentation

### Scenario Creation

[Threat Hunting Scenario — TOR Event Creation](https://github.com/PatArdiles010/Threat-Hunting-Scenario--Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

### Primary Data Sources

```text
DeviceFileEvents
DeviceProcessEvents
DeviceNetworkEvents
```

---

# 🏁 Final Assessment

| Attribute         | Assessment                              |
| ----------------- | --------------------------------------- |
| **Severity**      | 🔴 High                                 |
| **Confidence**    | 🟢 High                                 |
| **Status**        | 🔴 Confirmed                            |
| **Activity**      | Unauthorized TOR Browser Usage          |
| **Affected Host** | `mr2-btc-p62`                           |
| **Affected User** | `toborrm`                               |
| **Response**      | Endpoint Isolated / Management Notified |

> **Final Verdict:** Multiple independent telemetry sources confirm that TOR Browser was deliberately installed and actively used on endpoint `mr2-btc-p62` by user `toborrm`. The combination of **silent installation, TOR process execution, active SOCKS proxy communication, continued browser activity, and TOR-related file creation** provides sufficient evidence to treat this as a confirmed security event requiring further review.
