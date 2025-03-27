<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/winstonhibbert/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

### 1. Searched the `DeviceFileEvents` Table

Search for ANY file that had the string “tor” in the name and discovered it looks like the user “whibbert” downloaded a Tor installer (silently). Did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at 2025-03-27T18:06:27.5722232Z

**Query used to locate events:**

```kql
let VMname = "whibbert-edr-md";
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == VMname 
| where InitiatingProcessAccountName == "whibbert"
| where Timestamp >= datetime(2025-03-27T18:06:27.5722232Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/2994b79f-7443-4c53-8298-43e6433d7292)


---

### 2. Searched the `DeviceProcessEvents` Table

Search for any 'ProcessCommandLine' that contained the string “tor-browser-windows-x86_64-portable-14.0.8.exe” Based on the logs returned, at Mar 27, 2025 2:10:40 PM, an employee on the “whibbert-edr-md” device ran the above mentioned executable from their Downloads folder, using a command that triggered a silent installation which placed the installed files on the desktop.

**Query used to locate event:**

```kql
let VMname = "whibbert-edr-md";
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.8.exe  /S"
| where DeviceName == VMname 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/31c746b8-0574-4c54-b492-9c49e2dc7ead)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "whibbert" actually opened the TOR browser. There was evidence that they did open it at `2025-03-27T18:11:23.4338257Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
let VMname = "whibbert-edr-md";
DeviceProcessEvents
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| where DeviceName == VMname 
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/f99d3956-01b2-43b3-b71c-93c9b0ec3e04)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search for any indication the Tor browser was used to establish a connection using any of the known Tor ports. At '2024-11-08T22:18:01.1246358Z,' an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address '127.0.0.1' on port '9150.' The connection was initiated by the process tor.exe, located in the folder 'c:\users\whibbert\desktop\tor browser\browser\torbrowser\tor\tor.exe.' There were a few other connections. There were couple other connections to sites over '443'.

**Query used to locate events:**

```kql
let VMname = "whibbert-edr-md";
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where DeviceName == VMname 
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443, 80) //Known ports used by Tor browser
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/abc7a3bb-eb71-4136-a799-9b66f0b4d0c7)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-27T18:06:27.5722232Z`
- **Event:** The user "whibbert" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\whibbert\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-27T18:13:00.1346135Z`
- **Event:** The user "whibbert" executed the file `tor-browser-windows-x86_64-portable-14.0.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.8.exe /S`
- **File Path:** `C:\Users\whibbert\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-27T18:13:00.1346135Z`
- **Event:** User "whibbert" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\whibbert\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-27T18:11:39.0094287Z`
- **Event:** A local network connection to IP `127.0.0.1` on port `9150` by user "whibbert" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\whibbert\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-27T18:11:45.1278362Z` - Connected to `172.233.129.176` on port `443`.
  - `2025-03-27T18:11:42.6623461Z` - Connected to `172.233.129.176` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "whibbert" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-27T18:20:22.2137156Z`
- **Event:** The user "whibbert" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\whibbert\Desktop\tor-shopping-list.txt`

---

## Summary

The user "whibbert" on the "winston-edr-md" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `winston-edr-md` by the user `whibbert`. The device was isolated, and the user's direct manager was notified.

---
