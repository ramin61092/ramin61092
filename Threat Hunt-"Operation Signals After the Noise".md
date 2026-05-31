<div align="center">

# Operation Signals After the Noise

![Type](https://img.shields.io/badge/Type-Threat%20Hunt-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)
![Threat Actor](https://img.shields.io/badge/Threat%20Actor-Unknown%20Operator-red?style=for-the-badge)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Environment](#environment)
- [Executive Summary](#executive-summary)
- [Phase 01 — Initial Access](#phase-01--initial-access)
- [Phase 02 — Discovery and Execution](#phase-02--discovery-and-execution)
- [Phase 03 — Persistence](#phase-03--persistence)
- [Phase 04 — Defense Evasion](#phase-04--defense-evasion)
- [Phase 05 — Command and Control](#phase-05--command-and-control)
- [Phase 06 — Credential Access](#phase-06--credential-access)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Indicators of Compromise](#indicators-of-compromise)
- [Containment Actions](#containment-actions)
- [Recommendations](#recommendations)

---

## Overview

| Field | Detail |
|---|---|
| Operation | Signals After the Noise |
| Environment | Microsoft Sentinel |
| Workspace | LAW-Cyber-Range |
| Investigation Window | 2025-12-13 09:00 UTC — 2025-12-13 18:00 UTC |
| Anchor Timestamp | 2025-12-13 09:48 UTC |
| Scope | Post-intrusion activity reconstruction |
| Phases | 8 gated |
| Target System | azwks-phtg-01 |

---

## Environment

The investigation took place entirely within the **LAW-Cyber-Range** Microsoft Sentinel workspace. Schema discovery was performed at the start of the hunt using `take 1` and `getschema` queries across available tables. All evidence pivoting was conducted within Sentinel across `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, and `DeviceEvents`.

---

## Executive Summary

The break-in was already established. This hunt was tasked with reconstructing what the operator did once inside the PHTG HealthCloud estate on 13 December 2025.

What we found was a methodical, low-noise operator who entered via credential reuse, blended into the environment by mimicking legitimate administrative activity, and systematically worked through a full post-intrusion playbook — persistence, defense evasion, C2 establishment, and credential theft. Nearly every action was designed to look routine. Most of it nearly succeeded.

The operator staged their tooling under a convincing healthcare application path, established three independent persistence mechanisms, neutered Microsoft Defender through exclusion abuse, exfiltrated beacons through redundant C2 infrastructure, and ultimately reached LSASS for credential dumping. At no point did Defender block any of it.

---

## Phase 01 — Initial Access

**Technique: Credential Reuse**

The initial access vector was confirmed as **credential reuse**. No exploit, no phishing chain, no brute force — valid credentials walked the operator through the front door. The compromised account `vmadminusername` was used to authenticate to `azwks-phtg-01` from `10.0.0.152`.

| Field | Value |
|---|---|
| Compromised Account | `vmadminusername` |
| Source IP | `10.0.0.152` |
| Target Host | `azwks-phtg-01` |
| MFA / Conditional Access | None observed |

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| project TimeGenerated, AccountName, RemoteIP, LogonType, ActionType
| sort by TimeGenerated asc
```

> **Finding:** No MFA challenge or conditional access policy was applied to the logon. The operator authenticated cleanly with no friction.

---

## Phase 02 — Discovery and Execution

**Technique: Execution via PowerShell / Staged Tooling**

Following initial access, the operator executed a PowerShell script with deliberate execution policy bypass and hidden window flags — a textbook attempt to suppress visibility.

| Field | Value |
|---|---|
| Script Path | `C:\Users\vmAdminUsername\Documents\PHTG\_.ps1` |
| Execution Flags | `-WindowStyle Hidden -ExecutionPolicy Bypass` |
| Staging Directory | `C:\ProgramData\PHTG\HealthCloud` |
| Files Staged | Cache 17, TempCache 2, Cache |

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Hidden" or ProcessCommandLine contains "Bypass"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

> **Finding:** The operator chose `C:\ProgramData\PHTG\HealthCloud` as their staging directory — a path designed to blend in with a legitimate healthcare application install. 280 events were generated from this activity window.

---

## Phase 03 — Persistence

**Technique: Triple Persistence — Registry Run Key, LNK Shortcut, EventLog Masquerade**

The operator did not rely on a single persistence mechanism. They established three independent footholds, ensuring eviction of any one would not end their residency.

<div align="center">

![Dragons Meme](https://raw.githubusercontent.com/ramin61092/ramin61092/main/assets/dragons_meme.jpeg)

*The operator's persistence mechanisms pulling up to the PHTG HealthCloud estate*

</div>

### Registry Run Key

| Field | Value |
|---|---|
| Registry Path | `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` |
| Value Name | `PHTGHealthCloudTray` |
| Purpose | Survive user logon — re-executes malicious tray process on every login |

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "CurrentVersion\\Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

### LNK Shortcut

| Field | Value |
|---|---|
| File | `PHTG HealthCloud.lnk` |
| Purpose | Secondary persistence via startup shortcut |

### EventLog Masquerade

The operator registered their tooling under HKLM as a legitimate-looking Windows Event Log service — the most sophisticated of the three mechanisms and the hardest to spot without deliberate hunting.

| Field | Value |
|---|---|
| Registration Hive | HKLM |
| Technique | EventLog service masquerade |
| Purpose | Blend malicious process into Windows event infrastructure |

> **Finding:** Three persistence mechanisms across two registry hives and a LNK shortcut. This level of redundancy indicates an operator who expected detection of at least one mechanism and planned accordingly.

---

## Phase 04 — Defense Evasion

**Technique: LOLBin Masquerade, AMSI Bypass, Defender Exclusion Abuse**

The operator went directly after the host's defenses. Their evasion playbook had three distinct components.

### LOLBin Masquerade

The operator renamed their primary malicious binary to impersonate a trusted Windows built-in tool.

| Field | Value |
|---|---|
| Malicious Binary | `PHTGHealthCloudSvc.exe` |
| Masquerading As | `bitsadmin.exe` |
| Parent Process | `powershell.exe` |

<div align="center">

![Astronaut Meme](https://raw.githubusercontent.com/ramin61092/ramin61092/main/assets/astronaut_meme.jpeg)

*The PHTG HealthCloud process tree, on closer inspection*

</div>

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where FileName == "bitsadmin.exe"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
```

### AMSI Probe

| Field | Value |
|---|---|
| Script | `amsi_probe.ps1` |
| Purpose | Test AMSI detection capability before deploying further tooling |

> **Finding:** The operator tested the environment before committing. Dropping an AMSI probe first is a sign of operational discipline — they were not going to burn their tools until they knew what the host could see.

### Defender Exclusion Abuse

The operator added targeted Microsoft Defender exclusions to carve out safe operating space for their tooling. Defender detected this activity — and did not block it.

| Field | Value |
|---|---|
| Action | Defender exclusion added |
| Defender Response | Detected — not blocked |
| Mode | Audit |
| Lineage Pattern | Lineage break observed — parent process chain intentionally severed |

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where ActionType contains "DefenderExclusion" or ActionType contains "AntivirusDetection"
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName, AdditionalFields
```

> **Finding:** Defender was running in audit mode. Every detection fired and nothing was stopped. The operator effectively had a free pass from the moment they probed AMSI forward.

---

## Phase 05 — Command and Control

**Technique: Redundant C2 Beaconing / Ingress Tool Transfer**

The operator established dual C2 infrastructure — a primary beacon channel and a fallback, ensuring continuity of command even if one domain was sinkholed or blocked.

| Field | Value |
|---|---|
| Primary C2 | `updates.health-cloud.cc` |
| Fallback C2 | `status.health-cloud.cc` |
| C2 Port | `22` |
| Beacon Count | 2 active channels |
| Ingress Tool Transfer | Confirmed — additional tooling pulled post-access |

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where RemoteUrl contains "health-cloud.cc"
| project TimeGenerated, RemoteUrl, RemotePort, InitiatingProcessFileName, ActionType
| sort by TimeGenerated asc
```

> **Finding:** The domain pattern `updates.health-cloud.cc` and `status.health-cloud.cc` was deliberately chosen to mimic legitimate software update and status telemetry traffic. Both domains were active simultaneously, confirming intentional redundancy rather than failover.

---

## Phase 06 — Credential Access

**Technique: OS Credential Dumping — LSASS Memory**

The final phase of the operator's chain was credential theft. They targeted LSASS directly via `ReadProcessMemoryApiCall` — the standard technique for extracting credentials from memory without dropping a tool to disk.

| Field | Value |
|---|---|
| Target Process | `lsass.exe` |
| API Call | `ReadProcessMemoryApiCall` |
| Initiating Account | `vmadminusername` |
| Initiating Process | `powershell.exe` |
| Access Rights | `2047999` (PROCESS_ALL_ACCESS) |

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "ReadProcessMemoryApiCall"
| where FileName == "lsass.exe"
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessAccountName
```

> **Finding:** `PROCESS_ALL_ACCESS` (rights value `2047999`) confirms the operator requested full access to the LSASS process — not a read, not a snapshot, full access. Combined with the prior Defender exclusions and AMSI probe, this was a deliberate, prepared credential theft operation.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Tactic | Observed Behavior |
|---|---|---|---|
| T1078 | Valid Accounts | Initial Access | Credential reuse — `vmadminusername` |
| T1059.001 | PowerShell | Execution | Hidden window, execution policy bypass |
| T1547.001 | Registry Run Keys | Persistence | `HKCU\...\CurrentVersion\Run` — `PHTGHealthCloudTray` |
| T1547.009 | Shortcut Modification | Persistence | `PHTG HealthCloud.lnk` |
| T1036.005 | Match Legitimate Name | Defense Evasion | `PHTGHealthCloudSvc.exe` masquerading as `bitsadmin.exe` |
| T1562.001 | Disable/Modify Tools | Defense Evasion | Defender exclusion abuse |
| T1562.010 | Downgrade Attack | Defense Evasion | AMSI probe via `amsi_probe.ps1` |
| T1197 | BITS Jobs | Defense Evasion | LOLBin masquerade via bitsadmin |
| T1071 | Application Layer Protocol | Command and Control | Beaconing to `health-cloud.cc` domains |
| T1105 | Ingress Tool Transfer | Command and Control | Additional tooling pulled post-access |
| T1003.001 | LSASS Memory | Credential Access | `ReadProcessMemoryApiCall` on `lsass.exe` |

---

## Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| Hostname | `azwks-phtg-01` | Compromised workstation |
| Account | `vmadminusername` | Credential reuse initial access |
| IP Address | `10.0.0.152` | Source of initial logon |
| Domain | `updates.health-cloud.cc` | Primary C2 beacon |
| Domain | `status.health-cloud.cc` | Fallback C2 beacon |
| File | `PHTGHealthCloudSvc.exe` | Malicious binary masquerading as bitsadmin.exe |
| File | `amsi_probe.ps1` | AMSI detection probe |
| File | `PHTG HealthCloud.lnk` | Persistence via LNK shortcut |
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PHTGHealthCloudTray` | Registry Run key persistence |
| Directory | `C:\ProgramData\PHTG\HealthCloud` | Operator staging directory |
| Script | `C:\Users\vmAdminUsername\Documents\PHTG\_.ps1` | Initial execution script |
| API Call | `ReadProcessMemoryApiCall` on `lsass.exe` | Credential dumping |
| Process Rights | `2047999` | PROCESS_ALL_ACCESS on LSASS |

---

## Containment Actions

| Priority | Action | Rationale |
|---|---|---|
| Critical | Isolate `azwks-phtg-01` from network immediately | Active compromise — operator tooling may still be resident |
| Critical | Disable and reset `vmadminusername` credentials | Confirmed compromised account — credentials in operator's hands via LSASS dump |
| Critical | Rotate all credentials accessible from `azwks-phtg-01` | PROCESS_ALL_ACCESS on LSASS means all cached credentials are assumed stolen |
| High | Block `updates.health-cloud.cc` and `status.health-cloud.cc` at DNS and firewall | Sever active C2 channels |
| High | Remove all three persistence mechanisms | Registry Run key, LNK shortcut, EventLog registration |
| High | Remove Defender exclusions added by operator | Restore full detection capability before any remediation |
| Medium | Hunt for lateral movement from `azwks-phtg-01` | Stolen credentials may have been used to pivot — scope may be wider than one host |
| Medium | Review all accounts with access to `10.0.0.152` | Determine if credential reuse source can be identified and hardened |

---

## Recommendations

| Priority | Recommendation | Context |
|---|---|---|
| Critical | Enable Defender enforcement mode — audit mode is not protection | The operator moved through the entire environment with zero blocks. Audit mode means nothing gets stopped. |
| Critical | Implement MFA with phishing-resistant factors on all privileged accounts | Credential reuse only works when there is no second factor. MFA would have stopped this at the door. |
| High | Restrict modification of Defender exclusions to privileged admin accounts with alerting | The operator self-granted their own safe space. That should require elevated rights and trigger immediate alerting. |
| High | Enable LSASS protection mode (Credential Guard / PPL) | `ReadProcessMemoryApiCall` against LSASS should be blocked by default in hardened environments. |
| High | Alert on processes with PROCESS_ALL_ACCESS rights to LSASS | Rights value `2047999` is a high-fidelity detection signal — it should never be silent. |
| Medium | Deploy detection rules for LOLBin masquerade patterns | Binaries executing from non-standard paths with names matching Windows built-ins are a reliable signal. |
| Medium | Block or alert on outbound connections to `.cc` TLD from workstations | Uncommon TLD used for both C2 domains — a low-noise filter that would have caught the beaconing. |
| Medium | Implement PowerShell Constrained Language Mode and Script Block Logging | Hidden window and execution policy bypass flags should generate immediate alerts. |
| Low | Review staging directory naming conventions for anomaly detection | `C:\ProgramData\[AppName]` is a common attacker pattern — compare installed applications against directories present. |

---

<div align="center">

*Threat Hunt Report — Operation Signals After the Noise*
*Conducted in Microsoft Sentinel — LAW-Cyber-Range*
*github.com/ramin61092*

</div>
