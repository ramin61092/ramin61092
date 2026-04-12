<div align="center">

# THREAT HUNT REPORT

### LogN Pacific Financial Services
#### Finance Department

![Type](https://img.shields.io/badge/TYPE-THREAT%20HUNT-555555?style=flat-square)
![Status](https://img.shields.io/badge/STATUS-COMPLETE-238636?style=flat-square)
![Actor](https://img.shields.io/badge/THREAT%20ACTOR-SCATTERED%20SPIDER-e63946?style=flat-square)
![Impact](https://img.shields.io/badge/FINANCIAL%20IMPACT-£24%2C500%20BEC-7b2d8b?style=flat-square)

---

**Classification:** `CONFIDENTIAL` &nbsp;|&nbsp; **Analyst:** Ramin Delsouz &nbsp;|&nbsp; **Date:** 26 February 2026

**Platform:** Microsoft Sentinel &nbsp;|&nbsp; **Workspace:** `law-cyber-range`

**Log Sources:** `SigninLogs` · `CloudAppEvents` · `EmailEvents`

---

</div>

## Table of Contents

- [Executive Summary](#executive-summary)
- [Incident Trigger](#incident-trigger)
- [Compromised Identity](#compromised-identity)
- [Attacker Infrastructure](#attacker-infrastructure)
- [MFA Fatigue Attack](#mfa-fatigue-attack)
- [Post-Compromise Activity](#post-compromise-activity)
- [Inbox Rule Persistence](#inbox-rule-persistence)
- [Business Email Compromise](#business-email-compromise)
- [Scope of Compromise](#scope-of-compromise)
- [Defensive Gaps](#defensive-gaps)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Threat Actor Attribution](#threat-actor-attribution)
- [Indicators of Compromise](#indicators-of-compromise)
- [Containment Actions](#containment-actions)
- [Recommendations](#recommendations)
- [Full Flags Log](#full-flags-log)

---

## Executive Summary

On the evening of **25 February 2026**, a threat actor compromised the Microsoft 365 account of LogN Pacific Financial Services employee **Mark Smith** (`m.smith@lognpacific.org`) using an **MFA fatigue attack** combined with an **Adversary-in-the-Middle (AiTM)** session hijacking technique.

The attacker, operating from the **Netherlands** via IP `205.147.16.190` on an Ubuntu Linux machine, gained access to Mark's full M365 environment — including Outlook, OneDrive, and SharePoint. Once inside, they created two covert inbox rules to silently exfiltrate financial emails and delete all security alerts, blinding the victim to the compromise.

The attacker then sent a fraudulent email to finance colleague **J. Reynolds** impersonating Mark, requesting a **£24,500 vendor payment** be redirected to a fraudulent bank account. The receiving bank flagged the transaction and froze the funds. The attack is attributed to **Scattered Spider** (UNC3944).

> ⚠️ **Critical Finding:** LogN Pacific had **no Conditional Access policies enforced** on their M365 environment. The `ConditionalAccessStatus` field returned `notApplied` on every single attacker signin. A policy blocking foreign logins or requiring compliant devices would have stopped this attack entirely.

---

## Incident Trigger

> 📞 **IR Lead:** *"We have a confirmed fraudulent wire transfer. £24,500 redirected to an unknown account. The bank caught it and froze the funds. Finance say they followed procedure — they got an email from a known colleague with updated banking details and processed it. Mark reported weird MFA notifications last night. He approved one just to make it stop. This morning his team found inbox rules nobody created. I need you in the sign-in logs now."*

| Attribute | Value |
|-----------|-------|
| Reported Date | 26 Feb 2026 — 09:30 UTC |
| Investigation Window | 25 Feb 2026 21:00 UTC → 26 Feb 2026 00:00 UTC |
| Target Organisation | LogN Pacific Financial Services — Finance Department |
| Financial Loss | £24,500 (frozen by receiving bank) |

---

## Compromised Identity

| Attribute | Value |
|-----------|-------|
| Name | Mark Smith |
| Email | `m.smith@lognpacific.org` |
| Department | Finance |
| Legitimate IP | `172.175.65.103` — United States |
| Azure Object ID | `9199bf20-a13f-4107-85dc-02114787ef48` |

Mark's credentials had been obtained prior to the attack via **infostealer malware** logs purchased from underground markets — meaning the attacker already had his password before the MFA fatigue campaign began.

**Query — Confirm Compromised Identity**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where UserDisplayName contains "Mark Smith"
| project UserPrincipalName, UserDisplayName
| distinct UserPrincipalName, UserDisplayName
```

---

## Attacker Infrastructure

| Attribute | Value |
|-----------|-------|
| Attacker IP | `205.147.16.190` |
| Country | 🇳🇱 Netherlands (NL) |
| Operating System | Ubuntu Linux (x86_64) |
| Browser | Firefox 147.0 |
| User-Agent | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0` |
| Exfil Email | `insights@duck.com` |
| Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |

> 🔍 **Analyst Note:** The attacker's use of **Ubuntu Linux with Firefox** instead of a typical Windows/Chrome profile is an anomaly indicator. The Netherlands origin contrasts starkly with Mark's United States baseline — a clear impossible travel scenario that should have been caught by Conditional Access had any been in place.

**Query — Identify Attacker IP (Baseline Exclusion Method)**
```kql
// First establish Mark's legitimate baseline IP, then exclude it
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress != "172.175.65.103"
| project TimeGenerated, IPAddress, Location, UserAgent, ResultType, ResultDescription
| order by TimeGenerated asc
```

---

## MFA Fatigue Attack

<div align="center">

![Zoolander Cyber Meme](assets/Zoolander%20Cyber%20Meme.jpeg)

*// Mark approves. Scattered Spider intercepts. Simple as that.*

</div>

The attacker employed **T1621 — MFA Request Generation**. After just **3 failed push attempts**, Mark approved one to make the notifications stop. This was not a simple MFA bypass — it was a sophisticated **Adversary-in-the-Middle (AiTM)** proxy attack.

```
// Normal authentication flow
Mark  ──────────────────────────────────────▶  Microsoft ✅

// AiTM attack flow
Mark  ──▶  Attacker Proxy (NL)  ──▶  Microsoft
                   │
                   ▼
          Session token intercepted
                   │
                   ▼
Attacker  ──▶  Import cookie into Firefox  ──▶  Microsoft (as Mark) ✅
```

The moment Mark approved the push, Microsoft issued a valid session token which the proxy intercepted in real time. The attacker imported the stolen cookie into their own browser and was instantly authenticated as Mark — no password or MFA ever needed again.

### Push Bombing Sequence

| Time (Local) | Result Code | Description |
|-------------|-------------|-------------|
| 9:54:24 PM | `50074` | Strong Authentication required — MFA not completed |
| 9:54:55 PM | `50140` | Keep me signed in interrupt — failed |
| 9:55:15 PM | `50140` | Keep me signed in interrupt — failed |
| **9:59:52 PM** | **`0`** | ✅ **Mark approves — attacker gains session** |

> 📌 **Error Code 50074** — Indicates MFA was required but not completed. This code repeating in rapid succession from a foreign IP is the definitive signature of an MFA fatigue attack in SigninLogs.

**Query — MFA Push Bombing Sequence**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ResultType, ResultDescription, AppDisplayName, ConditionalAccessStatus
| order by TimeGenerated asc
```

---

## Post-Compromise Activity

The attacker's first action after gaining access was `MailItemsAccessed` — reading the inbox to understand active conversations and identify the right vendor thread before making any moves.

**Query — Post-Compromise CloudApp Activity**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, Application, AccountDisplayName, IPAddress, RawEventData
| order by TimeGenerated asc
```

| Time | Application | Action | Significance |
|------|-------------|--------|--------------|
| 9:59 PM | One Outlook Web | `MailItemsAccessed` | Inbox reconnaissance |
| 10:02 PM | One Outlook Web | `New-InboxRule` | Created rule `.` — forward financial emails |
| 10:03 PM | One Outlook Web | `New-InboxRule` | Created rule `-` — delete security alerts |
| 10:06 PM | One Outlook Web | Email sent | Fraudulent BEC email to J. Reynolds |
| 10:07 PM | Microsoft OneDrive for Business | `FileAccessed` | File system reconnaissance |
| 10:09 PM | Office 365 SharePoint Online | Browse | Company document access |
| 10:10 PM | OfficeHome | Navigate | Full M365 environment scoping |

---

## Inbox Rule Persistence

<div align="center">

![Girl Bro Cyber Meme](assets/Girl%20Bro%20Cyber%20Meme.jpeg)

*// Scattered Spider's operational security in practice.*

</div>

The attacker created two inbox rules using **T1564.008 — Hide Artifacts: Email Hiding Rules**. Both were named with single invisible characters — a deliberate evasion technique designed to blend into the Outlook rules list as visual noise.

**Query — Find All Malicious Inbox Rules**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, AccountDisplayName, IPAddress, RawEventData
| order by TimeGenerated asc
// Expand RawEventData > Parameters to find rule Name, ForwardTo,
// SubjectOrBodyContainsWords, DeleteMessage, and StopProcessingRules
```

### Rule 1 — Financial Exfiltration

| Parameter | Value |
|-----------|-------|
| Rule Name | `.` *(single period)* |
| Action | Forward to `insights@duck.com` |
| Keywords | `invoice, payment, wire, transfer` |
| StopProcessingRules | `True` |

### Rule 2 — Security Alert Deletion

| Parameter | Value |
|-----------|-------|
| Rule Name | `-` *(single hyphen)* |
| Action | `DeleteMessage: True` |
| Keywords | `suspicious, security, phishing, unusual, compromised, verify` |
| StopProcessingRules | `True` |

> ⭐ **Key Analyst Note — Evasion by Invisibility**
>
> The choice of a **single period** and **single hyphen** as rule names is a deliberate and highly effective evasion technique. When an administrator reviews the inbox rules list in Outlook, these characters appear as visual noise — virtually invisible without careful inspection. Most users would scroll past them without a second glance.
>
> Setting `StopProcessingRules` to `True` on both rules ensured no other rules processed matched emails — the victim's own notification rules never fired on financial or security emails. Together, these two rules created a **complete intelligence blackout**: the attacker could see everything while the victim saw nothing.

---

## Business Email Compromise

| Attribute | Value |
|-----------|-------|
| Time Sent | 25 Feb 2026 — 22:06:39 UTC |
| Sender | `m.smith@lognpacific.org` *(attacker)* |
| Recipient | `j.reynolds@lognpacific.org` |
| Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Sender IP | `205.147.16.190` ✅ Matches attacker IP |
| Direction | `Intra-org` |

**Query — Hunt Fraudulent BEC Email**
```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| where SenderIPv4 == "205.147.16.190"
| project TimeGenerated, SenderMailFromAddress, RecipientEmailAddress,
          Subject, SenderIPv4, EmailDirection
| order by TimeGenerated asc
```

> ⭐ **Key Analyst Note — Thread Hijacking**
>
> The attacker did not send a new suspicious email — they **replied to an existing vendor invoice thread**. The "RE:" prefix made the email appear as a natural continuation of a legitimate ongoing conversation between colleagues. J. Reynolds had no reason to doubt an internal email from a known colleague.
>
> The `Intra-org` email direction confirms it originated from a legitimate internal account, bypassing all external email security controls entirely. This is why the finance team insists they "followed standard procedures" — **from their perspective, they did**. The fraud was invisible at the human level.

> 🔗 **IP Cross-Correlation:** The SenderIPv4 on the fraudulent email (`205.147.16.190`) matches exactly the attacker's signin IP from SigninLogs. This cross-correlation across two separate log sources — **SigninLogs and EmailEvents** — conclusively proves the same attacker session was responsible for both the authentication and the fraudulent wire transfer email.

---

## Scope of Compromise

<div align="center">

![Oprah Cyber Meme](assets/Oprah%20Cyber%20Meme.jpeg)

*// The full M365 environment. Nobody was safe.*

</div>

The attacker's access extended well beyond email — they touched virtually the entire M365 environment during the attack window.

**Query — Full Application Footprint**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize Count = count() by AppDisplayName, IPAddress
| order by IPAddress asc
```

**Query — File & Data Access**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType in ("FileAccessed", "FileDownloaded", "FileViewed", "MailItemsAccessed")
| project TimeGenerated, ActionType, Application, AccountDisplayName, RawEventData
| order by TimeGenerated asc
```

| Application | Access Type | Significance |
|-------------|------------|--------------|
| One Outlook Web | `MailItemsAccessed` / Send | Email recon, inbox rules, BEC |
| Microsoft OneDrive for Business | `FileAccessed` | Personal file reconnaissance |
| SharePoint Online | Browse | Company document access |
| SharePoint Web Client Extensibility | Navigate | SharePoint environment mapping |
| OfficeHome | Navigate | Full M365 portal scoping |

---

## Defensive Gaps

> 🚨 **Critical — No Conditional Access Policies**
>
> The `ConditionalAccessStatus` field returned **`notApplied`** on every single attacker signin. LogN Pacific had **zero Conditional Access policies enforced** on their M365 environment. A properly configured policy could have blocked this attack by flagging the Netherlands origin, the unmanaged Ubuntu Linux device, or the impossible travel scenario.

**Query — Conditional Access Status Check**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| project TimeGenerated, AppDisplayName, ConditionalAccessStatus,
          RiskLevelDuringSignIn, UserAgent, Location
| order by TimeGenerated asc
```

> ⚠️ **High — No MFA Number Matching**
>
> Standard MFA push notifications with no number matching allowed Mark to blindly approve a request without verifying context. Number matching forces users to confirm a displayed code — making mindless approval during push bombing impossible.

---

## MITRE ATT&CK Mapping

| Technique ID | Tactic | Name | Description |
|-------------|--------|------|-------------|
| `T1621` | Credential Access | MFA Request Generation | Repeated MFA push notifications to fatigue the user into approving. Bypasses MFA by exploiting human frustration. Defence: implement number matching. |
| `T1564.008` | Defense Evasion | Hide Artifacts: Email Hiding Rules | Inbox rules created to silently forward financial emails externally and delete security alerts. Named with single invisible characters. |
| `T1555` | Credential Access | Credentials from Password Stores | Initial credentials obtained via infostealer malware logs purchased from underground markets prior to the attack. |
| `T1557` | Credential Access | Adversary-in-the-Middle | AiTM proxy intercepted the authenticated session token in real time after Mark approved the MFA push. |

---

## Threat Actor Attribution

| Attribute | Value |
|-----------|-------|
| Common Name | **Scattered Spider** |
| Mandiant Designation | `UNC3944` |
| Alternate Alias | `0ktapus` |
| Motivation | Financial |
| Known Victims | MGM Resorts, Caesars Entertainment, multiple UK retailers |

> 🕷️ **Attribution Rationale:** Every technique observed matches Scattered Spider's documented TTPs — MFA fatigue, AiTM session hijacking, single-character inbox rule names, thread hijacking for BEC, legitimate cloud infrastructure, and infostealer credentials as initial access. Attribution is assessed with **high confidence**.

> 📌 **Note on UNC3944:** This is Mandiant's internal tracking designation for Scattered Spider. "UNC" stands for *Uncategorised* — used for threat groups still being fully attributed before receiving a formal name designation.

---

## Indicators of Compromise

| Type | Value |
|------|-------|
| `IP` | `205.147.16.190` — Attacker IP (Netherlands) |
| `EMAIL` | `insights@duck.com` — Exfiltration address |
| `SESSION` | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` — Attacker session ID |
| `RULE` | `.` — Inbox rule forwarding: invoice, payment, wire, transfer |
| `RULE` | `-` — Inbox rule deleting: suspicious, security, phishing, unusual, compromised, verify |
| `USER-AGENT` | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0` |
| `SUBJECT` | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| `ACCOUNT` | `m.smith@lognpacific.org` — Compromised identity |
| `TARGET` | `j.reynolds@lognpacific.org` — BEC target |

---

## Containment Actions

> 🚨 **Immediate Priority — Revoke Session**
> The attacker still holds a valid session token. **Revoking the session is the single most important first action** — everything else means nothing if the attacker retains a live authenticated session in M365.

| Priority | Action | Rationale |
|----------|--------|-----------|
| 1 | **Revoke Session** | Invalidate all active tokens for `m.smith@lognpacific.org` immediately |
| 2 | **Reset Password** | Block re-authentication with stolen infostealer credentials |
| 3 | **Remove Inbox Rules** | Delete both `.` and `-` rules — stop exfiltration, restore visibility |
| 4 | **Block Attacker IP** | Block `205.147.16.190` at firewall and Conditional Access |
| 5 | **Notify J. Reynolds** | Confirm wire request was fraudulent — liaise with bank to recover frozen funds |
| 6 | **Org-Wide Audit** | Check all M365 accounts for similar inbox rules or suspicious signin activity |

---

## Recommendations

| Priority | Recommendation |
|----------|---------------|
| 🔴 Critical | **Implement Conditional Access policies** — Block signin from non-compliant devices and high-risk foreign locations immediately |
| 🔴 Critical | **Enable MFA number matching** — Prevents push bombing by requiring users to verify a displayed code before approving |
| 🔴 Critical | **Deploy FIDO2/WebAuthn hardware keys** — Cryptographically binds authentication to the legitimate domain, making AiTM interception impossible |
| 🟠 High | **Alert on external inbox rule forwarding** — Any `New-InboxRule` forwarding to an external domain should trigger an immediate security alert |
| 🟠 High | **User awareness training** — Focus on MFA fatigue recognition and email thread hijacking for all finance staff |
| 🟠 High | **Impossible travel alerting** — Flag simultaneous logins from geographically distant locations |
| 🟡 Medium | **Dark web credential monitoring** — Regularly check for employee credential exposure in infostealer logs |
| 🟡 Medium | **Finance process controls** — Require out-of-band verification (phone call) for any banking detail changes regardless of email source |

---

## Full Flags Log

| Flag | Category | Finding |
|------|----------|---------|
| F01 | Environment | `law-cyber-range` |
| F02 | Identity | `m.smith@lognpacific.org` |
| F03 | Geography | NL — Netherlands |
| F04 | Legitimate IP | `172.175.65.103` (United States) |
| F05 | Attacker IP | `205.147.16.190` (Netherlands) |
| F06 | Error Code | `50074` — Strong Authentication required |
| F07 | MFA Attempts | 3 failed attempts before approval |
| F08 | First App | `One Outlook Web` |
| F09 | First Action | `MailItemsAccessed` |
| F10 | Persistence | `New-InboxRule` |
| F11 | Rule 1 Name | `.` (single period) |
| F12 | Exfil Address | `insights@duck.com` |
| F13 | Rule 1 Keywords | `invoice, payment, wire, transfer` |
| F14 | Rule Parameter | `StopProcessingRules` |
| F15 | Rule 2 Name | `-` (single hyphen) |
| F16 | Rule 2 Keywords | `suspicious, security, phishing, unusual, compromised, verify` |
| F17 | BEC Recipient | `j.reynolds@lognpacific.org` |
| F18 | Email Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| F19 | Email Direction | `Intra-org` |
| F20 | IP Cross-Correl. | `205.147.16.190` confirmed across SigninLogs + EmailEvents |
| F21 | Data Store | `Microsoft OneDrive for Business` |
| F22 | Additional App | `SharePoint Online` |
| F23 | Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| F24 | CA Status | `notApplied` |
| F25 | MITRE — MFA | `T1621` — MFA Request Generation |
| F26 | MITRE — Rules | `T1564.008` — Email Hiding Rules |
| F27 | Initial Access | Infostealer credentials |
| F28 | Containment | Revoke Session |
| F29 | Threat Actor | **Scattered Spider** (UNC3944) |

---

<div align="center">

*Analyst: Ramin Delsouz &nbsp;|&nbsp; Platform: Microsoft Sentinel (law-cyber-range) &nbsp;|&nbsp; 26 February 2026*

*All IP addresses, email addresses, and domain names represent simulated infrastructure for training purposes only.*

</div>
