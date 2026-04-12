# 🕷️ Scattered Invoice — Threat Hunt Report

**Case:** Scattered Invoice  
**Analyst:** Ramin Delsouz  
**Platform:** Microsoft Sentinel (`law-cyber-range`)  
**Target Organisation:** LogN Pacific Financial Services — Finance Department  
**Investigation Window:** 25 Feb 2026 21:00 UTC → 26 Feb 2026 00:00 UTC  
**Report Date:** 26 Feb 2026  
**Classification:** Confidential — Internal IR Use Only  

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Incident Trigger](#incident-trigger)
3. [Compromised Identity](#compromised-identity)
4. [Attacker Infrastructure](#attacker-infrastructure)
5. [MFA Fatigue Attack](#mfa-fatigue-attack)
6. [Post-Compromise Activity](#post-compromise-activity)
7. [Persistence Mechanism — Inbox Rules](#persistence-mechanism--inbox-rules)
8. [Business Email Compromise](#business-email-compromise)
9. [Scope of Compromise](#scope-of-compromise)
10. [Defensive Gaps](#defensive-gaps)
11. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
12. [Threat Actor Attribution](#threat-actor-attribution)
13. [Indicators of Compromise](#indicators-of-compromise)
14. [Containment Actions](#containment-actions)
15. [Recommendations](#recommendations)
16. [Key Terminology](#key-terminology)
17. [Full Findings Log](#full-findings-log)

---

## Executive Summary

On the evening of 25 February 2026, a threat actor compromised the Microsoft 365 account of LogN Pacific Financial Services employee **Mark Smith** (`m.smith@lognpacific.org`) using an **MFA fatigue attack** combined with an **Adversary-in-the-Middle (AiTM)** session hijacking technique. The attacker, operating from the Netherlands via IP `205.147.16.190`, gained access to Mark's full M365 environment — including Outlook, OneDrive, and SharePoint.

Once inside, the attacker created two covert inbox rules to forward financial emails to an external address and delete all security alerts, effectively blinding the victim to the compromise. The attacker then sent a fraudulent email to finance colleague **J. Reynolds** (`j.reynolds@lognpacific.org`), impersonating Mark and requesting a £24,500 vendor payment be redirected to a fraudulent bank account.

The receiving bank flagged the transaction as suspicious and froze the funds, preventing the full financial loss. The attack is attributed to **Scattered Spider** (UNC3944), a financially motivated threat group known for MFA fatigue attacks, BEC fraud, and targeting financial services organisations.

---

## Incident Trigger

> **Reported:** 26 Feb 2026 09:30 UTC  
> Finance employee Mark Smith reported receiving repeated MFA push notifications on the evening of 25 February while at home. Believing it to be an IT glitch, he eventually approved one to make them stop. The following morning, colleagues discovered inbox rules no one had created. LogN Pacific's bank subsequently called to report a suspicious £24,500 wire transfer to an unknown account.

---

## Compromised Identity

| Attribute | Value |
|-----------|-------|
| **Name** | Mark Smith |
| **Email** | `m.smith@lognpacific.org` |
| **Department** | Finance |
| **Legitimate IP** | `172.175.65.103` (United States) |

Mark's account was confirmed as the entry point for the intrusion. His credentials had been obtained prior to the attack via infostealer malware logs purchased from underground markets, meaning the attacker had his password before the MFA fatigue campaign even began.

---

## Attacker Infrastructure

| Attribute | Value |
|-----------|-------|
| **Attacker IP** | `205.147.16.190` |
| **Country** | Netherlands (NL) |
| **Operating System** | Ubuntu Linux (x86_64) |
| **Browser** | Firefox 147.0 |
| **User-Agent** | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0` |
| **Exfiltration Email** | `insights@duck.com` |
| **Attacker Session ID** | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |

The attacker's use of **Ubuntu Linux with Firefox** rather than a typical Windows/Chrome combination is an anomaly indicator. The Netherlands origin contrasts starkly with Mark's United States baseline location, making this a clear impossible travel scenario that should have been caught by Conditional Access policies — had any been in place.

---

## MFA Fatigue Attack

The attacker employed **T1621 — Multi-Factor Authentication Request Generation**, commonly known as MFA fatigue or push bombing.

![Zoolander Cyber Meme](assets/Zoolander%20Cyber%20Meme.jpeg)

### How It Worked — AiTM Session Hijacking

The attacker did not simply guess Mark's MFA response. They deployed a more sophisticated **Adversary-in-the-Middle (AiTM)** proxy technique:

```
Normal login:   Mark → Microsoft ✅
AiTM attack:    Mark → Attacker Proxy → Microsoft
                             ↓
                        Steals session token
                             ↓
                Attacker → Microsoft (as Mark) ✅
```

1. **Credentials already stolen** — Mark's password was purchased from a dark web infostealer log prior to the attack
2. **Proxy established** — The attacker set up an AiTM proxy server between Mark and Microsoft
3. **Push bombing begins** — The proxy triggered real Microsoft MFA push notifications to Mark's phone
4. **Fatigue sets in** — After **3 failed attempts**, Mark approved a push just to make the notifications stop
5. **Session token stolen** — Microsoft issued a valid session cookie which the attacker's proxy intercepted in real time
6. **Session hijacked** — The attacker imported the stolen cookie into their Firefox browser in the Netherlands and was instantly authenticated as Mark — no password or MFA required

### MFA Push Bombing Sequence

| Time (UTC-5) | Result | Description |
|-------------|--------|-------------|
| 9:54:24 PM | 50074 | Strong Authentication required — failed |
| 9:54:55 PM | 50140 | Keep me signed in interrupt — failed |
| 9:55:15 PM | 50140 | Keep me signed in interrupt — failed |
| **9:59:52 PM** | **0** | **✅ Mark approves — attacker gains access** |

> **Error Code 50074** — Indicates strong authentication (MFA) was required but not completed. This code repeating multiple times in quick succession is the signature of an MFA fatigue attack in SigninLogs.

---

## Post-Compromise Activity

Immediately after authentication, the attacker moved methodically through Mark's M365 environment:

| Time (UTC-5) | Application | Action |
|-------------|------------|--------|
| 9:59 PM | One Outlook Web | `MailItemsAccessed` — Reading emails, reconnaissance |
| 10:02 PM | One Outlook Web | `New-InboxRule` — Created rule `.` (forward financial emails) |
| 10:03 PM | One Outlook Web | `New-InboxRule` — Created rule `-` (delete security alerts) |
| 10:06 PM | One Outlook Web | Sent fraudulent BEC email to J. Reynolds |
| 10:07 PM | Microsoft OneDrive for Business | `FileAccessed` — File reconnaissance |
| 10:09 PM | Office 365 SharePoint Online | Company document browsing |
| 10:10 PM | OfficeHome | M365 portal navigation |
| 10:12 PM+ | One Outlook Web | Continued email access |

The attacker's **first action** after gaining access was `MailItemsAccessed` — reading the inbox to understand active conversations, identify the right vendor thread, and gather intelligence before making their move. This demonstrates patience and operational discipline characteristic of Scattered Spider.

---

## Persistence Mechanism — Inbox Rules

The attacker created two inbox rules using **T1564.008 — Hide Artifacts: Email Hiding Rules**, both named with single invisible characters to evade detection.

![Girl Bro Cyber Meme](assets/Girl%20Bro%20Cyber%20Meme.jpeg)

### Rule 1 — Financial Email Exfiltration

| Parameter | Value |
|-----------|-------|
| **Rule Name** | `.` *(single period)* |
| **Forward To** | `insights@duck.com` |
| **Keywords** | `invoice, payment, wire, transfer` |
| **StopProcessingRules** | `True` |

Any email containing the words invoice, payment, wire, or transfer was silently forwarded to the attacker's external address at `insights@duck.com` in real time — creating a live wiretap on all of Mark's financial communications.

### Rule 2 — Security Alert Deletion

| Parameter | Value |
|-----------|-------|
| **Rule Name** | `-` *(single hyphen)* |
| **Keywords** | `suspicious, security, phishing, unusual, compromised, verify` |
| **DeleteMessage** | `True` |
| **StopProcessingRules** | `True` |

Any security alert, MFA notification, or IT warning email was automatically deleted before Mark could see it. This ensured the victim remained completely unaware of the compromise while it was actively occurring.

### ⭐ Key Analyst Note — Evasion by Invisibility

> The choice of a **single period (`.`)** and **single hyphen (`-`)** as rule names is a deliberate and highly effective evasion technique. When a user or administrator reviews the inbox rules list in Outlook, these characters appear as visual noise — they blend into the UI almost invisibly and do not raise suspicion the way descriptive names like "ForwardInvoices" or "DeleteAlerts" would. Most users would scroll past them without a second thought.

> Setting `StopProcessingRules` to `True` on both rules ensured no other rules processed matched emails afterward — the victim's own notification or folder rules never fired on financial or security emails. Together, these two rules created a complete intelligence blackout: the attacker could see everything while the victim saw nothing suspicious.

---

## Business Email Compromise

### ⭐ Key Analyst Note — Thread Hijacking

> The attacker did not send a new suspicious email. They **replied to an existing vendor invoice thread** — the "RE:" prefix made the email appear as a natural continuation of a legitimate conversation between colleagues. J. Reynolds had no reason to doubt an internal email from a known colleague continuing an active thread. This is a hallmark Scattered Spider technique: they don't create suspicious new emails, they **weaponize existing trusted conversations**.
>
> This is precisely why the finance team insists they "followed standard procedures" — from their perspective, they did. The fraud was invisible at the human level. The `Intra-org` email direction confirmed the email originated from a **legitimate internal account**, bypassing all external email security controls entirely.

### Fraudulent Email Details

| Attribute | Value |
|-----------|-------|
| **Time Sent** | 25 Feb 2026 10:06:39 PM UTC |
| **Sender** | `m.smith@lognpacific.org` *(attacker)* |
| **Recipient** | `j.reynolds@lognpacific.org` |
| **Subject** | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| **Sender IP** | `205.147.16.190` ✅ *Matches attacker IP — confirmed same session* |
| **Direction** | `Intra-org` |

The SenderIPv4 on the fraudulent BEC email matches the attacker's signin IP across both EmailEvents and SigninLogs — this cross-correlation across two separate log sources conclusively proves the same attacker session was responsible for both the authentication and the fraudulent wire transfer email.

---

## Scope of Compromise

![Oprah Cyber Meme](assets/Oprah%20Cyber%20Meme.jpeg)

The attacker's access extended well beyond email. They touched virtually the entire M365 environment during the attack window:

| Application | Access Type | Significance |
|-------------|------------|--------------|
| One Outlook Web | Email read/write | Reconnaissance, inbox rules, BEC |
| Microsoft OneDrive for Business | File access | Personal file reconnaissance |
| SharePoint Online | Document browsing | Company document access |
| SharePoint Online Web Client Extensibility | Navigation | SharePoint environment mapping |
| OfficeHome | Portal navigation | Full M365 environment scoping |

This was not a targeted smash-and-grab. The attacker methodically mapped the entire M365 environment — suggesting they were gathering intelligence for potential future attacks in addition to the immediate invoice fraud.

---

## Defensive Gaps

### ⭐ Critical Finding — No Conditional Access Policies

The `ConditionalAccessStatus` field in SigninLogs returned **`notApplied`** for every single attacker signin during the attack window. This means LogN Pacific had **no Conditional Access policies enforced** on their M365 environment.

A properly configured Conditional Access policy could have blocked this attack at multiple points:
- Blocking signin attempts from high-risk geographic locations (Netherlands vs. US baseline)
- Requiring compliant or managed devices (attacker used unmanaged Ubuntu Linux)
- Flagging impossible travel scenarios (US and NL in same session)
- Requiring number matching on MFA prompts (defeats push bombing entirely)

This is the single most significant defensive gap identified in this investigation.

---

## MITRE ATT&CK Mapping

| Technique ID | Tactic | Name | Description |
|-------------|--------|------|-------------|
| **T1621** | Credential Access | MFA Request Generation | Repeated MFA push notifications to fatigue the user into approving. Bypasses MFA by turning the security control against the user. The defence is implementing number matching on MFA prompts. |
| **T1564.008** | Defense Evasion | Hide Artifacts: Email Hiding Rules | Inbox rules created to forward financial emails externally and delete security alerts. Named with single invisible characters to evade detection. |
| **T1555** | Credential Access | Credentials from Password Stores | Initial credentials obtained via infostealer malware logs purchased from underground markets prior to the attack. |
| **T1557** | Credential Access | Adversary-in-the-Middle | AiTM proxy used to intercept the MFA session token in real time, enabling full account takeover without requiring ongoing access to the victim's credentials. |

---

## Threat Actor Attribution

**Threat Group: Scattered Spider (UNC3944 / 0ktapus)**

Scattered Spider is a financially motivated threat group known for:

- MFA fatigue / push bombing attacks (T1621)
- Help desk social engineering
- Business Email Compromise targeting finance teams
- Use of legitimate cloud infrastructure to blend in
- AiTM session hijacking
- Purchasing infostealer logs for initial credentials
- Targeting hospitality, retail, and financial services

**Known victims include:** MGM Resorts, Caesars Entertainment, and multiple UK retailers.

Every technique observed in this investigation — the MFA fatigue, the single-character inbox rule names, the thread hijacking, the legitimate cloud infrastructure, the financial targeting — is consistent with Scattered Spider's documented TTPs, confirming attribution with high confidence.

---

## Indicators of Compromise

| Type | Value |
|------|-------|
| Attacker IP | `205.147.16.190` |
| Attacker Country | Netherlands (NL) |
| Exfiltration Email | `insights@duck.com` |
| Attacker Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| Malicious Inbox Rule 1 | `.` (forward: invoice, payment, wire, transfer → insights@duck.com) |
| Malicious Inbox Rule 2 | `-` (delete: suspicious, security, phishing, unusual, compromised, verify) |
| Attacker User-Agent | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0` |
| Fraudulent Email Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Compromised Account | `m.smith@lognpacific.org` |
| Targeted Account | `j.reynolds@lognpacific.org` |

---

## Containment Actions

Immediate response actions in priority order:

1. **Revoke Session** — Invalidate all active tokens for `m.smith@lognpacific.org` immediately. This is the single most important first action — everything else means nothing if the attacker still has a live session.
2. **Reset Password** — Force password reset to prevent re-authentication with stolen credentials.
3. **Remove Inbox Rules** — Delete both `.` and `-` inbox rules to stop exfiltration and restore victim visibility.
4. **Block Attacker IP** — Block `205.147.16.190` at the firewall and Conditional Access level.
5. **Notify J. Reynolds** — Confirm the wire transfer request was fraudulent and liaise with the bank to recover the frozen £24,500.
6. **Audit all M365 users** — Check for similar inbox rules or suspicious signin activity across the organisation.

---

## Recommendations

| Priority | Recommendation |
|----------|---------------|
| 🔴 Critical | **Implement Conditional Access policies** — Block signin from non-compliant devices and high-risk locations immediately |
| 🔴 Critical | **Enable MFA number matching** — Prevents push bombing by requiring users to match a displayed code before approving |
| 🔴 Critical | **Deploy phishing-resistant MFA (FIDO2/WebAuthn)** — Hardware security keys cryptographically bind authentication to the legitimate domain, making AiTM interception impossible |
| 🟠 High | **Alert on New-InboxRule events** — Any inbox rule forwarding to external domains should trigger an immediate security alert |
| 🟠 High | **User awareness training** — Specifically targeting MFA fatigue recognition and thread hijacking awareness for finance staff |
| 🟠 High | **Impossible travel alerting** — Flag simultaneous or near-simultaneous logins from geographically distant locations |
| 🟡 Medium | **Monitor infostealer exposure** — Regularly check dark web sources for employee credential exposure |
| 🟡 Medium | **Financial process controls** — Require secondary verification (phone call) for any banking detail changes regardless of email source |

---

## Key Terminology

**Business Email Compromise (BEC)** — A cyberattack where an attacker compromises or impersonates a legitimate business email account to deceive employees into taking a financially damaging action. BEC is particularly dangerous because it bypasses technical controls by using real trusted accounts, exploits human trust, and targets financial workflows like wire transfers and invoice payments. The FBI consistently ranks BEC as the most financially damaging cybercrime globally. This investigation is a textbook example.

**MFA Fatigue (Push Bombing)** — A social engineering technique where an attacker repeatedly sends MFA push notifications to a victim's device until they approve one out of frustration or confusion. Requires no technical exploit — it attacks human patience rather than technical controls.

**Adversary-in-the-Middle (AiTM)** — An attack where a proxy server sits between the victim and a legitimate service, intercepting authentication tokens in real time. Used in this case to steal Mark's session cookie the moment he approved the MFA push.

**Infostealer** — Malware that silently harvests saved browser passwords, session tokens, autofill data, and credentials from infected machines. Stolen data is packaged into logs and sold on dark web markets. Scattered Spider routinely purchases these logs for initial access.

**Session Token / Cookie** — A credential issued by a service after successful authentication. Possessing a valid session token grants access without needing a username, password, or MFA. This is what the attacker stole via AiTM.

---

## Full Findings Log

| Flag | Finding |
|------|---------|
| F1 | Sentinel Workspace: `law-cyber-range` |
| F2 | Compromised Identity: `m.smith@lognpacific.org` |
| F3 | Attacker Country of Origin: `NL` (Netherlands) |
| F4 | Mark's Legitimate IP: `172.175.65.103` (United States) |
| F5 | Attacker IP: `205.147.16.190` (Netherlands) |
| F6 | MFA Incomplete Error Code: `50074` |
| F7 | MFA Push Bombing Attempts Before Success: `3` |
| F8 | First Application Accessed: `One Outlook Web` |
| F9 | First CloudApp Action: `MailItemsAccessed` |
| F10 | Persistence Mechanism: `New-InboxRule` |
| F11 | Inbox Rule 1 Name: `.` |
| F12 | Forward Destination: `insights@duck.com` |
| F13 | Keywords Monitored (Rule 1): `invoice, payment, wire, transfer` |
| F14 | Rule Priority Parameter: `StopProcessingRules` |
| F15 | Inbox Rule 2 Name: `-` |
| F16 | Delete Keywords (Rule 2): `suspicious, security, phishing, unusual, compromised, verify` |
| F17 | BEC Email Recipient: `j.reynolds@lognpacific.org` |
| F18 | BEC Email Subject: `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| F19 | Email Direction: `Intra-org` |
| F20 | BEC Sender IP (Cross-Correlated): `205.147.16.190` |
| F21 | Data Store Accessed: `Microsoft OneDrive for Business` |
| F22 | Additional Application Accessed: `SharePoint Online` |
| F23 | Attacker Session ID: `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| F24 | Conditional Access Status: `notApplied` |
| F25 | MITRE ATT&CK — MFA Fatigue: `T1621` |
| F26 | MITRE ATT&CK — Email Hiding: `T1564.008` |
| F27 | Initial Credential Source: `Infostealer` |
| F28 | First Containment Action: `Revoke Session` |
| F29 | Threat Actor: `Scattered Spider` |

---

*Report compiled by Ramin Delsouz | Cyber Range Investigation | LogN Pacific Financial Services*  
*All IP addresses, email addresses, and domain names represent simulated infrastructure for training purposes.*
