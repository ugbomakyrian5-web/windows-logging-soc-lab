# 🔍 SOC Investigation: Windows Logging – Brute Force, Persistence & C2 Detection

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat&logo=tryhackme)](https://tryhackme.com)
[![Path](https://img.shields.io/badge/Path-SOC%20Level%201-blue?style=flat)](https://tryhackme.com/path/outline/soclevel1)
[![Topic](https://img.shields.io/badge/Topic-Windows%20Event%20Log%20Analysis-007ACC?style=flat)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat)]()
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()
[![Tools](https://img.shields.io/badge/Tools-Event%20Viewer%20%7C%20Sysmon%20%7C%20PowerShell%20History%20%7C%20VirusTotal-blue?style=flat)]()

Post-compromise SOC investigation into a Windows endpoint breach on THM-PC. An attacker brute-forced their way in via RDP, created a hidden backdoor account with elevated privileges, downloaded and executed confirmed malware, established C2 communication, embedded startup persistence — and left a trail across Windows Security logs, Sysmon telemetry, and PowerShell command history.

**Attack chain confirmed:**
> Brute Force → RDP Access → Backdoor Account Creation → Privilege Escalation → Malware Execution → Startup Persistence → C2 Communication

---

## 📌 Investigation Summary

| Field | Detail |
|-------|--------|
| **Incident** | Windows endpoint compromise — RDP brute force, malware, C2 |
| **Target Host** | THM-PC |
| **Attacker Source IP** | 10.10.53.248 (Workstation: b1465f) |
| **Compromised Account** | Administrator |
| **Logon ID** | `0x183c36d` (Logon Type 10 — RDP) |
| **Backdoor Account** | `svc_sysrestore` |
| **Malware** | `ckjg.exe` — `http://gettsveriff[.]com/bgj3/ckjg.exe` |
| **Malware Hash (MD5)** | `962D2A0880C5325328930B66BB4E2CF1` |
| **C2 Server** | `193.46.217.4:7777` |
| **C2 Domain** | `hkfasfsafg[.]click` |
| **Persistence** | `DeleteApp.url` — Startup folder |
| **Evidence Sources** | Windows Security EVTX, Sysmon EVTX, PowerShell history, VirusTotal |
| **Outcome** | Full 7-stage attack chain reconstructed — IOCs extracted, flags recovered |

---

## 🎯 Key Findings

| # | Finding | Event ID / Source |
|---|---------|------------------|
| 1 | Brute-force attack from `10.10.53.248` — repeated 4625 failures | Event ID 4625 |
| 2 | Successful RDP login — Administrator compromised — Logon ID `0x183c36d` | Event ID 4624 (Type 10) |
| 3 | Backdoor account `svc_sysrestore` created at 5/17/2025 10:54:58 PM | Event ID 4720 |
| 4 | `svc_sysrestore` added to Backup Operators + Remote Desktop Users | Event ID 4732 |
| 5 | Browser: Google Chrome — malware `ckjg.exe` downloaded via Chrome | Sysmon Event ID 1 |
| 6 | `ckjg.exe` downloaded from `http://gettsveriff[.]com/bgj3/ckjg.exe` | Sysmon Event ID 1 + VirusTotal |
| 7 | VirusTotal verdict: **MALWARE — 100% score** (Nucleon Malprob) | VirusTotal |
| 8 | Startup persistence — `DeleteApp.url` written to Startup folder | Sysmon Event ID 11 |
| 9 | C2 connection to `193.46.217.4:7777` | Sysmon Event ID 3 |
| 10 | C2 domain confirmed: `hkfasfsafg[.]click` via DNS query | Sysmon Event ID 22 |
| 11 | First PowerShell command: `Get-ComputerInfo` — May 18, 2025 | PowerShell History |
| 12 | Flag recovered from sarah.miller's PS history: `THM{it_was_me!}` | PowerShell History |

---

## 🔎 Investigation Walkthrough

### Phase 1 — Initial Access: Brute-Force Attack Detected

**Event ID**: 4625 (Failed Logon)
**Source IP**: 10.10.53.248
**Workstation**: b1465f
**Timestamp**: 5/17/2025 10:53:30 PM

Security log analysis revealed repeated Event ID 4625 failures originating from a single external IP — `10.10.53.248`. The workstation name `b1465f` does not follow any corporate naming pattern, immediately flagging it as external. The pattern of rapid, repeated failures is consistent with automated brute-force or password spraying targeting the Administrator account via RDP.

**Key indicator**: High-frequency 4625 events from a single non-corporate source IP — the definitive brute-force signature in Windows Security logs.

#### 📸 Screenshot 1 — Event ID 4625: Brute-Force Activity from 10.10.53.248
<img width="1366" height="720" alt="image" src="https://github.com/user-attachments/assets/fbdb53cc-1dd2-42f6-92de-af63e870d5ae" />


*Event ID 4625 — Source Network Address: 10.10.53.248, Workstation: b1465f — repeated failed logon attempts confirm brute-force activity*

---

### Phase 2 — Initial Access: Successful RDP Login — Logon ID Established

**Event ID**: 4624 (Successful Logon)
**Logon Type**: 10 (RemoteInteractive — RDP)
**Compromised Account**: Administrator
**Logon ID**: `0x183c36d`
**Timestamp**: 5/17/2025 10:53:41 PM

Following the brute-force, Event ID 4624 with Logon Type 10 confirmed a successful RDP login to the Administrator account. The Logon ID `0x183c36d` was saved immediately — this value became the investigation's anchor, used to correlate every subsequent attacker action (account creation, privilege changes) back to this single authenticated session.

**Key insight**: Logon ID is the backbone of Windows incident investigation. It transforms isolated events into a connected attack chain.

#### 📸 Screenshot 2 — Event ID 4624: Successful RDP Login — Logon ID `0x183c36d`
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/b523e828-ed4d-430e-a466-4bba9133be08" />

*Event ID 4624 — TargetUserName: Administrator, LogonType: 10, TargetLogonId: 0x183c36d — RDP compromise confirmed*

---

### Phase 3 — Persistence: Backdoor Account Created

**Event ID**: 4720 (User Account Created)
**New Account**: `svc_sysrestore`
**Timestamp**: 5/17/2025 10:54:58 PM
**Logon ID Match**: Confirmed — same session as malicious RDP login

One minute after gaining access, the attacker created `svc_sysrestore` — a service-account-style name designed to blend into a legitimate system account list. Event ID 4720 logged the creation with the Logon ID matching the attacker's RDP session, directly tying this action to the compromised Administrator account.

**Key indicator**: New account creation by an account whose Logon ID matches a preceding suspicious 4624 event — immediate escalation trigger.

#### 📸 Screenshot 3 — Event ID 4720: `svc_sysrestore` Backdoor Account Created
<img width="1366" height="720" alt="image" src="https://github.com/user-attachments/assets/666f434c-a2a1-41c5-bb3f-43cd1a5cae15" />

*Event ID 4720 — New Account: svc_sysrestore — created at 10:54:58 PM, 1 minute after successful RDP login*

---

### Phase 4 — Privilege Escalation: Backdoor Account Added to Privileged Groups

**Event ID**: 4732 (User Added to Security Group)
**Groups Assigned**:
- Backup Operators
- Remote Desktop Users
**Timestamp**: 5/17/2025 10:54:59 PM — 10:55:24 PM

Within seconds of creation, `svc_sysrestore` was added to two privileged groups. `Backup Operators` grants access to backup and restore files regardless of file permissions — a powerful privilege for data theft. `Remote Desktop Users` ensures the backdoor account retains persistent RDP access even if the Administrator password is reset.

**Key indicator**: 4720 immediately followed by 4732 within the same session — account creation + privilege assignment is a high-confidence persistence pattern.

#### 📸 Screenshot 4 — Event ID 4732: `svc_sysrestore` Added to Remote Desktop Users + Backup Operators
<img width="1366" height="720" alt="image" src="https://github.com/user-attachments/assets/e43f3ccd-0126-4ad8-845b-6fa40e85d3d5" />

*Event ID 4732 — svc_sysrestore added to Remote Desktop Users and Backup Operators — persistent elevated access established*

---

### Phase 5 — Execution: Malware Downloaded via Google Chrome

**Sysmon Event ID**: 1 (Process Creation)
**Browser**: Google Chrome (`GoogleUpdater\138.0.7156.0\updater.exe` as parent)
**Downloaded File**: `C:\Users\sarah.miller\Downloads\ckjg.exe`
**Source URL**: `http://gettsveriff[.]com/bgj3/ckjg.exe`
**MD5 Hash**: `962D2A0880C5325328930B66BB4E2CF1`
**SHA256**: `08037DE4A729634FA818DDF03DDD27C28C89F42158AF5EDE71CF0AE2D78FA198`

Sysmon Event ID 1 captured `ckjg.exe` being spawned from `sarah.miller`'s Downloads directory with Google Chrome's updater as the parent process — confirming a browser-initiated download. The source URL — `gettsveriff[.]com` — has no legitimate business presence. The file was submitted to VirusTotal which returned a **100% MALWARE verdict** from Nucleon Malprob, with YARA tags including `#keylogger`, `#inject_thread`, `#win_hook`, and `#dropper_strings`.

**Key indicator**: Executable spawned from `\Downloads\` by browser process + unknown external domain + confirmed malware hash.

#### 📸 Screenshot 5 — Sysmon Event ID 1: Google Chrome Identified as Sarah's Browser
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/7f57c562-673a-42dd-9198-d318e635fe85" />

*Sysmon Event ID 1 — ParentImage: GoogleUpdater\138.0.7156.0\updater.exe confirms Google Chrome as Sarah's browser*

#### 📸 Screenshot 6 — Sysmon Event ID 1: `ckjg.exe` Execution — Parent Confirmed as Chrome
<img width="1366" height="731" alt="image" src="https://github.com/user-attachments/assets/483505d4-d0b7-40d7-b34c-7c7b3877f077" />

*Sysmon Event ID 1 — ParentCommandLine: C:\Users\sarah.miller\Downloads\ckjg.exe — malware execution confirmed under sarah.miller context*

#### 📸 Screenshot 7a — Sysmon Event ID 1: MD5 Hash of `ckjg.exe` Extracted
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/deef8566-db8e-47d3-8d46-61af5ee08f52" />

*Sysmon Event ID 1 — MD5: 962D2A0880C5325328930B66BB4E2CF1 — hash submitted to VirusTotal for reputation check*

#### 📸 Screenshot 7b — VirusTotal: `ckjg.exe` Confirmed MALWARE — Source URL Verified
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/fb5b21ee-1961-4119-871a-85d2513b9fe4" />

*VirusTotal community — Nucleon Malprob verdict: MALWARE 100% — SRC URL: http://gettsveriff[.]com/bgj3/ckjg.exe confirmed*

---

### Phase 6 — Persistence: Startup Folder File Drop

**Sysmon Event ID**: 11 (File Creation)
**Image**: `C:\Users\sarah.miller\Downloads\ckjg.exe`
**Target File**: `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`
**Timestamp**: 5/18/2025 16:08:46 UTC

Sysmon Event ID 11 captured `ckjg.exe` writing `DeleteApp.url` directly to the user's Startup folder — confirming the malware immediately established persistence after execution. The filename `DeleteApp.url` is deliberately innocuous, designed to avoid suspicion during casual file system review. The file executes automatically on every login of `sarah.miller`.

**Key indicator**: File creation in `\Start Menu\Programs\Startup\` by a non-system process — any such event warrants immediate investigation regardless of filename.

#### 📸 Screenshot 8 — Sysmon Event ID 11: `DeleteApp.url` Written to Startup Folder
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/6c5d6a57-33e4-425b-bed2-61c48de05d8c" />

*Sysmon Event ID 11 — Image: ckjg.exe → TargetFilename: \Startup\DeleteApp.url — startup persistence confirmed at 16:08:46 UTC*

---

### Phase 7 — Command & Control: Outbound C2 Connection

**Sysmon Event ID**: 3 (Network Connection)
**Destination IP**: `193.46.217.4`
**Destination Port**: `7777`
**Timestamp**: 5/18/2025 16:08:58 UTC

**Sysmon Event ID**: 22 (DNS Query)
**Query Name**: `hkfasfsafg[.]click`
**Query Result**: `193.46.217.4`
**ProcessId**: 1460 (ckjg.exe)

Sysmon Event ID 3 captured an outbound connection from `ckjg.exe` to `193.46.217.4` on port `7777` — a non-standard port commonly used for C2 to evade default firewall rules. Correlating via ProcessId 1460, Sysmon Event ID 22 revealed the DNS query that resolved `hkfasfsafg[.]click` to the same IP — confirming the full C2 infrastructure: domain → IP → port.

**Key indicator**: Outbound connection on non-standard port (7777) from a recently executed unknown process, resolving to a suspicious `.click` domain — immediate containment trigger.

#### 📸 Screenshot 9 — Sysmon Event ID 3: C2 Connection to `193.46.217.4:7777`
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/ea47754e-227e-411f-843c-bc3fe05557e0" />

*Sysmon Event ID 3 — DestinationIp: 193.46.217.4, DestinationPort: 7777 — outbound C2 connection from ckjg.exe confirmed*

#### 📸 Screenshot 10 — Sysmon Event ID 22: DNS Query Confirms C2 Domain `hkfasfsafg[.]click`
<img width="1366" height="724" alt="image" src="https://github.com/user-attachments/assets/4270ddcb-f23a-4e39-b1de-bc62e8479d1a" />

*Sysmon Event ID 22 — QueryName: hkfasfsafg.click → QueryResults: 193.46.217.4 — DNS resolution confirms full C2 infrastructure*

---

### Phase 8 — PowerShell Forensics: Attacker Commands & Flag Recovery

**Log Source**: `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
**First Command**: `Get-ComputerInfo`
**File Created**: May 18, 2025 (confirmed via file Properties)

**Log Source**: `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
**Commands Observed**: `get-localuser`, `get-smbshare`, `ipconfig /all`, `get-mppreference`, `clear-recyclebin`
**Flag**: `THM{it_was_me!}`

PowerShell history analysis across multiple user profiles provided decisive corroborating evidence. The Administrator's history confirmed `Get-ComputerInfo` as the first command — system enumeration immediately post-compromise. The file creation date of May 18, 2025 confirmed when the attacker began their PowerShell activity.

Crucially, the flag `THM{it_was_me!}` was found in `sarah.miller`'s PowerShell history — embedded via `echo "THM{it_was_me!}" > flag.txt` — confirming the attacker operated under her account context and confirming complete forensic reconstruction of the breach.

**Key insight**: PowerShell history survives reboots, covers all sessions, and captures commands invisible to Sysmon Event ID 1 — checking every active user's history file is essential in Windows investigations.

#### 📸 Screenshot 11 — Administrator PowerShell History: `Get-ComputerInfo` First Command
<img width="1366" height="722" alt="image" src="https://github.com/user-attachments/assets/2b96bcb4-c9ff-4c66-9206-35e13d952a0d" />

*Administrator ConsoleHost_history.txt — Get-ComputerInfo highlighted as first command — system enumeration post-compromise*

#### 📸 Screenshot 12 — PowerShell History File Properties: Created May 18, 2025
<img width="1366" height="724" alt="image" src="https://github.com/user-attachments/assets/6d8d75a8-4db4-4e04-bc3f-073ed93f0a57" />

*ConsoleHost_history Properties — Created: Sunday, May 18, 2025, 8:49:26 PM — confirms when Administrator first ran PowerShell*

#### 📸 Screenshot 13 — sarah.miller PowerShell History: Flag `THM{it_was_me!}` Recovered
<img width="1366" height="722" alt="image" src="https://github.com/user-attachments/assets/3e7a4103-55ab-4e91-91f3-b08a29bce08a" />

*sarah.miller ConsoleHost_history.txt — echo "THM{it_was_me!}" > flag.txt — flag confirmed, full attacker activity reconstructed*

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|----|----------|
| Initial Access | Brute Force | T1110 | Password spraying via RDP — Event ID 4625 |
| Initial Access | Valid Accounts | T1078 | Administrator RDP login — Event ID 4624 Logon Type 10 |
| Persistence | Create Account | T1136 | `svc_sysrestore` — Event ID 4720 |
| Privilege Escalation | Account Manipulation | T1098 | Added to Backup Operators + RDP Users — Event ID 4732 |
| Execution | User Execution: Malicious File | T1204.002 | `ckjg.exe` executed from Downloads — Sysmon Event ID 1 |
| Persistence | Boot or Logon Autostart: Startup Folder | T1547.001 | `DeleteApp.url` — Sysmon Event ID 11 |
| Command & Control | Application Layer Protocol | T1071 | HTTP-based C2 to `hkfasfsafg[.]click:7777` — Sysmon Event ID 3 |
| Discovery | System Information Discovery | T1082 | `Get-ComputerInfo` — PowerShell history |
| Collection | Data from Local System | T1005 | `get-localuser`, `get-smbshare`, `ipconfig /all` — PowerShell history |

---

## 🛡 Containment & Hardening Recommendations

### Immediate Response
- **Isolate THM-PC** — block all outbound traffic to `193.46.217.4` immediately
- **Disable and delete `svc_sysrestore`** — backdoor account confirmed
- **Reset Administrator credentials** — account confirmed compromised
- **Delete `DeleteApp.url`** from `\Startup\` — persistence mechanism confirmed
- **Block `gettsveriff[.]com` and `hkfasfsafg[.]click`** at DNS and firewall
- **Submit `ckjg.exe` for full sandbox analysis** — YARA tags suggest keylogger + injector capabilities

### Authentication Hardening
- Enforce **account lockout after 5 failed attempts** — defeats brute force at source
- Implement **MFA for all RDP access** — single-factor authentication is insufficient
- Restrict **RDP to trusted IP ranges only** via Windows Firewall / network ACL
- Disable RDP entirely if not operationally required

### Detection Rules (SIEM)
Brute force detection
Alert: >10 Event ID 4625 from single IP within 60 seconds
Successful login post-brute-force
Alert: Event ID 4624 within 5 minutes of 10+ Event ID 4625 from same source IP
Backdoor account creation
Alert: Event ID 4720 + Event ID 4732 sharing same Logon ID within 60 seconds
Malware execution from user directories
Alert: Sysmon Event ID 1 — process spawned from \Downloads\ or \AppData\Temp\
Startup folder persistence
Alert: Sysmon Event ID 11 — file written to \Start Menu\Programs\Startup\
C2 on non-standard ports
Alert: Sysmon Event ID 3 — outbound connection on ports 4444, 7777, 8888, 1337
Suspicious DNS queries
Alert: Sysmon Event ID 22 — query to *.click, *.top, *.xyz domains from endpoint processes
PowerShell download commands
Alert: PowerShell Script Block containing Invoke-WebRequest + .exe extension

---

## 📌 Investigator Notes

> Windows investigations are a correlation exercise — no single event tells the full story.
> The attack only became visible by linking events across three separate log sources:
>
> **Security logs**: 4625 → 4624 (brute force to RDP success) → 4720 + 4732 (account creation + privilege)
> **Sysmon**: Event ID 1 (malware execution) → Event ID 11 (startup persistence) → Event ID 3 + 22 (C2 connection + DNS)
> **PowerShell history**: system enumeration commands + flag confirming attacker operated as sarah.miller
>
> The Logon ID `0x183c36d` was the thread that tied the Security log events together.
> ProcessId `1460` was the thread that tied the Sysmon events together.
> Without both, the attack chain fragments into disconnected, unactionable alerts.

---

## 📌 Key Windows Event IDs Reference

| Event ID | Description | Attack Phase |
|----------|-------------|--------------|
| 4625 | Failed logon | Brute force detection |
| 4624 | Successful logon | Initial access confirmation |
| 4720 | User account created | Persistence — backdoor account |
| 4732 | User added to security group | Privilege escalation |
| Sysmon 1 | Process creation | Malware execution |
| Sysmon 3 | Network connection | C2 detection |
| Sysmon 11 | File creation | Persistence — startup folder |
| Sysmon 22 | DNS query | C2 domain resolution |

---

## 📌 Skills Demonstrated

- Windows Security Event Log analysis — 4624, 4625, 4720, 4732
- Sysmon endpoint detection — process creation, network connections, file writes, DNS queries
- Logon ID and ProcessId correlation to link attacker actions across log sources
- Malware hash extraction and VirusTotal threat intelligence enrichment
- Startup folder persistence identification and analysis
- Multi-user PowerShell history forensic investigation
- C2 infrastructure profiling — IP, port, domain correlation via Sysmon Event IDs 3 + 22
- Structured, SOC-grade incident documentation with MITRE ATT&CK mapping

---

**Completed**: May 2026

Full portfolio of SOC investigations available at [github.com/ugbomakyrian5-web](https://github.com/ugbomakyrian5-web)

Feel free to fork, star, or reach out. Open to feedback and collaboration!

MIT License – see the [LICENSE](LICENSE) file for details.
