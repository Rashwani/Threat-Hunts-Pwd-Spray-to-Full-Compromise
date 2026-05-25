# Threat-Hunts-Pwd-Spray-to-Full-Compromise

# Threat Hunt: RDP Brute Force to Data Exfiltration

## Executive Summary

**Incident ID:** INC2025-0916-001  
**Incident Severity:** Severity 1 (Critical)  
**Incident Status:** Resolved

## Incident Overview

Following detection of suspicious RDP login activity on the cloud-hosted Windows server `slflarewinsysmo`, an investigation revealed a brute-force attack originating from external IP address `159.26.106.84`. After multiple failed login attempts against the `slflare` account, the attacker achieved a successful RDP logon at `6:40:57 PM UTC` on September 16, 2025.

Post-compromise, the attacker executed a malicious binary (`msupdate.exe`) disguised as a legitimate Microsoft update process, which invoked a PowerShell script (`update_check.ps1`) with execution policy bypass. Persistence was established through a scheduled task named `MicrosoftUpdateSync`. The attacker then impaired defenses by adding `C:\Windows\Temp` to Microsoft Defender's exclusion list, conducted system discovery using built-in Windows utilities, and staged collected data into an archive file (`backup_sync.zip`). Command and control communications were established with `185.92.220.87`, and exfiltration was attempted over HTTP to `185.92.220.87:8081`.

## Key Findings

- External IP `159.26.106.84` conducted brute-force RDP login attempts against the `slflare` account, achieving a successful logon after multiple failures.
- The attacker executed `msupdate.exe` from `C:\Users\Public\`, invoking a PowerShell script with `-ExecutionPolicy Bypass`.
- A scheduled task named `MicrosoftUpdateSync` was created for persistence.
- Microsoft Defender was weakened by adding `C:\Windows\Temp` to folder exclusions via `Add-MpPreference -ExclusionPath`, initiated by `payload.exe`.
- System discovery was performed using `"cmd.exe" /c systeminfo`, followed by `whoami /all` and `net user`.
- Sensitive data was archived into `backup_sync.zip` and staged for exfiltration.
- C2 communications were established with `185.92.220.87`.
- Exfiltration was attempted via `curl` and `powershell` over HTTP to `185.92.220.87:8081/api/upload`.

## Immediate Actions

The SOC and DFIR teams initiated incident response procedures upon detection. The compromised server `slflarewinsysmo` was immediately isolated via network segmentation. The `slflare` account was disabled in Active Directory. Firewall rules were updated to block all communications with `159.26.106.84`, `185.92.220.87`, and `79.76.123.251`. The malicious scheduled task `MicrosoftUpdateSync` was removed, the Defender exclusion was reverted, and all malicious binaries were quarantined. Available event logs and telemetry were preserved for forensic analysis.

---

## Technical Analysis

### Affected Systems & Data

**Devices**

| Asset | Type | Role in Attack |
| --- | --- | --- |
| `slflarewinsysmo` | Windows Server | Target of RDP brute force, payload execution, data staging and exfiltration |

**Accounts**

| Account | Usage |
| --- | --- |
| `slflare` | Compromised account — brute-forced via RDP, used for all post-exploitation activity |

---

## Evidence Sources & Analysis

### Initial Access — RDP Brute Force

#### 🔸 T1110.001 – Brute Force: Password Guessing
#### 🔸 T1078 – Valid Accounts

Querying `DeviceLogonEvents` filtered for the device name containing `"flare"` and action types of `LogonSuccess` and `LogonFailed` revealed a pattern of brute-force activity. Multiple failed login attempts from external IP `159.26.106.84` targeting the `slflare` account were observed between `6:36 PM` and `6:38 PM`, followed by a successful logon at `6:40:57 PM`.

A second failed attempt from a different IP (`79.76.123.251`) targeting the `slflarewinsysmo` account was also observed at `6:35 PM`, suggesting broader scanning activity.

```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| where ActionType has_any ("LogonSuccess", "LogonFailed")
| project TimeGenerated, ActionType, DeviceName, AccountDomain, AccountName, RemoteIP
| order by TimeGenerated desc
```

![RDP Brute Force - Logon Events](Screenshot_2026-05-22_164945.png)

![RDP Brute Force - Account Highlighted](Screenshot_2026-05-22_165021.png)

---

### Execution — Malicious Binary

#### 🔸 T1059.003 – Command and Scripting Interpreter: Windows Command Shell
#### 🔸 T1204.002 – User Execution: Malicious File

Querying `DeviceProcessEvents` filtered for the compromised account `slflare`, executable filenames, and process command lines referencing unusual paths (`public`, `temp`, `download`) revealed a suspicious binary `msupdate.exe` executed at `7:38:40 PM`. The binary was launched with `-ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`, indicating it was being used to invoke a PowerShell script while bypassing execution policy restrictions.

The binary was located in a public user directory — a common staging location for attacker tooling.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16) .. datetime(2025-09-17))
| where DeviceName has "slflarewinsysmo"
| where AccountDomain == "slflarewinsysmo"
| where FileName has "exe"
| where AccountName == "slflare"
| where ProcessCommandLine has_any ("public", "temp", "download")
| project TimeGenerated, DeviceName, AccountName, AccountDomain, ActionType, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

![Execution - Process Events](Screenshot_2026-05-22_171440.png)

![Execution - Command Line Detail](Screenshot_2026-05-22_171549.png)

---

### Persistence — Scheduled Task

#### 🔸 T1053.005 – Scheduled Task/Job: Scheduled Task

Querying `DeviceEvents` for `ScheduledTaskCreated` action types on the compromised device, filtered for events occurring after the initial binary execution timestamp, revealed a scheduled task named `MicrosoftUpdateSync` created at `7:39:45 PM` on September 16, 2025 — approximately one minute after the initial payload execution. The task name mimics legitimate Microsoft update processes to avoid detection.

```kql
DeviceEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:40.063299Z')
| where DeviceName contains "flare"
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, ActionType, TaskName = tostring(AdditionalFields.TaskName), InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

![Persistence - Scheduled Task Created](Screenshot_2026-05-25_155122.png)

---

### Defense Evasion — Defender Exclusion

#### 🔸 T1562.001 – Impair Defenses: Disable or Modify Windows Defender

Querying `DeviceProcessEvents` for process command lines containing `"ExclusionPath"` revealed three events related to Defender exclusion modifications. The earliest event at `2:59:47 AM` on September 27, 2025 shows `powershell.exe` executing `Add-MpPreference -ExclusionPath 'C:\Windows\Temp'`, initiated by `payload.exe`. This excluded the `C:\Windows\Temp` directory from Defender scans, allowing the attacker to operate freely within that path without triggering antimalware detections.

Two later events at `3:34 AM` show additional exclusion attempts for `C:\` — a much broader exclusion — initiated by `WinSetup.exe` and propagated through `cmd.exe`.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16) .. datetime(2025-09-30))
| where DeviceName contains "flare"
| where ProcessCommandLine has "ExclusionPath"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

![Defense Evasion - Defender Exclusion](Screenshot_2026-05-25_160832.png)

---

### Discovery — System Enumeration

#### 🔸 T1082 – System Information Discovery

Querying `DeviceProcessEvents` for common Windows enumeration binaries (`whoami.exe`, `ipconfig.exe`, `hostname.exe`, `systeminfo.exe`, `net.exe`, `net1.exe`, `netstat.exe`, `tasklist.exe`, `query.exe`, `nltest.exe`, `wmic.exe`, `arp.exe`, `nslookup.exe`) revealed a sequence of reconnaissance commands executed under the compromised `slflare` session.

The earliest discovery command was `"cmd.exe" /c systeminfo` at `7:40:28 PM`, followed by `whoami /all` at `7:40:34 PM` and `net user` at `7:40:35 PM`. These commands enumerate host configuration, current user privileges, and local user accounts respectively. The initiating process for `systeminfo` was `"cmd.exe" /c systeminfo`, while subsequent commands were launched from interactive `cmd.exe` sessions.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16) .. datetime(2025-09-17))
| where DeviceName == "slflarewinsysmo"
| where FileName in ("whoami.exe", "ipconfig.exe", "hostname.exe", "systeminfo.exe", "net.exe", "net1.exe", "netstat.exe", "tasklist.exe", "query.exe", "nltest.exe", "wmic.exe", "arp.exe", "nslookup.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

![Discovery - System Enumeration](Screenshot_2026-05-25_161358.png)

---

### Collection — Data Archiving

#### 🔸 T1560.001 – Archive Collected Data: Local Archiving

Querying `DeviceProcessEvents` for process command lines containing archive-related strings (`.zip`, `.rar`, `.7z`, `.tar`, `Compress-Archive`) revealed data staging activity. At `7:43:20 PM`, the attacker used `curl` via `cmd.exe` to upload a file named `backup_sync.zip` from `C:\Users\SLFlare\AppData\Local\Temp\` to the C2 server.

Multiple exfiltration attempts were observed using both `curl` (at `7:43:20 PM` and `7:43:21 PM`) and `powershell Invoke-WebRequest` (at `7:43:28 PM`), all targeting the same archive file and external endpoint.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16) .. datetime(2025-09-17))
| where DeviceName == "slflarewinsysmo"
| where ProcessCommandLine has_any (".zip", ".rar", ".7z", ".tar", "Compress-Archive")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

![Collection - Archive File](Screenshot_2026-05-25_161802.png)

---

### Command and Control — C2 Beacon

#### 🔸 T1071.001 – Application Layer Protocol: Web Protocols (HTTP/S)
#### 🔸 T1105 – Ingress Tool Transfer

Analysis of the exfiltration-related process events revealed the C2 server destination. The `curl` and `powershell Invoke-WebRequest` commands both contacted `185.92.220.87` on port `8081` at the `/api/upload` endpoint. This external IP served as both the C2 callback destination and the exfiltration endpoint.

The C2 traffic used HTTP (unencrypted), making it detectable via network monitoring and proxy logs.

![C2 - Destination IP](Screenshot_2026-05-25_161834.png)

---

### Exfiltration — Data Theft Attempt

#### 🔸 T1048.003 – Exfiltration Over Unencrypted Protocol

The attacker attempted to exfiltrate the staged archive `backup_sync.zip` to the external C2 server using multiple methods. The earliest attempt at `7:43:20 PM` used `curl -X POST` with the `-F` flag to upload the file to `http://185.92.220.87:8081/upload`. A second attempt at `7:43:21 PM` used the same `curl` method. A third attempt at `7:43:28 PM` used `powershell -Command "Invoke-WebRequest"` with `-Method POST` to the same destination at `http://185.92.220.87:8081/api/upload`.

The use of port `8081` and unencrypted HTTP for data exfiltration is consistent with attacker tooling designed for speed rather than stealth.

![Exfiltration - IP and Port](Screenshot_2026-05-25_161907.png)

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
| --- | --- | --- | --- |
| Initial Access | T1110.001 | Brute Force: Password Guessing | Multiple failed RDP logins from `159.26.106.84` followed by success |
| Initial Access | T1078 | Valid Accounts | Successful RDP login using `slflare` credentials |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `msupdate.exe` invoking PowerShell script |
| Execution | T1204.002 | User Execution: Malicious File | Execution of `msupdate.exe` from `C:\Users\Public\` |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | `MicrosoftUpdateSync` scheduled task created |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Windows Defender | `C:\Windows\Temp` added to Defender exclusions |
| Discovery | T1082 | System Information Discovery | `systeminfo`, `whoami /all`, `net user` executed |
| Collection | T1560.001 | Archive Collected Data: Local Archiving | `backup_sync.zip` created in user Temp directory |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP communications to `185.92.220.87:8081` |
| Command and Control | T1105 | Ingress Tool Transfer | Tooling retrieved from external C2 server |
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted Protocol | `curl` and `Invoke-WebRequest` POST to `185.92.220.87:8081` |

---

## Recommendations

1. **Enforce MFA on all RDP-accessible accounts** to prevent credential-based brute-force attacks from succeeding even when passwords are compromised.
2. **Restrict RDP access** to authorized IP ranges via Network Security Groups or firewall rules; disable public-facing RDP where not required.
3. **Implement account lockout policies** to automatically lock accounts after a defined number of failed login attempts.
4. **Monitor for scheduled task creation** via Defender for Endpoint or SIEM alerting rules, especially tasks with names mimicking legitimate Microsoft services.
5. **Alert on Defender exclusion modifications** — any change to `Add-MpPreference -ExclusionPath` should trigger a high-priority alert for SOC review.
6. **Restrict PowerShell execution policies** and enable Script Block Logging, Module Logging, and Transcription Logging for full visibility into PowerShell activity.
7. **Block known malicious IPs** (`159.26.106.84`, `185.92.220.87`, `79.76.123.251`) at the perimeter firewall and in endpoint detection rules.
8. **Deploy application whitelisting** to prevent execution of binaries from non-standard paths such as `C:\Users\Public\` and `C:\Windows\Temp\`.
9. **Enable enhanced network monitoring** for outbound HTTP traffic on non-standard ports (e.g., 8081) to detect C2 and exfiltration activity.
10. **Conduct a password reset** for all accounts on the compromised system and review for lateral movement to other assets.
