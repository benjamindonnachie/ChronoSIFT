# ChronoSift v2.31 Dead-Box ATT&CK Matrix

Status key:

- `Covered` = implemented explicitly in ChronoSift v2.31
- `Plaso-possible` = realistically derivable from dead-box Plaso artifacts but not yet modeled deeply enough
- `Not realistic` = generally requires live, volatile, or non-Plaso telemetry

This matrix maps ATT&CK techniques against:

- whether they are realistically identifiable during dead-box forensics
- whether they can plausibly be derived from Plaso output
- whether ChronoSift v2.31 currently covers them

The mapping is based on:

- [chronoSIFT_v2_31.py](../chronoSIFT_v2_31.py)
- [rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml](../rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml)
- [weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml](../rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml)
- [chronosift_yara_category_mapping.md](YARA_ENRICHMENT.md) — YARA Forge category-aware scoring reference
- Plaso parser and field availability as documented in the Plaso GitHub repository and wiki

## Matrix

| Tactic | ATT&CK ID | Technique | Dead-box identifiable? | Detectable from Plaso output? | ChronoSift v2.31 status | Notes |
|---|---|---|---|---|---|---|
| Initial Access | T1078 | Valid Accounts | Yes | Yes | Covered | Successful SSH/RDP/auth patterns plus contextual anomaly logic |
| Initial Access | T1190 | Exploit Public-Facing Application | Partial | Partial | Covered | Conservative web request, upload, traversal, and command-exec correlation |
| Initial Access | T1133 | External Remote Services | Partial | Partial | Covered | Remote-service success semantics are modeled, but confidence remains low |
| Execution | T1059 | Command and Scripting Interpreter | Yes | Yes | Covered | Linux interpreters, shell history, and command-line artefacts |
| Execution | T1218 | System Binary Proxy Execution | Yes | Yes | Covered | Windows LOLBins and suspicious argument patterns |
| Execution | T1053.003 | Cron | Yes | Yes | Covered | Cron execution and cron persistence are both represented |
| Execution | T1053.005 | Scheduled Task | Yes | Yes | Covered | Scheduled execution and task-cache/task artefacts |
| Execution | T1204 | User Execution | Partial | Partial | Covered | Browser download plus nearby execution correlation is explicit in v2.31 |
| Persistence | T1543.003 | Windows Service | Yes | Yes | Covered | Service artefacts and service configuration changes |
| Persistence | T1547.001 | Run Keys / Startup Folder | Yes | Partial | Covered | Run keys explicit; Startup folder remains more indirect |
| Persistence | T1136 | Create Account | Yes | Yes | Covered | Windows account creation and Linux user/group command evidence |
| Persistence | T1098 | Account Manipulation | Yes | Yes | Covered | Account/group change and privileged group addition logic |
| Persistence | T1547.004 | Winlogon Helper DLL | Yes | Yes | Covered | Registry path matching for Winlogon Shell/Userinit/Notify/AppInit/Taskman value modifications |
| Persistence | T1546.015 | Component Object Model Hijacking | Yes | Yes | Covered | CLSID InprocServer32 and TreatAs registry modification detection |
| Persistence | T1543.002 | Systemd Service | Yes | Yes | Covered | Filesystem and command/log semantics for unit management are modeled |
| Persistence | T1098.004 | SSH Authorized Keys | Yes | Yes | Covered | File create/modify/delete evidence is modeled directly |
| Persistence | T1505.003 | Web Shell | Partial | Partial | Covered | Web-root script artefacts, suspicious requests, temporal webshell activity chains, and YARA `webshell` category hits (551 rules) |
| Privilege Escalation | T1548.001 | Setuid and Setgid | Yes | Yes | Covered | SUID-related command and path heuristics |
| Privilege Escalation | T1543.003 | Windows Service | Yes | Yes | Covered | Service installation/change may also support escalation narratives |
| Privilege Escalation | T1055 | Process Injection | No | No | Not realistic | Normally requires volatile memory or detailed endpoint telemetry |
| Defense Evasion | T1218 | System Binary Proxy Execution | Yes | Yes | Covered | Shared execution/evasion coverage through LOLBins |
| Defense Evasion | T1562.001 | Disable or Modify Tools | Yes | Yes | Covered | Defender disablement and security-control impairment indicators |
| Defense Evasion | T1562.004 | Disable or Modify Firewall | Yes | Yes | Covered | Firewall file/config/log-based change detection |
| Defense Evasion | T1070 | Indicator Removal on Host | Partial | Partial | Covered | Cleanup commands, event-log clearing, history/log deletion, and short-lived file cues |
| Defense Evasion | T1070.006 | Timestomping | Yes | Yes | Covered | MFT $STANDARD_INFORMATION vs $FILE_NAME creation timestamp comparison detects back-dated files |
| Defense Evasion | T1036 | Masquerading | Yes | Yes | Covered | Suspicious path plus trusted/system binary naming is modeled directly |
| Credential Access | T1003 | OS Credential Dumping | Partial | Partial | Covered | Command lines, dump artefacts, follow-on collection chains, YARA `offensive_tool` category hits, and ClamAV `av_offensive_tool` category hits (Mimikatz, Rubeus, etc.) are modeled |
| Credential Access | T1555 | Credentials from Password Stores | Partial | Partial | Covered | Browser/vault artefacts and staging/exfil chains are modeled conservatively |
| Credential Access | T1110 | Brute Force | Yes | Yes | Covered | Failures, invalid-user attempts, and fail-then-success temporal logic |
| Discovery | T1083 | File and Directory Discovery | Partial | Partial | Covered | Discovery commands are modeled with bounded dampening to reduce admin noise |
| Discovery | T1018 | Remote System Discovery | Partial | Partial | Covered | Command-history and web/Windows discovery semantics are explicit in v2.31 |
| Discovery | T1033 | System Owner/User Discovery | Partial | Partial | Covered | Command-history-driven host/user discovery is modeled with noise controls |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | Yes | Yes | Covered | Windows EVTX-derived fields plus continuity/context logic |
| Lateral Movement | T1021.004 | SSH | Yes | Yes | Covered | SSH auth parsing from syslog/journal messages |
| Lateral Movement | T1021.002 | SMB/Admin Shares | Partial | Partial | Covered | Windows logon, share-access, and admin-share semantics are modeled heuristically |
| Lateral Movement | T1550 | Use Alternate Authentication Material | Partial | Partial | Covered | NTLM/newcredentials/explicit-credential signals are modeled heuristically |
| Collection | T1005 | Data from Local System | Yes | Yes | Covered | Sensitive path access, dump-like artefacts, and referenced-file propagation |
| Collection | T1074 | Data Staged | Yes | Yes | Covered | Archive and staging temporal composites are present |
| Collection | T1560.001 | Archive via Utility | Yes | Yes | Covered | Archive creation and archive-tool execution context |
| Collection | T1119 | Automated Collection | Partial | Partial | Covered | Scheduled/repeated collection with archive context is modeled conservatively |
| Command and Control | T1071 | Application Layer Protocol | Partial | Partial | Covered | URLs, HTTP artefacts, and transfer tooling are represented where artefacts preserve them |
| Command and Control | T1105 | Ingress Tool Transfer | Partial | Partial | Covered | Browser downloads, transfer tooling, and later execution correlations are explicit |
| Command and Control | T1573 | Encrypted Channel | No | No | Not realistic | Dead-box Plaso lacks session fidelity for confident encrypted-channel detection |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Partial | Partial | Covered | Transfer tooling is covered, but destination semantics remain weaker |
| Exfiltration | T1567 | Exfiltration Over Web Service | Partial | Partial | Covered | Large HTTP transfer, staging, and boundary-crossing logic help where web fields exist |
| Exfiltration | T1020 | Automated Exfiltration | Partial | Partial | Covered | Recurring transfer and staging behaviour is modeled conservatively |
| Impact | T1491.001 | Internal Defacement | Yes | Yes | Covered | Web-root file modification and creation heuristics |
| Impact | T1486 | Data Encrypted for Impact | Partial | Partial | Covered | Ransomware-style mass-modification composite plus YARA `ransomware` and ClamAV `av_ransomware` category hits feed ransomware impact detection |
| Impact | T1489 | Service Stop | Yes | Yes | Covered | Service/process termination commands and Windows Event ID 7036 stopped-state detection |
| Impact | T1490 | Inhibit System Recovery | Yes | Yes | Covered | Commands, logs, and configuration artefacts are modeled directly |
| Impact | T1531 | Account Access Removal | Yes | Yes | Covered | Account disable/delete and group-removal events are modeled |

## Remaining Depth Targets

These are no longer missing breadth items; they are the highest-value areas for improving precision and parser depth:

- parser-specific IIS, W3C, Apache, and nginx web request parsing
- richer credential-theft to archive/transfer correlation for `T1003` and `T1555`
- broader Windows EVTX coverage for share access, alternate auth, and account removal/manipulation edge cases
- stronger ransomware/impact modeling beyond the current conservative composite
- more granular discovery sub-technique mapping instead of broad discovery buckets
- post-implementation weight tuning for low-confidence signals that are currently zero- or low-weighted
- ATT&CK coverage gaps: T1546.001 (file association), T1547.009 (shortcut modification), T1529 (shutdown/reboot), T1548.002 (UAC bypass), T1550.003 (Pass the Ticket), T1564.001 (hidden files)

## Diamond Model Interpretation

For dead-box forensics using Plaso-derived data, the Diamond Model elements map approximately as follows:

- `Capability`: strongest coverage; commands, scripts, LOLBins, persistence artefacts, archives, transfer tools, web exploitation traces, and YARA-classified offensive tools/ransomware/webshells are often visible. YARA Forge category-aware scoring (see [chronosift_yara_category_mapping.md](YARA_ENRICHMENT.md)) provides high-confidence capability identification for 10,500+ known malware families and tools. ClamAV category-aware scoring (see [chronosift_clamav_category_mapping.md](CLAMAV_ENRICHMENT.md)) provides complementary malware family identification with PUA dampening across 27 category tokens and 27 known family overrides.
- `Victim`: strong coverage; local accounts, hosts, sensitive files, web roots, impacted content, and local configuration changes are well represented
- `Infrastructure`: moderate coverage; IPs, URLs, domains, GeoIP continuity, and remote service endpoints are only available when preserved by artefacts or logs
- `Adversary`: moderate-weak coverage; dead-box Plaso data supports behaviour clustering and inference. YARA `apt` category signals (181 APT-attributed rules) provide partial attribution when known APT tooling is identified, but strong attribution still requires external intelligence correlation
