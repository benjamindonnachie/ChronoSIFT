# ChronoSift v2.31 — ClamAV Category Mapping Reference

This document describes how ChronoSift v2.31 classifies ClamAV antivirus detections into forensic categories, and how those categories interact with the signal scoring and temporal composite pipeline.

## Background

Plaso stores ClamAV detection results as an `av_signature` string (the full ClamAV signature name) and an `av_hit` boolean. Previously, ChronoSift treated all AV hits identically — emitting a single `av_hit` signal at weight 8 regardless of what was detected. This meant a PUA toolbar detection scored the same as a Mimikatz or ransomware detection.

ClamAV uses a structured naming convention that embeds platform, malware category, and family name directly in the signature string:

```
{Platform}.{Category}.{FamilyName}-{SignatureID}-{Revision}
```

ChronoSift now parses this structure at scoring time to emit category-specific signals with differential weights.

## Naming Convention

### Standard Form

```
Win.Trojan.Agent-12345-0
│    │       │      │    │
│    │       │      │    └─ Revision
│    │       │      └────── Signature ID
│    │       └───────────── Family name
│    └───────────────────── Category token
└────────────────────────── Platform
```

### PUA Prefix Form

```
PUA.Win.Toolbar-55555-0
│    │    │       │    │
│    │    │       │    └─ Revision
│    │    │       └────── Signature ID
│    │    └──────────────── Family name
│    └───────────────────── Platform (shifted)
└────────────────────────── PUA category prefix
```

### Deviations

Some ClamAV signatures deviate from the standard form:
- Two-part names: `Win.Generic-999-0`
- No ID/revision suffix: `Win.Trojan.Agent`
- Multi-dot families: `Win.Trojan.Sub.Family-1-0`
- Bare names: `FooBar-42-1`

The parser handles all of these gracefully, defaulting to `malware` when classification is ambiguous.

## Classification Hierarchy

Each ClamAV signature is classified using a two-level priority system — first match wins:

### 1. Family Name Overrides (Highest Priority)

Known tool and malware family names override category-based classification. This handles cases where ClamAV categorises a tool generically (e.g., `Win.Trojan.Mimikatz`) but the family name reveals its true forensic significance.

| Family Pattern | Forensic Category | Notable Tools |
|---|---|---|
| `mimikatz` | `offensive_tool` | Credential dumping |
| `pwdump` | `offensive_tool` | SAM/NTDS extraction |
| `lazagne` | `offensive_tool` | Multi-target credential theft |
| `rubeus` | `offensive_tool` | Kerberos abuse |
| `impacket` | `offensive_tool` | Network protocol exploitation |
| `cobaltstrike` | `offensive_tool` | C2 framework |
| `metasploit` | `offensive_tool` | Exploitation framework |
| `meterpreter` | `offensive_tool` | Post-exploitation agent |
| `sharphound` | `offensive_tool` | AD enumeration |
| `bloodhound` | `offensive_tool` | AD attack path analysis |
| `c99shell`, `c99` | `webshell` | PHP webshell |
| `r57shell` | `webshell` | PHP webshell |
| `b374k` | `webshell` | PHP webshell |
| `weevely` | `webshell` | PHP backdoor/webshell |
| `wso` | `webshell` | PHP webshell |
| `petya` | `ransomware` | Destructive ransomware |
| `wannacry` | `ransomware` | Self-propagating ransomware |
| `lockbit` | `ransomware` | RaaS family |
| `conti` | `ransomware` | RaaS family |
| `revil` | `ransomware` | RaaS family |
| `ryuk` | `ransomware` | Targeted ransomware |
| `maze` | `ransomware` | Double-extortion ransomware |
| `blackcat`, `alphv` | `ransomware` | Rust-based RaaS |
| `babuk` | `ransomware` | Cross-platform ransomware |
| `akira` | `ransomware` | RaaS family |
| `razy` | `ransomware` | Ransomware family |

### 2. Category Token Mapping

When no family override matches, the ClamAV category token (second dot-separated segment) is mapped:

| ClamAV Token(s) | Forensic Category | Signal |
|---|---|---|
| `Ransomware` | `ransomware` | `av_ransomware` |
| `Trojan`, `Backdoor`, `Virus`, `Worm`, `Malware`, `Dropper`, `Downloader`, `Loader`, `Infostealer`, `Spyware`, `Keylogger`, `Ircbot`, `Proxy`, `Phishing`, `Packed`, `Packer`, `File` | `malware` | `av_malware` |
| `Rootkit`, `Exploit` | `exploit` | `av_exploit` |
| `Tool`, `Hacktool`, `Countermeasure` | `offensive_tool` | `av_offensive_tool` |
| `Pua`, `Adware`, `Coinminer`, `Joke` | `pua` | `av_pua` |
| *(unknown token)* | `malware` | `av_malware` |

## Scoring Model

### Category Signal Weights

| Category | Signal | Weight | Rationale |
|---|---|---|---|
| `offensive_tool` | `av_offensive_tool` | 10 | Confirms post-exploitation tooling — highest forensic relevance |
| `ransomware` | `av_ransomware` | 9 | Confirms ransomware presence — direct impact indicator |
| `webshell` | `av_webshell` | 9 | Confirms webshell — directly actionable |
| `exploit` | `av_exploit` | 8 | Confirms exploit/rootkit payload |
| `malware` | `av_malware` | 8 | Generic malware — confirmed threat but less specific |
| `pua` | `av_pua` | 2 | Low forensic relevance — adware, coinminers, joke programs |

### PUA Dampening

When a detection is classified as PUA:
- `av_hit` is **suppressed** (not emitted) — prevents the weight-8 `av_hit` from inflating scores
- `av_pua` is emitted at weight 2 — preserves the detection in the timeline without disproportionate scoring

For non-PUA detections:
- `av_hit` is emitted normally (weight 8)
- The category-specific signal is emitted additionally

### Score Examples

**Mimikatz detection** (`Win.Hacktool.Mimikatz-12345-0`):
- `av_hit`: 1.0 × 8 = 8 points
- `av_offensive_tool`: 1.0 × 10 = 10 points
- **Total: 18 points** (of 50 max)

**Adware detection** (`Win.Adware.Toolbar-55555-0`):
- `av_hit`: suppressed = 0 points
- `av_pua`: 1.0 × 2 = 2 points
- **Total: 2 points**

**Generic trojan** (`Win.Trojan.Agent-12345-0`):
- `av_hit`: 1.0 × 8 = 8 points
- `av_malware`: 1.0 × 8 = 8 points
- **Total: 16 points**

## Temporal Composite Integration

### Ransomware Impact

`av_ransomware` is a ransomware source signal, alongside `mass_file_modification`, `ransomware_extension_burst`, `yara_ransomware`. When any of these is present, the ransomware impact composite checks for temporal support events (defense impairment, recovery inhibition, suspicious execution, ransom note creation).

This means a ClamAV-identified ransomware binary can trigger `ransomware_impact` even without visible mass file modification.

### Credential Dump Collection

`av_offensive_tool` is a credential source signal, alongside `credential_dumping`, `yara_offensive_tool`. When any of these is present, the credential dump collection composite checks for follow-on copying, archiving, or transfer activity.

This means a ClamAV-identified Mimikatz or Rubeus binary can trigger `credential_dump_collection` even without explicit dump command-line evidence.

## Backwards Compatibility

When `av_signature` is null or empty, no category signal is emitted. The existing `av_hit` signal continues to work from the boolean `av_hit` column. All existing pipelines remain functional.

## Comparison with YARA Forge Category-Aware Scoring

| Aspect | YARA Forge | ClamAV |
|---|---|---|
| Metadata source | External `.yar` file parsed at init | Signature name itself (self-contained) |
| Classification inputs | tc_detection_type, inline tags, category metadata, rule name | Family name overrides, category token |
| Category count | 7 (includes `apt`, `certificate`) | 6 (no `apt` or `certificate`) |
| Rule coverage | ~10,561 (extended) | Unlimited (any ClamAV signature) |
| Certificate handling | Explicit dampening (weight 0) | N/A (ClamAV doesn't scan certs) |
| PUA handling | N/A | Explicit dampening (suppress `av_hit`, emit `av_pua`) |
| External file needed | Yes (`yara-rules-extended_20260215.yar`) | No (parsing is self-contained) |

Both systems feed into the same temporal composites (ransomware impact, credential dump collection) and contribute to the same forensic narrative.
