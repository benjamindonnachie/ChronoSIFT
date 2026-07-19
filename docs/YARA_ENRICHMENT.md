# ChronoSift v2.31 — YARA Forge Category Mapping Reference

This document describes how ChronoSift v2.31 classifies YARA Forge rule matches into forensic categories, and how those categories interact with the signal scoring and temporal composite pipeline.

## Background

Plaso stores only the **rule name** from YARA matches — all metadata (score, quality, tags, description, detection type) is discarded at scan time. ChronoSift recovers this metadata by parsing the YARA Forge `.yar` file at engine initialisation, building an in-memory index of `rule_name → {score, quality, category}`.

The parser handles both the **extended** and **full** YARA Forge rulesets:

| Ruleset | Rules | Min Quality | Min Score | File |
|---|---|---|---|---|
| Extended | ~10,561 | 50 | 60 | `rules/yara-rules-extended_20260215.yar` |
| Full | ~11,621 | 20 | 40 | `rules/yara-rules-full_20260215.yar` |

Extended is recommended for initial full-dataset runs (lower false-positive surface). Full provides broader coverage but includes lower-quality rules (quality 20–49, score 40–59) that were excluded from extended for noise reasons. With category-aware scoring, the noise from full is mitigated by differential weighting.

## Category Taxonomy

Each matched YARA rule is classified into exactly one forensic category. Classification uses a priority hierarchy — first match wins:

1. **`tc_detection_type` metadata** (ReversingLabs rules only; ~308 rules) — explicit, highest quality
2. **Inline tags** from rule declaration (e.g., `rule NAME : RANSOMWARE FILE`)
3. **`category` metadata** field (e.g., `"INFO"` for certificate blocklists)
4. **Rule name pattern matching** — regex patterns against the rule identifier
5. **Default** → `malware`

### Category Definitions

| Category | Signal Name | Weight | Description |
|---|---|---|---|
| `offensive_tool` | `yara_offensive_tool` | 10 | Credential theft tools, post-exploitation frameworks, offensive security tooling |
| `ransomware` | `yara_ransomware` | 8 | Ransomware family binaries and components |
| `webshell` | `yara_webshell` | 9 | Web shell scripts (PHP, JSP, ASPX, Perl, Python) |
| `apt` | `yara_apt` | 9 | APT-attributed malware and implants |
| `exploit` | `yara_exploit` | 7 | Exploit payloads, shellcode, rootkits, LOLDrivers |
| `malware` | `yara_malware` | 7 | Generic malware (trojans, backdoors, infostealers, RATs, worms) |
| `certificate` | `yara_certificate_blocklist` | 0 | Revoked/leaked certificate blocklist matches (informational only) |

### Category Distribution (Extended Ruleset)

| Category | Rule Count | % of Total |
|---|---|---|
| `malware` | 6,678 | 63.2% |
| `certificate` | 1,566 | 14.8% |
| `offensive_tool` | 899 | 8.5% |
| `webshell` | 547 | 5.2% |
| `ransomware` | 463 | 4.4% |
| `exploit` | 227 | 2.2% |
| `apt` | 181 | 1.7% |

## Rule Name Classification Patterns

When metadata-based classification is unavailable, rules are classified by name patterns (case-insensitive, applied in order):

| Pattern | Category | Matches |
|---|---|---|
| `Cert_Blocklist`, `INDICATOR_KB_CERT` | `certificate` | ReversingLabs and DitekSHen certificate blocklist rules |
| `Webshell`, `web_shell` | `webshell` | All webshell detection rules across vendors |
| `Cobaltstrike`, `Mimikatz`, `Rubeus`, `HKTL_`, `Hacktool`, `INDICATOR_TOOL`, `SafetyKatz`, `SharpKatz`, `LaZagne`, `Impacket` | `offensive_tool` | Offensive security tools and frameworks |
| `Ransomware`, `Ransom_` | `ransomware` | Ransomware family detections |
| `_APT_`, `_Apt_`, `APT` + digit | `apt` | APT-attributed rules (SEKOIA, Signature Base, FireEye-RT, etc.) |
| `Exploit`, `Shellcode`, `CVE_` + digit, `CVE` + digit | `exploit` | Exploit payloads and CVE-specific rules |
| `Rootkit`, `LOLDriver` | `exploit` | Kernel-level persistence and driver abuse |

## Scoring Model

### yara_hit_strength (Refined)

The existing `yara_hit_strength` signal is recomputed with two refinements:

1. **Certificate exclusion**: Certificate blocklist matches are excluded from the hit count. A file with 3 cert hits and 0 real hits produces `yara_hit_strength = 0.0`.
2. **Score multiplier**: YARA Forge's per-rule `score` metadata (40–100) modulates strength:
   - `refined_strength = min(1.0, non_cert_count / 3.0)`
   - `yara_hit_strength = refined_strength × min(1.0, best_score / 100.0)`

| Score Range | Multiplier | Interpretation |
|---|---|---|
| 90–100 | 0.90–1.00 | Critical/high-severity detection |
| 75 (most rules) | 0.75 | Standard malware detection |
| 60–74 | 0.60–0.74 | Moderate confidence |
| 40–59 (full only) | 0.40–0.59 | Suspicious, low confidence |

### Category Signal Weights

Category signals are emitted as binary (1.0) values. Their contribution to event score is:

```
score_contribution = 1.0 × weight
```

Combined with `yara_hit_strength × 8`, the total YARA contribution for a single offensive-tool hit is:
- `yara_offensive_tool`: 1.0 × 10 = 10 points
- `yara_hit_strength`: 0.333 × 0.75 × 8 = 2.0 points
- **Total: 12 points** (of 50 max)

For a single certificate blocklist hit:
- `yara_certificate_blocklist`: 1.0 × 0 = 0 points
- `yara_hit_strength`: 0.0 × 8 = 0 points
- **Total: 0 points** (no score inflation)

## Temporal Composite Integration

Category-specific YARA signals feed into existing temporal composites:

### Ransomware Impact

`yara_ransomware` is an alternative **ransomware source signal**, alongside `mass_file_modification` and `ransomware_extension_burst`. When any of these three is present, the ransomware impact composite checks for temporal support events (defense impairment, recovery inhibition, suspicious execution, ransom note creation) within the configured window.

This means a YARA-identified ransomware binary referenced by a process execution event can trigger `ransomware_impact` even without visible mass file modification — useful when the MFT evidence is incomplete or the ransomware was stopped early.

### Credential Dump Collection

`yara_offensive_tool` is an alternative **credential source signal**, alongside `credential_dumping`. When either is present, the credential dump collection composite checks for follow-on copying, archiving, or transfer activity within the configured window.

This means a YARA-identified Mimikatz or Rubeus binary can trigger `credential_dump_collection` even without explicit dump command-line evidence.

### Webshell Activity

`yara_webshell` is not directly wired into the webshell temporal composite (which uses `webshell_artifact`), but the existing `referenced_file_yara_hit` propagation already feeds `webshell_artifact` when a YARA-hit file is in a web root with a script extension. The category signal provides independent attribution-grade evidence.

## Configuration

### Engine Configuration (rules YAML)

```yaml
engine_config:
  yara_forge_metadata_path: "rules/yara-rules-extended_20260215.yar"
```

### Python API

```python
engine = ChronoSiftEngine.from_yaml(
    rules_path="rules/rules.yaml",
    weights_path="rules/weights.yaml",
    yara_metadata_path="rules/yara-rules-extended_20260215.yar",
)
```

### Backwards Compatibility

When no metadata file is configured, the engine falls back to legacy undifferentiated scoring (`yara_hit_strength` based on total match count, no category signals). All existing pipelines continue to work without change.

## Plaso YARA Configuration

Plaso's YARA scanning is configured via its own `yara_rules.yar` path. For consistency, the same ruleset should be used for both Plaso scanning and ChronoSift metadata parsing.

When running Plaso via Docker:
```bash
docker run ... -v /path/to/rules/yara-rules-extended_20260215.yar:/yara_rules.yar:ro ...
```

## Representative Rule Examples

### Offensive Tool (weight 10)
```
Rule: BINARYALERT_Hacktool_Windows_Mimikatz_Errors
Score: 75, Quality: 80
Category: offensive_tool (name pattern: "Mimikatz")
Signal: yara_offensive_tool = 1.0
```

### Ransomware (weight 8)
```
Rule: REVERSINGLABS_Win32_Ransomware_Lockbit
Score: 75, Quality: 90
Category: ransomware (tc_detection_type: "Ransomware")
Signal: yara_ransomware = 1.0
```

### Certificate Blocklist (weight 0)
```
Rule: REVERSINGLABS_Cert_Blocklist_05E2E6A4Cd09Ea54D665B075Fe22A256
Score: 75, Quality: 90
Category: certificate (category: "INFO" + "Cert" in name)
Signal: yara_certificate_blocklist = 1.0, yara_hit_strength = 0.0
```

### Cobalt Strike (weight 10)
```
Rule: GCTI_Cobaltstrike_Resources_Template_Sct_V3_3_To_V4_X
Score: 75, Quality: 85
Category: offensive_tool (name pattern: "Cobaltstrike")
Signal: yara_offensive_tool = 1.0
```
