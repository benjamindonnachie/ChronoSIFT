# ChronoSIFT v2.31 YARA classification

ChronoSIFT consumes YARA matches already present in a Plaso timeline. It does
not scan evidence itself. Plaso normally retains the matched rule name but not
the rule's score, quality, tags, category, or detection type, so ChronoSIFT can
parse the same YARA Forge corpus to recover that metadata.

The mandatory
[`detector_policy.detectors.yara_classification`](../rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml)
definition is authoritative. YAML owns enablement, metadata-resource handling,
ordered classification, the ordered category registry, strength calculation,
category emissions, confidence,
evidence, and referenced-file qualification. Python retains only YARA syntax
parsing, fixed `yara_match` access, typed predicate evaluation, sparse emission,
and manifest-index mechanics.

## Validated corpus

The surrounding Snakemake pipeline currently pins
`yara-rules-extended_20260719.yar`, SHA-256
`b3a09382f3e5a6c73f6b697bf5c61179640876ae85b05c41a2be14bdcb6788bd`.
The corpus is independently licensed and is not redistributed in this
repository. Parsing it with the shipped policy produces 10,735 indexed rules:

| Category | Rules |
|---|---:|
| `malware` | 5,985 |
| `certificate` | 1,566 |
| `apt` | 1,027 |
| `offensive_tool` | 921 |
| `webshell` | 550 |
| `ransomware` | 465 |
| `exploit` | 221 |

Source score values span 50–100. The corpus contains out-of-range negative
quality metadata; the parser deliberately bounds both score and quality to
0–100, producing effective quality values from 0–90 for this corpus. These
counts and ranges describe the pinned July 2026 input, not every possible YARA
Forge release.

## Metadata policy

The policy declares a repository-relative default resource path. A run can
replace it with `--yara-metadata-path`, which is useful because the corpus is
normally managed by the surrounding pipeline.

```yaml
yara_classification:
  stage: atomic
  executor: yara_classifier
  enabled: true
  metadata:
    path: rules/yara-forge-rules-extended.yar
    on_missing: name_only
    on_parse_error: name_only
    defaults: {score: 75, quality: 70}
    unindexed_rule:
      classification: name_only
      score: 0
      quality: 0
```

`defaults` applies when an indexed rule omits or has an unparsable score or
quality value. If the corpus is unavailable or unreadable, names can still be
classified, but their configured unindexed score and quality are both zero.
This preserves category visibility without silently treating unverified names
as score/quality-qualified referenced-file evidence.

Metadata loading is lazy. A dataset with no YARA candidates does not pay the
cost of parsing the external corpus. Setting `enabled: false` suppresses the
derived strength and category signals and avoids loading the corpus. Raw YARA
matches remain available to the independently configured
`referenced_file_correlation` detector, but disabled or non-qualifying YARA
cannot enter web-path or upload-hash indexes under the configured YARA gate.

## Ordered classification

Each named match resolves to exactly one configured semantic category ID. The
shipped registry contains seven; policies may add, remove, or reorder entries
after updating classification, gate, and downstream signal references. The
configured `classification.mode` is `first_match`; all conditions within an
ordered rule must pass. Predicates are case-insensitive and missing values do
not satisfy either positive or negative conditions.

The shipped order preserves this hierarchy:

1. explicit `tc_detection_type` values classify ransomware, malware families,
   and exploit/rootkit rules;
2. ransomware tags classify as `ransomware`;
3. informational tags or category metadata combined with a certificate-like
   name classify as `certificate`;
4. ordered rule-name regexes identify certificate blocklists, web shells,
   offensive tools, ransomware, APT names, and exploit/rootkit names; and
5. unmatched rules use the configured `malware` default.

Supported condition fields are `rule_name`, combined inline/metadata `tags`,
metadata `category`, and `tc_detection_type`. Version 1 supports
`equals_any`, `contains_any`, `contains_none`, and `regex`. Classification
order and regex text are therefore reviewable and mutable without editing
Python.

## Strength and category signals

Named matches are de-duplicated case-insensitively before scoring. With the
shipped policy, certificate matches emit their informational category signal
but do not contribute to strength. For the remaining distinct rules:

```text
base_strength = min(1, contributing_rule_count / 3)
score_multiplier = clamp(max(contributing_scores) / 100, 0.6, 1.0)
yara_hit_strength = base_strength * score_multiplier
```

If `yara_match_count` is positive but no names can be recovered, the configured
fallback is `min(1, raw_count / 3) * 0.6`. All numeric constants and evidence
fields in these formulas come from the policy. Version 1 exposes the fixed
executor markers `distinct_rule_names`, `maximum`, and `raw_count` so the
mechanics are explicit and startup-validated rather than alternative modes.

| Category | Default signal | Weight | Strength contributor |
|---|---|---:|---|
| `offensive_tool` | `yara_offensive_tool` | 10 | yes |
| `ransomware` | `yara_ransomware` | 8 | yes |
| `webshell` | `yara_webshell` | 9 | yes |
| `apt` | `yara_apt` | 9 | yes |
| `exploit` | `yara_exploit` | 7 | yes |
| `malware` | `yara_malware` | 7 | yes |
| `certificate` | `yara_certificate_blocklist` | 0 | no |

The weights remain in the weights YAML; the output names, values, rule IDs,
descriptions, baseline confidence, score-based confidence promotion, evidence
fields, and evidence caps live in the detector definition. Category confidence
is evaluated from the best score within that category, rather than from an
unrelated rule in the same event.

Temporal candidate selection and the remaining ransomware-impact and
credential-collection composites resolve the configured emissions for the
`ransomware` and `offensive_tool` semantic IDs. Renaming those outputs in the
policy therefore updates their downstream use without a Python edit.

## Referenced-file qualification

The YARA definition also owns the gate used for web-path and upload-hash
correlation:

```yaml
referenced_file_gate:
  minimum_score: 75
  minimum_quality: 70
  categories:
  - offensive_tool
  - ransomware
  - webshell
  - apt
  - exploit
  - malware
  allow_unnamed: false
```

The pinned corpus contains 7,698 rules that satisfy this gate. Certificate,
weak, unindexed, and unnamed matches do not qualify. Raw direct hit maps retain
the original evidence, while canonical web aliases and SHA-256 upload indexes
contain YARA only for qualified evidence. URL aliases use qualified paths;
upload correlation uses the exact qualified SHA-256 and its hash-specific YARA
identity. A strong version of a reused path therefore cannot qualify a weak or
certificate-only version's upload hash.

Referenced-file manifest schema v7 records the ClamAV, YARA, and correlation
policy digests plus a source digest that fingerprints dataset membership/file
metadata, enrichment inputs, referenced-file settings, the YARA metadata file
bytes, and the effective parsed metadata index. A changed policy, corpus,
supplied index, or source input forces a rebuild, and an incompatible in-memory
manifest is rejected.

## Running with a corpus

Use the same corpus for upstream scanning and ChronoSIFT metadata recovery.
For example:

```bash
uv run python run_chronosift_sidecar_cli.py INPUT OUTPUT \
  --rules-yaml rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml \
  --weights-yaml rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml \
  --yara-metadata-path /path/to/yara-rules-extended_20260719.yar
```

For reproducible research, retain the corpus filename and digest, rules and
weights YAML, manifest, engine revision, and upstream Plaso/YARA configuration
with the run outputs.
