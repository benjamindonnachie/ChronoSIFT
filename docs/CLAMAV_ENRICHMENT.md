# ChronoSIFT v2.31 — ClamAV classification policy

The shipped ChronoSIFT policy classifies ClamAV detections into six forensic
categories before scoring and temporal correlation. The category registry and
classification judgement are
authoritative in
[`detector_policy.detectors.clamav_classification`](../rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml),
not in Python lookup tables.

## Policy boundary

The shipped detector uses the `clamav_classifier` executor at atomic phase 5.
Its outputs are available to later atomic signal gates, which run at phase 10.

YAML owns:

- enablement and the default forensic category;
- the category-token mapping;
- ordered family-substring overrides;
- the ordered category registry and generic/category-specific signal names,
  values, rule IDs, descriptions, confidence, evidence, and
  generic-suppression behaviour.

Python retains only the reusable mechanics: interpreting `av_hit`, parsing the
signature grammar including configured leading category tokens, applying the configured mappings in order, formatting
configured explanations, and merging sparse emissions. The raw input fields
remain fixed executor mechanics: `av_hit`, `av_signature`, and `filename`.

The complete classifier definition is mandatory even when `enabled: false`.
Unknown keys, an empty registry, dangling category references, invalid evidence
names, duplicate normalised tokens or override substrings, output collisions,
missing weights, and invalid policy dependencies fail engine construction.

## Signature grammar

The usual ClamAV form is:

```text
{Platform}.{Category}.{FamilyName}-{SignatureID}-{Revision}
```

For example, `Win.Trojan.Agent-12345-0` yields platform `Win`, category token
`Trojan`, and family `Agent`. The parser also handles configured
category-token-prefixed names,
two-part names, missing ID/revision suffixes, multi-dot families, and bare
names. Grammar handling is deliberately lenient; classification is still
decided by the configured policy.

## Classification order

For every non-empty signature with `av_hit` true, the executor applies:

1. `family_overrides` in YAML list order, using lowercase substring matching;
2. `category_tokens` using the lowercase parsed category token; then
3. `default_category` when neither configured lookup matches.

Order matters. The shipped policy places `c99shell` before `c99`, for example.
It contains 27 category-token keys and 28 ordered family-substring patterns.
The shipped registry contains `offensive_tool`, `ransomware`, `exploit`,
`malware`, `pua`, and `webshell`. Mapping order is authoritative, and a policy
can add, remove, or reorder categories after updating all category references
and downstream signal dependencies.

The baseline family overrides cover common offensive tools such as Mimikatz,
Rubeus, Impacket, Cobalt Strike, Metasploit, Meterpreter, SharpHound and
BloodHound; web shells including C99/C99shell, R57shell, B374k, Weevely and
WSO; and ransomware families including Petya, WannaCry, LockBit, Conti,
REvil, Ryuk, Maze, BlackCat/ALPHV, Babuk, Akira and Razy. The shipped YAML is
the definitive list.

## Shipped emissions and weights

Signal names are configurable. The baseline uses:

| Category | Configured signal | Weight | Generic `av_hit` suppressed? |
|---|---|---:|---|
| `offensive_tool` | `av_offensive_tool` | 10 | no |
| `ransomware` | `av_ransomware` | 9 | no |
| `webshell` | `av_webshell` | 9 | no |
| `exploit` | `av_exploit` | 8 | no |
| `malware` | `av_malware` | 8 | no |
| `pua` | `av_pua` | 2 | yes |

The configured generic signal is `av_hit` at weight 8. A non-PUA classified
hit therefore emits both the generic signal and its category signal. The
shipped PUA policy emits only `av_pua`, preventing a low-relevance toolbar,
adware, coinminer, or joke-program hit from inheriting the generic weight.
Changing an emission name also requires a corresponding weight entry.

Each emission has its own configured rule ID, description, confidence, and
evidence list. Non-PUA hits consequently receive separate generic and category
explanations rather than one explanation standing in for two producers.

## Empty, unknown, and disabled behaviour

- `av_hit: false` emits nothing, regardless of signature text.
- A true hit with a null or empty signature emits only the configured generic
  signal using `generic.unclassified_description`.
- A true hit with an unknown non-empty signature uses `default_category` and
  follows the configured generic/category suppression rules.
- `enabled: false` suppresses every direct classifier output, including the
  configured generic signal. The full definition remains required.

Disabling classification does not erase source evidence. Raw AV hit and
signature values can still be retained in referenced-file identities, and the
independently configured `referenced_file_correlation` detector may still
propagate AV evidence when its `av` branch is present. Derived AV categories
and families are omitted, so classifier-driven
ransomware, offensive-tool, and confirmed-webshell paths receive no category
support.

## Downstream integration

Downstream candidate selection and the legacy ransomware-impact and
credential-dump composites resolve the configured category emission names from
the detector registry. Renaming `av_ransomware` or `av_offensive_tool` in YAML
therefore updates those consumers without a Python edit. Disabling the
classifier removes those category outputs from the effective candidate and
composite inputs.

An enabled policy consumer may use a classifier output because phase 5
precedes atomic gates at phase 10. A consumer whose only path depends on a
disabled policy producer is rejected. `any` gates and sequence sides may still
retain a disabled optional input when another live input path remains; an
`all` gate may not.

## Referenced-file manifest

Referenced-file manifest schema v7 preserves raw AV signatures plus derived
families and categories through filesystem paths, web aliases, and SHA-256
identity maps. Dataset-resident and external-CSV signatures are accumulated
independently under their own hit masks, so two valid signatures are unioned
and an `av_hit: false` CSV row cannot replace a dataset hit's signature.
SHA-256 tags and identities are accumulated at exact-hash scope rather than
reconstructed from an aggregated filename, so different file versions that
reuse a path cannot exchange AV, Luhn, or YARA evidence.

Schema v7 records four digests:

- `clamav_policy_digest`: SHA-256 of the complete raw classifier block;
- `yara_policy_digest`: SHA-256 of the complete YARA classifier block;
- `correlation_policy_digest`: SHA-256 of the complete referenced-file
  correlation block; and
- `source_digest`: a fingerprint of Parquet membership/file metadata, AV and
  Luhn CSV paths and contents, referenced-file configuration, and the YARA
  metadata source path/bytes plus its effective parsed index.

Partitioned processing rebuilds a loaded or caller-supplied manifest when the
schema is not exactly v7 or any expected digest differs. Direct in-memory
contextual calls reject a manifest whose schema or any policy digest is
incompatible, because they do not have the dataset inputs needed to rebuild or
verify its source fingerprint.

## Relationship to YARA

YARA and ClamAV remain separate evidence producers. The shipped YARA policy
uses external rule metadata and seven categories; the shipped ClamAV policy
uses the signature grammar and six categories. Their configured category
signals can support the same later behavioural composites, but neither source
is treated as a verdict on its own.
