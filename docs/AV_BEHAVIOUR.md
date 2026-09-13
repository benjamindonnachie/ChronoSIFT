# AV-supported behavioural capability scoring

Rules v23 / weights v21 add offline VirusTotal behavioural enrichment to the
existing AV classification stage. This is a triage component in a larger
pipeline, not an assertion that every capability executed successfully on the
examined host. Scores remain capped at 50 overall and are not probabilities.

## Evidence and interpretation

An AV-positive SHA-256 provides the initial malicious/suspicious context. The
engine reads the enriched CSV's `vt_behaviour_context`, verifies its referenced
raw reports, and builds one compact profile per hash. Existing base-report
fields and summary inventories (`vt_attack_ids`, Sigma counts, vendor verdict
counts) are retained upstream but are **not numeric votes** in this policy.

The new policy uses:

- Actual ATT&CK-associated signature text, with the technique and description
  both satisfying YAML conditions. A parent technique's descriptive text alone
  is not a finding. Specific HIGH/CRITICAL findings receive the strongest band;
  a provider severity label without the qualifying behaviour does not.
- CAPA credential-acquisition capabilities at the middle band. INFO does not
  mean benign. CAPA may use static or dynamic analysis; the engine does not
  invent an analysis mode when the report does not identify one.
- Sigma matched events, initially registry `SetValue` operations with a real
  Run/RunOnce value and nonempty payload details. A rule title, severity label,
  match count or ordinary registry write alone does not qualify.
- Selected generic tags as low-strength support in the already AV-positive
  population: debugger detection, obfuscation, long sleeps and persistence.

Related signatures, multiple tactic placements, tags and Sigma rules are grouped
by capability. Only the strongest qualifying support band contributes; adding
copies or more providers does not increase the score. This combines AV with
behavioural evidence without assuming statistical independence. One hash may
have distinct credential-access and evasion capabilities, subject to the cap.

VT's merged summary can omit the originating analysis name/date, and sandbox
behaviour may include child processes. Lookup time is not local execution time.
See the official [behaviour schema](https://docs.virustotal.com/reference/file-behaviour-summary),
[merged summary](https://docs.virustotal.com/reference/file-all-behaviours-summary),
[ATT&CK report endpoint](https://docs.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file)
and [CAPA](https://github.com/mandiant/capa).

## YAML policy and score accounting

All admission patterns, support bands, mappings and strengths are under
`detector_policy.detectors.clamav_classification.behaviour` in v23; corresponding
weights are in v21. Python handles transport parsing, validation and aggregation.
No evidence hash, challenge filename, user, address or vendor family selects a
new capability.

| Capability | Maximum added points | ATT&CK rationale |
|---|---:|---|
| Credential access | 8 | [Browser credentials T1555.003](https://attack.mitre.org/techniques/T1555/003/), [Credential Manager T1555.004](https://attack.mitre.org/techniques/T1555/004/), reported T1003-family findings |
| Persistence | 5 | [Registry Run Keys / Startup Folder T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| Evasion | 3 | [Debugger evasion T1622](https://attack.mitre.org/techniques/T1622/), [time-based checks T1497.003](https://attack.mitre.org/techniques/T1497/003/), T1497.001 and T1027-family findings |
| Destructive/encryption | 10 | [Data Encrypted for Impact T1486](https://attack.mitre.org/techniques/T1486/), [Disk Wipe T1561](https://attack.mitre.org/techniques/T1561/) |
| Exfiltration | 7 | [Exfiltration Over C2 Channel T1041](https://attack.mitre.org/techniques/T1041/), [Alternative Protocol T1048](https://attack.mitre.org/techniques/T1048/) |
| Web shell | 8 | [Web Shell T1505.003](https://attack.mitre.org/techniques/T1505/003/) |

High, medium and low capability support multiply those points by 1, 0.75 and
0.5 respectively. All new behavioural contributions on an event share a
**14-point cap**. When necessary, proportional scaling preserves the relative
contributions and makes explanation arithmetic sum exactly. This cap is a
conservative configurable policy choice, not an empirically calibrated error
rate. Existing generic/category AV scoring is unchanged, apart from removing
the unsupported `razy` family-substring override to ransomware in v23. A generic
Razy detection remains malware; credential evidence can then add the appropriate
capability without inferring encryption from its family name.

Each `AV_BEHAVIOUR_*` explanation records the selected hash, capability,
capability confidence, identity confidence, match scope, unscaled strength,
cap multiplier, actual admitted ATT&CK IDs and source digests. Up to six
representative findings per capability retain report paths and JSON pointers;
strongest-band support is prioritised. This is bounded representative provenance,
not an exhaustive list of correlated reports. Equal-strength alternatives retain
the first representative; their count does not affect the result. The capability
definition's broad ATT&CK reference list is not emitted wholesale. A generic
persistence tag has no automatic technique-specific label.

## Local context and identity

Direct matched file hashes and exact upload hashes use full capability strength.
Existing qualified path/reference matches use a further 0.75 multiplier; their
explanation confidence is at most medium. Capability confidence and confidence
that this event refers to that file are distinct. A path match may associate a
historically observed file, not prove the identical file version existed at that
moment. Exact upload hash takes precedence over a conflicting name.

The manifest carries profiles only for AV-supported hashes actually encountered
in the dataset. It stores hash references under the existing admitted identity
maps. POSIX case remains significant, Windows paths retain their established
case folding, web-root collision checks remain effective, and a relative
executable basename alone does not invent an exact-hash behavioural profile.

Existing Windows/Linux execution, privileged-account, schedule and web rules
continue to assess local evidence. Capabilities can reinforce qualified local
references without introducing a second execution vote or demanding successful
payload effects. They are explicitly ineligible as temporal seed signals, so
retrospective external metadata does not manufacture earlier local activity.
Persistent integer row IDs, including rows with identical timestamps, remain
the enrichment and sidecar alignment keys.

## Loading, failure behaviour and memory

The scoring path makes no network requests. Keep the enriched CSV and its
relative raw-report directory together as one immutable snapshot. It validates
schema, duplicate-hash consistency, matching SHA-256 identities, report digests,
relative-path containment and available/null response shapes. Invalid supplied
enrichment raises an error; it is not silently treated as absent. Explicit
unavailable/error endpoint statuses do not mean benign and contribute no new
capability. No summary leaves ordinary AV scoring intact.

By default `require_enriched_csv: false` allows a legacy AV CSV or no AV CSV;
ordinary AV-only operation remains supported. Set it to `true` when the pipeline
must fail if behavioural enrichment is missing. `enabled: false` disables the
new component; disabling the outer ClamAV classifier disables it as well.

The catalog cache is keyed by CSV **content** SHA-256, policy digest and parser
version, bounded to four snapshots. Raw reports are verified at initial load,
not reread for every event/month; do not mutate them in place during a run.
Large `vt_*` transport columns are projected out of dataframe joins, including
when running a legacy policy. Ordinary AV/Luhn fields retain their existing
semantics. Sparse event explanations contain bounded summaries; there is no new
defensive dataframe copy or per-event raw-report parse. File-hit manifest schema
9 / source fingerprint 6 invalidate incompatible saved manifests.

## Running and validating

The v23/v21 pair introduced the policy described here; see
[rules and weights](../rules/README.md) for the current CLI defaults. To reproduce
this explicitly versioned policy, use the runner with a fresh output directory:

```sh
python run_chronosift_sidecar_cli.py "$DATASET_ROOT" "$NEW_OUTPUT_ROOT/sidecar" \
  --rules-yaml rules/rules_evidence_calibrated_v23.yaml \
  --weights-yaml rules/weights_evidence_calibrated_v21.yaml \
  --av-csv-path "$ENRICHED_AV_CSV" \
  --yara-metadata-path "$EXACT_EXTRACTION_YARA_CORPUS" \
  --output-mode sidecar
```

These are placeholders, not a production launch. Keep the other extraction
resources and explicit web-root configuration appropriate to the dataset.
Main checkout, pipeline configuration and historical sidecars are not changed
by this isolated implementation. Supply v22/v20 explicitly for legacy scoring.

`benchmarks/build_av_behaviour_policy.py` without arguments verifies generated
YAML without rewriting it. New focused/native tests cover missing and malformed
metadata, duplicate findings, exact hashes, case/alias controls, cap reinjection,
explanation accounting, disabled policies, duplicate timestamps/row IDs, cache
round trips and compact/eager month-boundary parity. The bounded retained-AV
comparison reports only AV-component changes, not full-event scores or a new
full-corpus ground-truth assessment. Small projected-join diagnostics are not
full-run performance estimates; Pandas deep memory can double-count shared
strings and must not be described as actual RSS savings.
