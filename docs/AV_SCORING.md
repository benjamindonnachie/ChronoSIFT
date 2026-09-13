# Antivirus presence weighting

Rules v19 with weights v17 increase the priority of already-classified malicious
AV findings. This is a weights-only change: matching, classification, evidence
requirements, temporal windows and the Python engine are unchanged.

| Existing AV classification | v16 AV contribution | v17 AV contribution |
|---|---:|---:|
| Malware, including the Honeynet archive's generic Agent signature | 8 + 8 = 16 | 8 + 24 = 32 |
| Exploit or rootkit | 8 + 8 = 16 | 8 + 24 = 32 |
| Ransomware | 8 + 9 = 17 | 8 + 25 = 33 |
| Web shell | 8 + 9 = 17 | 8 + 25 = 33 |
| Offensive/dual-use tool | 8 + 10 = 18 | unchanged |
| Potentially unwanted application | 2; generic hit suppressed | unchanged |
| Hit without a classified signature | 8 | unchanged |

The category weight is additive to the existing generic hit weight. This is an
explicit severity decomposition of **one AV finding**, not a claim of two
independent detections. Other genuinely observed evidence can contribute further,
subject to the existing event-score cap of 50. Scores are stage-level weights,
not probabilities or confidence percentages.

A malware-bearing file should rank distinctly above routine privileged cron
activity even when execution evidence is unavailable. The classifier still owns
whether a signature is malware, a dual-use tool or PUA; this change does not
promote every signature name, copy future evidence backwards or infer successful
payload effects. Actual matched file hashes and existing explanation provenance
remain authoritative. A filename such as `rk.tar` alone receives no new points.

Honeynet 7's `Unix.Malware.Agent-6835737-0` finding is classified as generic Unix
malware and therefore receives the 32-point AV contribution. The external
ground-truth narrative calls the archive a rootkit, but this weighting does not
claim that the generic signature identifies a specific rootkit family.

For ATT&CK interpretation, rootkit concealment relates to
[T1014 Rootkit](https://attack.mitre.org/techniques/T1014/), and a web shell to
[T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/). Presence or
an AV classification alone does **not** establish those behaviours, persistence,
execution or successful ransomware impact. Generic malware is not automatically
assigned a behaviour-level technique by this change. No new ATT&CK labels or
engine detectors are introduced.

AV weighting was introduced with v19/v17 and is retained by later policies.
V19/v16 remains reproducible by supplying both
`--rules-yaml rules/rules_evidence_calibrated_v19.yaml` and
`--weights-yaml rules/weights_evidence_calibrated_v16.yaml`. Existing frozen runs
continue with their recorded YAML and retain their original sidecars. No main
checkout, published repository or production-pipeline adoption is implied.
