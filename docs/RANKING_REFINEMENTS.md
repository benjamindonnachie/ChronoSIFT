# Ranking refinements: rules v22 / weights v20

This policy refines investigator priority, not a compromise verdict. It is
derived from v21/v19, which remain reproducible. No corpus names, challenge
accounts/IPs, hashes or benign filename allowlists enter the policy. The Python
engine and AV classification are unchanged. `build_ranking_policy.py` generates
the versioned YAML; historical files and completed sidecars are not rewritten.

## Scheduled execution — ATT&CK T1053.003

[Cron](https://attack.mitre.org/techniques/T1053/003/) is dual-use. An ordinary
`CMD (...)` wrapper is no longer sufficient evidence of interpreter invocation.
Parsed cron commands require actual interpreter syntax; the previous separate
actor-command/command-line routes remain. This is syntax evidence, not proof
that an interpreter or payload completed successfully.

| Contribution | Old | New |
| --- | ---: | ---: |
| Scheduled execution | 3 | 1 |
| Privileged scheduled execution | 7 | 2 |
| Repetition alone | 7 | 1 |
| Actual interpreter invocation | 3 | 3 |
| Qualified payload: scheduled context | included above | +2 |
| Qualified payload: privileged context | included above | +5 |
| Qualified payload: repetition | included above | +6 |

Root `run-parts` consequently falls from 13 to 3 (4 with repetition); an
ordinary root Python job is 6. Qualified root interpreter invocation preserves
31/38 for repository linkage and 39/46 for exact-file linkage. Bare binary
invocation no longer gets the incorrectly inferred interpreter contribution.
Cron-definition changes, suspicious commands, malicious payload qualification
and account-context signals retain their own weights. A low base is not an
allowlist or a claim that regular activity is benign.

Qualified invocations are computed after contextual adjustments. Extra context
is therefore projected at the final temporal phase, after repetition. The
existing invocation detector chooses exactly one best route, preferring an
exact path over repository attribution; distinct projection outputs preserve
that provenance without adding both. No new overlap or history horizon is
introduced. Exact/repository, host, expiry and native month-boundary controls
exercise this contract.

## Linux unit metadata — ATT&CK T1543.002

[Systemd services](https://attack.mitre.org/techniques/T1543/002/) can establish
persistence, but a unit timestamp observation alone does not demonstrate it.
For actual `filestat` records under the configured Linux unit-path pattern,
without independent AV/YARA/tool support, service-change contribution is 2
(was 7), and systemd contribution is 2 (was 6). Both observations remain in the
explanation. Other evidence, such as a mass-change contribution, stays additive.

This is deliberately not a global service-weight change. Windows services,
explicit systemctl management commands, supported malicious units, and other
behavioural/account evidence retain their contributions. It does not distinguish
a package installation from a malicious new unit without further evidence;
both still warrant review at a lower standalone priority.

## Weak names versus web shells — ATT&CK T1505.003

[Web shell](https://attack.mitre.org/techniques/T1505/003/) attribution now needs
an executable script mapped to a configured document root plus direct AV/YARA
web-shell category support. Existing typed HTTP/file correlation and behavioural
web detections remain separate. Strong metadata confidence requirements are not
relaxed; a weak YARA category can support a candidate but is not upgraded into
confirmed successful execution.

Names containing `upload`, `shell` and similar historical hint tokens supply
only `webshell_name_hint` (+1). That signal does not seed webshell activity or
upload/execution chains. Generic message text and a reference to some other
hit-bearing file no longer turn an ordinary script into a web shell. Strong
category support suppresses the redundant name point, not the strong evidence.
Ordinary script-creation context (+9) remains separate, so a newly created
upload-named script may score 10 without a shell verdict.

Document-root mapping uses `configure_web_roots.py` and the existing
`evidence_web_file_relative` normalisation; there are no new dataset-specific
roots. Case sensitivity, ambiguous aliases and exact-path controls remain.

## AV category promotion — diagnostic only

The raw signature `Win.Malware.Razy-10007727-0` parses to platform `Win`, category
token `Malware`, family `Razy`. The existing YAML family override `contains:
razy → ransomware` takes precedence over the generic category token. It is a
ChronoSIFT classification decision, not a raw AV assertion of ransomware.

The diagnostic records this path, original explanations, unchanged scores and
synthetic substring-collision probes. It does **not** change the override, AV
weights, impact rules or upstream enrichment, and does not infer that the actual
binary is harmless from its name. Generic malware remains important evidence.
The existing later-note rule describes filename co-occurrence, not demonstrated
encryption or note contents; [T1486](https://attack.mitre.org/techniques/T1486/)
must not be treated as proved from that observation alone. Any classification
change requires a separate decision following the diagnostic.
