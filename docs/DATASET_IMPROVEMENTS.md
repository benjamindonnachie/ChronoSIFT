# Windows and web-server evidence linkage

Implementation candidate: rules v14 / weights v13. The preceding policy pairs
and completed outputs are preserved. This is an intermediate event-scoring
stage, not a complete incident reconstruction. Full-corpus validation is pending.
The follow-on [rules v15 / weights v14](ACCOUNT_REMOVAL_SCORING.md) adds explicit
base-plus-privilege account-removal scoring and fixes overlapping base
explanations without changing the engine or other detection policy.
The later [rules v16 / weights v15](CONTEXT_PROVENANCE.md) corrects continuity
carry/reference handling and adds bounded creator risk and qualified tool
novelty while excluding container-only sensitive-path contributions.

## Corrections and additional evidence

| Area | Implemented behaviour | Evidence boundary |
| --- | --- | --- |
| YARA metadata | Fail on absent/non-numeric per-rule score or quality, duplicate rule names, unknown matched names and unnamed positive matches. Applies to direct scoring and referenced-file qualification. | Existing historical policies retain their explicitly configured defaults. Actual signed Forge values remain available metadata and use the existing 0–100 bounds; negative quality is not replaced by 70. |
| URI semantics | Admit HTTP/HTTPS resource URLs and actual HTTP request targets; reject standalone local-file/FTP/SMB URLs from HTTP classification and web-reference propagation. | `file://` inside a genuine HTTP query remains potential inclusion syntax. URL history is not a measured network transfer. |
| Execution paths | Prefer structured program paths, decoded UserAssist program names and PowerShell XML HostApplication commands. Do not classify NTUSER.DAT/WebCache locations as executable locations. | A registry/file container is not the executable or its hash. UserAssist/use evidence does not prove successful payload effects. |
| Windows identity | Domain-qualified task principal lookup; unknown domains do not fall back to a same-spelled account in another domain. | Profile-owner aliases remain weaker than direct subject SIDs. Resolution uses available frame history, not an invented global identity service. |
| Malware-linked use | Qualified AV/YARA artefact then program use, linked by a unique observed full-path/hash candidate; explicit executed hashes are stronger. | Ambiguous observed versions revoke path aliases. Stripping device/drive prefixes is not validated volume mapping or proof the file was unchanged at execution. No basename joins. |
| GPO | Recognise directory change events and 4662 create/delete/write-capable operation masks associated with policy objects. | Access mask 0x1 means Create Child, not Read Property. An attempted change is useful evidence without proving the setting or completion. |
| Shell requests | The temporal artefact/request association uses an unambiguous full web-file identity, not global proximity. Configured Windows roots permit case-insensitive aliases; Linux paths remain case-sensitive. | Below-gate YARA does not acquire fabricated metadata or a confirmed-shell label. The actual request is not proof of command execution. |
| Sensitive download | Add four points for same-file recent creation and four for preceding hostile-client requests, with separate witnesses. | No score is copied from another event. Luhn, recent creation and client behaviour are different evidence dimensions. Novel IP/country context remains bounded and country-neutral. |
| Database impact | Score explicit database-storage deletion and destructive commands in execution/history records. | Ordinary MariaDB modifications/recreation do not prove destroyed contents. Absent SQL logs cannot be reconstructed from table-directory timestamps. |
| Content replacement | Retain modification evidence and add bounded same-asset context after a file-linked suspicious request. | No claim of image content, visual defacement or actor identity from filenames/timing. |

## Numerical ownership

Malware path candidates contribute at most 26 points; explicit hash-linked use
contributes at most 42. A single maximum-strength projection owns these points,
so AV and YARA, or path and hash routes, cannot stack the same malware dimension.
The underlying zero-weight qualifiers and their supporting rows remain visible.
Other independent program-use/account/context features may add points before
the normal cap of 50. FTP attempts retain the preceding policy's strong score
without requiring upstream confirmation or successful completion.

## Generic implementation contract

Normalisation supports optional `stage: post_web` after HTTP materialisation,
case-sensitive identity lookups, complete `join_fields` identities,
`bitmask_any`, path-separator conversion and canonical URL paths. These are
generic field mechanics; YAML owns paths, source predicates, masks, thresholds,
lookbacks, weights and descriptions. Missing join components and ambiguous
aliases fail closed. All joins/output retain the persistent integer row IDs;
tied timestamps remain separate. No defensive whole-dataframe copies are added.

The selected policy still requires automatic **174-hour** overlap. New aliases
are frame-local; a full replay must assess their loaded-history boundaries,
performance and resource cost. Full Windows and Ubuntu validation runs must
use frozen source/configuration, the actual extraction YARA corpus and normal
AV/Luhn/GeoIP/NSRL/profiling settings, writing fresh dated sidecars. Bounded
development windows are neither independent hold-outs nor a full confusion matrix.

## ATT&CK and source rationale

- [Web Shell, T1505.003](https://attack.mitre.org/techniques/T1505/003/):
  distinguish deployed file, access and executed commands.
- [PowerShell, T1059.001](https://attack.mitre.org/techniques/T1059/001/):
  retain explicit host command/program evidence without treating an arbitrary
  event's mention of PowerShell or CMD as execution.
- [Group Policy Modification, T1484.001](https://attack.mitre.org/techniques/T1484/001/)
  and [Microsoft event 4662 access-mask definitions](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662):
  distinguish change-capable operations from property reads.
- [Data Destruction, T1485](https://attack.mitre.org/techniques/T1485/):
  destructive-command/deletion evidence does not follow from ordinary writes.
- [Defacement, T1491](https://attack.mitre.org/techniques/T1491/):
  content changes and visual/semantic impact are separate observations.
- [Local Data Staging, T1074.001](https://attack.mitre.org/techniques/T1074/001/)
  and [Credentials in Files, T1552.001](https://attack.mitre.org/techniques/T1552/001/):
  newly created sensitive material can support a transfer sequence; a CSV
  filename alone is not credential-content verification.

ATT&CK supplies behavioural vocabulary, not these expert-set weights. General
credential-content enrichment, validated volume mappings and missing command
telemetry are still upstream evidence limits; no ground-truth labels are used
as detection inputs to manufacture that evidence.
