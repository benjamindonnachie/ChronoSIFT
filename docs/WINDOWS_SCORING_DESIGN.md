# Windows behavioural scoring: policy and evidence contract

Reviewed 8 September 2026 against the completed Windows evidence audit and the
current MITRE ATT&CK Enterprise technique pages linked below.

**Implementation candidate: rules v13 / weights v12, isolated worktree only.**
The implementation below follows the design rationale in this document.
The full suite passes (493 passed, eight expected skips). A bounded 699,021-row
Windows replay and four Case1/Ubuntu windows validate keys, scores and
explanation totals; an isolated note-branch follow-on covers basename-only USN
creation. These are development fixtures, not an independent hold-out study.
No existing sidecar is rescored and no change is published to main.
See [current calibration](EVIDENCE_CALIBRATION.md) and the historical
[coverage matrix](ATTACK_MATRIX.md).

## Implemented policy and boundaries

- Numeric event IDs are normalised into a separate field, including `4720.0`.
  XML target/member/subject SID aliases distinguish the created account from
  its creator. Task `UserContext`, BAM/SRUM paths and execution-provider events
  are recognised without relying on the evidence case's names or addresses.
- Creation followed by privileged membership within one hour establishes a
  seven-day account context. Direct SID or unambiguous profile ownership adds
  12 points to eligible later actions. Same-image security/archive/task actions
  without actor evidence receive only 6; the stronger of these counts once.
  A known different SID does not receive that unknown-actor fallback. Null SIDs
  from failed authentication are excluded from identity seeds.
- A newly observed successful-logon source in the available seven-day account
  history can add 4 points to a relevant action within six hours. Repeated
  logons do not refresh the original novelty observation. Missing preceding
  history limits novelty confidence; it is not a first-ever-IP claim.
- Defender disabling values must be 1, not just a setting name containing
  `Disable`. Recovery inhibition requires specific destructive/disabling
  command semantics. Log clearing requires its event provider. A failed
  scheduled PsExec action remains an attempt, not successful remote execution.
- Whole rooted path references to AV-positive files give a malware-use
  **candidate**, not an exact identity. Device-volume stripping is only a
  volume-relative candidate alias: volume mapping, replacement between file
  observation and execution, and cross-volume collisions remain unresolved.
  No new basename-only fallback is enabled. The explicit executed-file hash
  contract below enables the stronger identity feature.
- Archive creation, including basename-only USN `FILE_CREATE` evidence, receives
  8 points without pretending a basename establishes identity or authorship.
  Later FTP activity on the same account/profile receives 16 contextual points;
  a weaker same-image archive/FTP association receives 8 instead, never both.
  FTP registry account-cache records qualify as destination activity even when
  they contain no URL. An explicit FTP upload command or failed attempt receives
  20 points; completion and upstream confirmation are **not required**. Ordinary
  FTP navigation remains distinct from a demonstrated upload attempt. New note-like
  files alone are neutral; prior ransomware-classified file evidence for the
  same account/profile supplies 24 points of note context. A basename-only
  creation without attributable SID can receive 16 points from same-image
  ransomware evidence within 12 hours instead; it never receives both links.
  Note content, malware family
  and encryption effects are not inferred from the filename.
- Shared-account failure/success correlation now also requires the same source
  IP. Login geography has lower weights; neither a new country nor a particular
  country is inherently malicious.

The added Python is generic: optional regex selectors, ambiguity-rejecting
identity lookup, explicit derived-field recomputation, sequence witness IDs and
compounded overlap validation. Detection vocabulary, conditions, durations and
weights remain YAML-owned. No defensive dataframe copies were added.

### Optional upstream evidence contracts

These fields describe actual upstream observations, never annotations copied
from ground truth. Existing Windows Parquets do not currently supply them.
They are optional corroboration: their absence does not gate the attempted or
inferred FTP-transfer rules above, nor erase their contextual scores.

| Fields | Meaning and gate |
| --- | --- |
| `chronosift_executed_sha256` | Hash of the executable actually used, not the hash of the EVTX, registry hive or SRUDB container. Must match an AV-positive file hash observed in the loaded frame, together with an execution/use artefact. |
| `chronosift_sensitive_content_verified`, `chronosift_sensitive_content_type` | Explicit boolean verification and type `plaintext_credentials` or `payment_card_data` for the referenced file. An access timestamp can then receive sensitivity weight. An ordinary CSV name does not qualify. |
| `chronosift_transfer_direction`, `chronosift_transfer_outcome`, `chronosift_transfer_bytes` | File-linked outbound transfer, success and positive bytes, together with the verified sensitivity fields, activate the stronger observed-upload feature. FTP history alone supplies none of this proof. |

The numerical distinction is observation quality, not a requirement to succeed:
an explicit failed attempt already contributes 20 before account/source context,
and can exceed 30 without any upstream content or completion fields. Verified
sensitive successful upload is an additional supported case, not the baseline
for treating possible exfiltration as concerning.

Identity aliases are resolved within the loaded frame, case-insensitively by
name, only when every seed agrees on the SID. Domain/name collisions refuse
resolution; profile ownership is not proof of the process user or operator.
Known identity seeds outside that frame are not looked up magically. Name-only
task/profile aliases are not a fully qualified domain-identity service; an
unrepresented domain cannot be ruled out from a unique local name match.
YARA-only
execution identity and global asset/volume-scoped executable version identity
  remain follow-on work; weak name-only YARA cannot activate the AV-backed branch.

### Partition and provenance contract

Generic account/source sequences replay from overlap, not persistent global
state. This policy requires **7 days 6 hours**, including the nested source
novelty-to-action window. Automatic overlap chooses the greater of 24 hours and
the configured requirement; an explicitly smaller value fails before output.
The actual loaded boundary can truncate history at dataset start. Use a fresh
referenced-file manifest when adopting the new policy digest.
Longer overlap deliberately loads more history and can increase I/O/memory on
other datasets too; it is not a free performance optimisation. A full Ubuntu
run has not been repeated with this Windows-oriented policy.
Sequence explanations include triggering/supporting integer row IDs and
timestamps, grouping key, lookback and an explicit attribution limitation.
Replays retain all rows; equal timestamps never become join keys.

## Scoring principle

Prioritise observed harmful behaviour and its supporting context, not the
number of ATT&CK labels attached to a row. Technique references describe the
behaviour being modelled; they do not prescribe ChronoSIFT weights or establish
malicious intent. Numerical contributions remain expert-set YAML policy,
separate from explanation confidence and the final pipeline's decision.

Known-malware execution should rank very highly even without a new IP or an
identified account. A recently created privileged account, unusual remote use,
and subsequent security changes should strengthen relevant later events across
sessions. Requiring the entire incident to occur within one session would lose
useful context. Conversely, host-level proximity must not be presented as proof
that a particular user made a registry change.

## First priorities and ATT&CK rationale

The baseline scores below come from the completed Windows v12/v11 audit. They
are examples of current coverage, not exhaustive attack recall measurements.

| Improvement | Evidence and scoring change to evaluate | ATT&CK relationship |
| --- | --- | --- |
| Known-malware identity linked to execution | Final executable-use records currently score 0, while associated AV-backed binary artefacts score about 30. Resolve the executable identity from each supported execution source and correlate it with qualified malware evidence. Preserve a distinction between exact hash linkage, validated path linkage, file presence and execution. | Map the observed execution mechanism, such as [Service Execution, T1569.002](https://attack.mitre.org/techniques/T1569/002/), only when supported. Ransomware identity provides context for [Data Encrypted for Impact, T1486](https://attack.mitre.org/techniques/T1486/); running its binary does not by itself prove encryption. |
| Newly created privileged account used for follow-on actions | Account creation scores 11 from generic privilege features; group addition scores 0. First recognise creation and membership changes, then link the created account's SID/domain identity to later actions. Do not confuse the creating subject with the created target account. | [Domain Account Creation, T1136.002](https://attack.mitre.org/techniques/T1136/002/), [Additional Local or Domain Groups, T1098.007](https://attack.mitre.org/techniques/T1098/007/), and subsequent abuse of [Domain Accounts, T1078.002](https://attack.mitre.org/techniques/T1078/002/). Use the domain sub-techniques only when domain scope is established. |
| Security impairment in that account's activity | Defender policy evidence currently scores 10. Require a disabling value, command or state, then add distinct account/session or broader host context at its supported confidence. A value name containing `Disable` with value 0 must not become positive disablement evidence. | [Disable or Modify Tools, T1685](https://attack.mitre.org/techniques/T1685/). Where GPO authorship and the relevant change are linked, also describe [Group Policy Modification, T1484.001](https://attack.mitre.org/techniques/T1484/001/), without scoring two labels for one observation. |
| New task or service with a suspicious action | The deployment-task cohort currently scores 0. Distinguish registration, modification, action launch and action outcome; link the author/principal and executable. A task targeting a known-malicious file should rank above an ordinary scheduled backup. | [Scheduled Task, T1053.005](https://attack.mitre.org/techniques/T1053/005/) and [Windows Service, T1543.003](https://attack.mitre.org/techniques/T1543/003/). Task creation does not establish that its action completed successfully. |
| PsExec and administrative-share activity | Raise identity-linked execution or attempted deployment under the recent privileged account, particularly when associated with a malicious payload. Keep a failed task action useful but distinct from successful remote execution; installation of the legitimate utility alone is weak evidence. | [Service Execution, T1569.002](https://attack.mitre.org/techniques/T1569/002/) and [SMB/Windows Admin Shares, T1021.002](https://attack.mitre.org/techniques/T1021/002/). A cached share path does not establish a current remote session or service execution. |
| Sensitive collection, archive creation and external transfer | Archive/FTP traces currently score mostly 0–7. Correlate sensitive-source access, genuinely new archive creation and later transfer activity using file/account identity. Score the linked sequence even where transfer completion remains inferred, but reserve the stronger outcome contribution for observed transfer evidence. | [Local Data Staging, T1074.001](https://attack.mitre.org/techniques/T1074/001/), [Archive via Utility, T1560.001](https://attack.mitre.org/techniques/T1560/001/), and candidate [Unencrypted Non-C2 Exfiltration, T1048.003](https://attack.mitre.org/techniques/T1048/003/). Use the archive sub-technique only with utility evidence. FTP navigation is not a measured upload, and channel separation/encryption require support. |
| Ransom-note placement with ransomware context | Current note traces score 0–7. Give more weight to actual note creation linked to ransomware artefacts/execution, and still more to verified note content or destructive file effects. Do not require every supporting feature before retaining a useful candidate. | [Data Encrypted for Impact, T1486](https://attack.mitre.org/techniques/T1486/). A note-like filename is weaker than ransom content and is not proof of encryption or malware family. An ordinary package README must not receive the same treatment. |

## Additional improvements beyond the immediate gaps

1. **Credential sensitivity, not only payment-card sensitivity.** Reading a
   file known to contain plaintext account credentials should strengthen
   subsequent staging/transfer evidence. An ordinary CSV extension or a
   suggestive filename is insufficient. This connects to
   [Credentials In Files, T1552.001](https://attack.mitre.org/techniques/T1552/001/).
   The Windows audit already identifies a relevant credential-file access
   sequence; a separate proposal is not evidence that its contents were uploaded.
2. **Recovery inhibition and anti-forensic actions.** Confirmed backup/shadow-copy
   destruction or disabling recovery should carry substantial independent
   weight and strengthen a linked ransomware sequence:
   [Inhibit System Recovery, T1490](https://attack.mitre.org/techniques/T1490/).
   Explicit log clearing provides a different useful feature:
   [Clear Windows Event Logs, T1685.005](https://attack.mitre.org/techniques/T1685/005/).
   These are general coverage priorities, not claims that both occurred in the
   reviewed Windows case. Missing later telemetry alone proves neither.
3. **Independent corroboration rather than label accumulation.** Give one
   bounded increment for a genuinely new evidence dimension. Repeated AV
   aliases, technique aliases and multiple timestamp representations of the
   same source event must not manufacture independent corroboration. Retain
   every source row and its integer ID; this is evidence accounting, not row
   deletion or timestamp-based joining.
4. **Separate account anomaly from action attribution.** The legitimate
   administrator currently reaches 47 because attacker and legitimate uses of
   the same account contribute to shared authentication context. Keep the
   useful account-compromise observation, but stop treating every later use as
   the same operator. IP novelty and geography should corroborate relevant
   actions, not dominate known-malware execution. Do not hard-code risky
   countries, account names, addresses or case-specific filenames.

## Original calibration targets

For bounded calibration, start by testing the following relative ordering on
the existing 50-point scale. These are candidate **total event scores**, not
additive per-signal weights, adopted thresholds or probabilities.

| Supported observation | Initial calibration target |
| --- | ---: |
| Strong known-malware identity plus observed execution | 45–50 |
| Strong known-malware file presence without execution | 30–40 |
| Security impairment or suspicious task/service action linked to recent privileged-account misuse | 25–40 |
| Sensitive staging followed by linked suspicious external transfer activity, completion unproved | 20–35 |
| Observed sensitive upload with linked suspicious account/destination context | 40–50 |

These bands can overlap: additional independent evidence should change
priority. A harmless new account or a new IP alone should not receive the
combined-action score. Preserve a meaningful score for an attempted malicious
action even when failure prevents its intended outcome.

## Implementation and explanation contract

The implementation uses a new versioned rules/weights pair, preserving v12/v11.
Keep selectors, field precedence, temporal bounds, confidence descriptions,
signal ownership and numerical weights in YAML. Add Python mechanics only
where the existing generic field/identity/temporal executors cannot express
the policy; do not embed Windows-case answers in the engine.

First check numeric event-ID normalisation, raw EVTX string versus XML field
coverage, subject/target SID extraction, and executable-path recovery. Missing
features cannot be repaired by increasing a weight that never activates.
Device-volume and drive-letter paths need evidenced, asset-scoped aliases:
never join unrelated files solely because they share a basename.

Maintain bounded recent-account context across days and month boundaries;
repeated logons should not indefinitely refresh its original creation time.
The existing 24-hour overlap is not automatically sufficient for a new
multi-day rule. Test carried state and any compounded lookback requirements
before changing defaults. Keep the implementation sparse and outside large
pandas metadata structures so the performance repair is preserved.

Every contextual explanation should identify the triggering row, supporting
row IDs, temporal bounds, identity key and quality of the link. Keep direct
subject/session attribution separate from profile ownership and host-level
co-occurrence. Report the scored feature once and list all applicable ATT&CK
references separately. Do not transfer a whole prior row's score to a later
row or insert a pre-dDCA aggregate: the output remains event-level evidence.

Use comments of this form beside YAML implementations:

```yaml
# ATT&CK: T1053.005, https://attack.mitre.org/techniques/T1053/005/
# Rationale: task registration plus distinct recent privileged-actor context.
# Requires: registration evidence; explicit author/principal identity link.
# Does not establish: successful task action or successful remote deployment.
# Score ownership: one contextual increment; ATT&CK aliases stay score-neutral.
```

## ATT&CK version boundary

The existing matrix uses historical **T1562.001** for disabling defensive tools.
The current MITRE page presents this behaviour under
[T1685, Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)
(technique version 1.0, last modified 12 May 2026). Current Windows log clearing
is [T1685.005](https://attack.mitre.org/techniques/T1685/005/).
These are documentation cross-references, not a silent migration of saved
signals, the historical matrix or emitted technique IDs. Record the chosen
ATT&CK release/object versions in a future implementation's provenance and
review all affected mappings together. Do not apply the mobile-domain
Disable or Modify Tools identifier to Windows.

## Validation before adoption

- Synthetic tests with invented accounts, paths and addresses: integer/float
  event IDs, raw/XML variants, different creator and created account, unknown
  identity, same basename on different volumes, reversed ordering, elapsed
  context, missing geography, benign tasks and legitimate administration.
- Contrast Defender values 0/1; known-malware presence/execution; failed task
  actions/successful execution; FTP browsing/attempted transfer/observed upload;
  generic README/corroborated note; repeated source representations versus
  independent evidence. Failure to prove the strongest outcome must not erase
  the weaker supported feature.
- Replay chronological Windows context containing the actual account creation,
  group change, both Defender observations, task/PsExec, archive/FTP, note and
  final execution. Include preceding and concurrent legitimate activity, not
  only attacker-selected rows. Compare old and candidate scores/explanations
  at stable IDs; assess each attribution rather than forcing all anchors high.
- Recheck Case1 benign/package and attack windows plus Ubuntu setup and
  compromise windows. Explicitly test account context across month boundaries
  and inspect memory/runtime before a full-corpus run.
- Validate all output IDs, score sums/cap, evidence ownership and exact source,
  configuration and enrichment provenance. Ground-truth-informed calibration
  is not independent hold-out performance or final-pipeline precision/recall.
