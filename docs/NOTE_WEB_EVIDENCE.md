# Web-name hints and YARA ransom-note evidence

Rules **v26**, weights **v22** extend v25 without rewriting historical YAML.
This is an intermediate human-triage stage, not a malware or compromise verdict.

## HTTP status and names

A shell-like requested name alone contributes **1 point**, including HTTP 404,
403, 200 or unknown status. It emits `web_shell_name_probe`, not
`web_exploitation_hint`, and cannot independently produce the 3-point public
application exploit projection. HTTP 200 alone does not establish a shell.

Actual traversal, inclusion or command-parameter syntax retains its existing
attempt scoring even when rejected. Independent AV/YARA, same-file shell
activity and sensitive-file download evidence are not blanket-suppressed by a
404. A 404 is not proof of execution; several independent concerning signals
can still make such a row worth reviewing.

The name-only lead has no ATT&CK attribution. Qualified exploit syntax can
support attempted [T1190](https://attack.mitre.org/techniques/T1190/);
content-qualified web-shell presence relates to
[T1505.003](https://attack.mitre.org/techniques/T1505/003/). These are separate
claims with separate prerequisites.

## Content-qualified ransom notes, including Forge FULL

The user-supplied latest FULL URL resolved to release **20260927**:
[YARA Forge release](https://github.com/YARAHQ/yara-forge/releases/tag/20260927).
Downloaded `packages/full/yara-rules-full.yar` SHA-256:
`5d2a322b7e64970adf23a2ca917c3d8fafe7af90740be73fd315265fa64b5ae3`.
There are 12,384 public metadata entries and 24 private helpers in that bundle.
External rules are independently licensed and are not bundled here.

These six content rules were reviewed in FULL, including descriptions and
conditions, and are also present in the current extended 20260719 input:

| Reviewed identity | Note content | Score / quality |
|---|---|---|
| `TRELLIX_ARC_Clop_Ransom_Note` | Clop note text | 75 / 70 |
| `TRELLIX_ARC_Ransom_Note_Kraken_Cryptor_Ransomware` | Kraken note text | 75 / 70 |
| `TELEKOM_SECURITY_Crylock_Hta` | CryLock HTA note | 75 / 70 |
| `SIGNATURE_BASE_Wannacry_Ransomnote` | WannaCry note text | 75 / 85 |
| `SIGNATURE_BASE_MAL_SUSP_RANSOM_Lockbit_Ransomnote_Feb24` | LockBit note text | 75 / 85 |
| `SIGNATURE_BASE_MAL_SUSP_RANSOM_Lazy_Ransomnote_Feb24` | Lazy note text | 75 / 85 |

The explicit YAML identity registry maps an upstream content detection, not a
file name, rule-name fragment or training-image IOC. A rule for a binary that
drops a note is **not** a note detector. Other reviewed note rules can be added
to `classification.ordered_rules` without engine changes. Future rules whose
metadata explicitly declares `category` or `tc_detection_type` as
`ransom_note` are also supported. This is not a claim of exhaustive family or
note-language coverage.

Role classification precedes generic RANSOMWARE tags. `yara_ransom_note`
contributes **8 points**, distinct from `yara_ransomware`; the existing general
YARA-strength contribution remains. One rule must have actual score **>=50**
and quality **>=50** for note-category emission. These policy thresholds admit
moderate FULL content detections; a high score from one hit and high quality
from another cannot combine to qualify. Existing missing/invalid metadata
failures are preserved. Sub-threshold hits retain general YARA evidence but
cannot supply note corroboration. A note is not added to the referenced-file
malware/execution qualification gate merely because it was read.

The generic two-hour ransomware context branch now requires a distinct
content-qualified note, not README/decrypt/recover filenames. Repeated MAC-time
rows of the same path cannot manufacture independent note corroboration.
Its source explanation includes the note timestamp/path/signal; the note row
retains the matched rule and score/quality. Windows note-creation context also
requires the content signal plus creation evidence. Existing account/image
lookbacks and numerical context weights are unchanged. Note access alone does
not establish creation or authorship.

Note content is contextual evidence relevant to
[T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/),
not proof that encryption occurred. A copied sample, training material or a
quoted note may still match YARA content; provenance and analyst review matter.
Temporal co-occurrence is not causation or proof of unchanged file content.

## Adoption and compatibility

ChronoSIFT consumes upstream `yara_match` evidence; it never scans the disk image.
The surrounding pipeline still pins **extended 20260719**. Nothing here changes
that resource, old Parquet inputs or saved sidecars. To obtain detections unique
to FULL, a separate upstream rescan/extraction and corresponding metadata
provenance are required. Always pass the corpus that actually produced the hits
with `--yara-metadata-path`; don't relabel old hits as results of a newer scan.

Existing weights are unchanged; v22 adds only the new 1-point URL lead and
8-point note signal. Removing filename corroboration lowers some earlier
rankings, while genuine note content can increase note-row priority. Selecting
an older policy explicitly retains its old filename heuristics. The private-
helper metadata boundary correction applies to all policies: previously
overwritten score/quality or classification may legitimately change strength,
confidence or category and needs
source-bound comparison when reprocessing.

Reproducible builders: `build_note_web_policy.py` for v26/v22/current inventory;
`build_semantic_evidence_policy.py` for v25 and its historical inventory. The
focused tests include renamed notes, generic README negatives, weak/unknown
metadata, public/private rule boundaries, Windows contexts and native month-
boundary compact/expanded parity. These tests are not a real-corpus ground-truth
assessment and do not establish a false-positive rate.
