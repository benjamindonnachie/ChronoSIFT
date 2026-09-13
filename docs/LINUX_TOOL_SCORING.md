# Linux tool invocation and failed authentication — v19/v16

This is an intermediate pipeline score, not an incident verdict. The isolated
candidate uses rules v19 and weights v16. Earlier versioned policies and completed
sidecars are retained. The changes were informed by scenarioTWO review, so that
dataset is a regression case, not independent evidence of general detection quality.

## Evidence and weighting

| Observation | New contribution | Meaning |
| --- | ---: | --- |
| Score/quality-qualified tool-file fact | 0 | Existing direct YARA points remain; this is a correlation prerequisite. |
| Scheduled reference to that full-path file candidate | 26 | File-at-execution version and successful effects remain unproved. |
| Scheduled reference to a different observed component of its verified repository | 18 | Lower-confidence repository support, **not** a YARA hit on the referenced file. |
| SSH failure | 1 | Failed guess, not access. |
| Invalid-user context | 1 | Target-account context, not a second login attempt. |
| Generic authentication failure fallback | 1 | Requires authentication context; suppressed when the SSH-specific fact already exists. |

The two linkage contributions are alternatives, never added together. Existing
scheduled/interpreter/privileged-schedule evidence totals 13 in the representative
root Python cron fixture, yielding 31 with repository support. Existing repetition
adds seven once at three observations in ten minutes, giving 38 at that observation.
Neither direct source-file YARA points nor unrelated archive/collection scores
are copied onto the command. Generic privileged-execution context is suppressed
when the dedicated privileged-schedule signal already accounts for it.

Failed authentication cannot earn privileged-login or privileged-execution points.
Account/source pivots require successful remote authentication observations;
disconnects, unsuccessful username spraying and unspecified/loopback source
addresses do not establish that pivot. Three failed attempts followed by success
still qualify for the existing same-source/same-principal escalation rules.
The Plaso IPv4 `Successful login of user: ... using authentication method: ... ssh`
rendering now supplies SSH success, actor, protocol, direction and outcome facts.
CRON/CROND `(user) CMD (...)` records use the named user, not the daemon, as actor.

## Bounded linkage contract

The optional `qualified_artifact_command` executor runs at contextual phase 38,
after qualification and signal adjustments, before temporal rules. YAML owns all
input fields, parser/type admission, marker/reference patterns, source/target
signals, positive lookback, emission metadata and weights. Python supplies only
the reusable correlation mechanics. Unknown fields, bad captures, invalid
dependencies and missing weights fail policy validation.

The current YAML admits file observations from `filestat`, regular-file type,
and an observed `/.git/HEAD` marker to identify the nearest repository root.
It admits qualified YARA offensive-tool/malware categories or existing qualified
malware-file evidence. A marker by itself never makes a file malicious. A different
component must have an observed full path under the **same nearest marked root**.
Nested repositories, prefix-neighbour directories and case differences do not
inherit support. Missing target/marker evidence, future observations, conflicting
observed SHA-256 values or missing qualification fail closed. The reference is
lexical: no filesystem reads, shell execution, symlink traversal or basename search.
Repository membership is not semantic proof that two components implement the
same tool: a monorepo can contain unrelated utilities. That is a remaining
false-association risk and a reason to retain the lower-confidence label.

The configured command patterns accept an absolute interpreted script, an explicit
`cd ... && interpreter script`, or an absolute wrapper-prefix directory followed
by an interpreter and relative script. That final form is labelled
`prefix_directory_hint`: it records a command reference/attempt, **not** proof that
a possibly malformed wrapper command successfully launched the interpreter.
Variables, traversal, arbitrary shell expressions and multiple distinct resolved
targets are rejected. Unsupported quoting/arguments remain a coverage limitation.

Both files and the marker must be observed at or before the command within 24h.
The configured detector lookback participates in the partition planner's raw
feature requirement. No seven-day Linux raw overlap has been introduced. There
is no indefinite taint or refresh from mere repeated invocation: later commands
outside the evidence window can retain ordinary cron scores without this link.
Chronological order does not prove filesystem timestamps are trustworthy.

Explicit file-host labels must match the command's host. The YAML option
`unlabelled_file_scope: current_dataset` admits hostless filesystem records from
the current single-image dataset alongside a named local cron event; `isolated`
disables that fallback. This is a declared evidence-ownership assumption, not
proof that a log's hostname identifies the original file owner. Plaso hostname
fields can contain remote login addresses or non-host strings, so they are not
used to infer a unique machine for unlabelled files. As with other dead-box file
associations, use one evidence image per dataset; do not concatenate unlabelled
images and assume they can be distinguished. Source, target-file and
marker explanations carry persistent integer row IDs; timestamps are not join keys.

Only qualifying/source paths, referenced targets and markers enter scalar indexes.
The executor does not copy dataframes or nested signal/explanation structures.
Unrelated source repositories are indexed out of each command's candidate set.

## ATT&CK rationale and limits

Recurring cron invocation is relevant to [T1053.003 — Cron](https://attack.mitre.org/techniques/T1053/003/).
Interpreted commands relate to T1059. A keylogger-labelled source is supporting
context for investigating [T1056.001 — Keylogging](https://attack.mitre.org/techniques/T1056/001/),
not proof that keystrokes were captured by a sibling Linux component. Keep payload
effects distinct from scheduled invocation.

Failed password guessing remains relevant to [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/),
but this pipeline policy prioritises evidence-supported local tool invocation and
successful access/follow-on behaviour above failed guesses alone. The numeric
weights are research-policy choices, not values prescribed by MITRE.

The separate broad credential-collection/manual-page association found during
scenarioTWO review is not used by this linkage and is not repaired in this change.
SELinux audit authentication canonicalisation and wider shell grammar are also
outside this bounded implementation. No original ground-truth ledger was edited.
