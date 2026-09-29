# Semantic evidence gates (rules v25 / weights v21)

This pipeline stage prioritises evidence for an investigator. It need not prove
compromise, but it must not turn a word in documentation into an observed action.
V25 follows the September static-string review. Weights, historic policies,
completed sidecars and the AV/YARA category-qualified DVWA/web-shell route are
unchanged. **Future scores can change; old sidecars are not retroactively fixed.**

## What changed and why

| Boundary | V25 admission and interpretation | Knock-on effect |
|---|---|---|
| Database dump | Newly created database/dump-like file must be under an explicitly configured web document root. Label is potential exposure, not proven dumping. | Arbitrary package `dump` archives and ordinary private databases lose the seven-point candidate. Luhn/content-linked HTTP transfer and recent creation chains are independent and retained. |
| Commands | Source-qualified history, native command fields, recognised cron/sudo records; literal executable position, not every token. | `echo python`, tool-name substrings and documentation no longer produce execution/tool signals or their projections. Actual attempts still count without proof of success. |
| SUID/SGID | Literal chmod setting the special permission bits. | `chown root` is not set-ID creation. Signal name `exec_new_suid_binary` is retained for compatibility; explanation explicitly says attempt, not a new binary or execution. ATT&CK T1548.001. |
| Accounts | Tool log prefix or invocation for attempts; structured new-user grammar for successful creation. | Manual-page extraction errors no longer score as account operations; failed useradd remains an attempt but loses successful-creation points/context. Deletion requires a removal record or invocation. |
| Authentication | Structured outcome, or admitted authentication parser plus actual SSH/PAM record format. | Documentation cannot seed success/failure, travel or fail-then-success context. Local PAM remains local. Unrecognised free-text formats may need an explicit parser grammar. |
| Configuration | Anchored effective locations, e.g. root/home `.ssh`, Windows GroupPolicy/SYSVOL, Linux cron/service/firewall configuration. | Nested example paths and arbitrary `policies` directories no longer imply persistence. Custom SSH homes/config locations need explicit policy configuration. T1098.004, T1484.001 and relevant persistence mappings remain candidate evidence. |
| Security impairment | Actual invocation for recovery inhibition, log cleanup and service stopping; Defender provider/event 5001 for the standalone disablement route. | Phrases in filenames, tutorials or negated test text do not qualify. Existing registry disabling-value route is retained. Attempts remain concerning (T1490, T1685 and T1489). |
| Credentials | Recognised credential-container location/format or operation; explicit upstream process-dump role/target, not an `lsass`/`minidump` basename. | Removes generic vault/credentials/guide matches. Upstream dump metadata uses `artifact_type=process_memory_dump` and `target_process_name`; command evidence works independently. T1003/T1555 describe the qualified source, not every filename. |
| Follow-on | A later admitted copying/archiving/transfer operation explicitly references the source's full path. POSIX case preserved; Windows paths case-insensitive. | Shared name fragments and same-row self-links cannot amplify credentials. Basename-only/relative/ambiguous references may now remain unlinked; no speculative identity is invented. Same-path evidence is not proof of unchanged file version or successful exfiltration. |
| Archives | Large-archive staging signal needs creation time, not mere access. An archive suffix no longer supplies benign-backup suppression. | Access-only large ZIP loses creation points. Real tar/zip commands may score **higher** because `.zip` is not a routine-behaviour baseline. |

Recognised paths, executable names, provider IDs and formats are legitimate
policy vocabulary. They are not universally suspicious indicators. The semantic
admission and explanation are what make a match defensible. No training-image
IP, country, account or malicious filename is added as a scoring shortcut.

## Command syntax and limits

`command_invocations` is an optional normalisation method. YAML supplies `from`,
`wrappers` and `scripts`; each wrapper/script regex requires a named `command`
capture. The generic helper splits unquoted command separators, preserves quoted
arguments, normalises only executable heads, and recognises configured literal
wrappers/shell payloads. It never executes commands or resolves PATH, variables,
aliases, substitutions or filesystem objects. Malformed quoting fails closed.
Recursion is bounded to eight levels, 256 invocations; cache is bounded to 4096
entries. It is **not** a complete POSIX, cmd or PowerShell parser. Complex or
unsupported syntax can lose these generic heuristic signals; raw evidence and
independent malware/use signals remain available.

`command_match_mode: invocation_heads` in the execution classifier consumes
that field. Historical policies default to the original token mode. Lifecycle
`classification.path_regex` optionally replaces `web_root`/`sensitive` substring
matching with configured regexes; `configure_web_roots.py` updates the root regex
as well as existing mappings. Follow-on `identity_mode: full_path` replaces label
matching; historical policies retain `labels` mode.

## Explanation accounting

Scoring already merged duplicate producers of one signal. Explanation output
previously attached that final contribution to **each** producer. Now the first
producer in deterministic output order owns the final merged contribution;
later explanations still show their evidence and final signal value, but their
`score_contribution` is zero. Each signal detail includes `contribution_role`
(`owner`/`supporting`) and `contribution_owner` (rule ID). Ownership is bookkeeping,
not a claim that the first producer is more evidentially reliable. Distinct
signals remain additive, including base account removal plus privileged-group
severity. Top-level score, cap, profile and trust semantics are unchanged by this
accounting correction; explanations describe pre-cap contributions as before.

Native Arrow structs and JSON both preserve the added fields. Readers using a
fixed nested schema should allow these two strings. Saved explanations are not
rewritten; old reporting can still double-count if it sums old producer values.

## Policy and validation provenance

Build v25 with `benchmarks/build_semantic_evidence_policy.py` from immutable v24.
The builder emits an apply-patch document, keeps historical YAML byte-identical,
and explicitly revises the changed dump/outcome rationale. ATT&CK IDs are checked
against the existing offline pinned catalogue, not fetched at scoring time.
`docs/ATTACK_MATRIX_CURRENT.md` is generated from v25; v24's inventory is preserved
as `docs/ATTACK_MATRIX_V24.md`.

`tests/test_v231_semantic_evidence.py` covers negative counterexamples, real
attempts/locations/outcomes, exact-path linkage, additive scoring and native/JSON
explanation accounting. `benchmarks/replay_semantic_probes.py` replays only the
saved synthetic scan inputs into an exclusively created receipt. These are
regression checks, **not** a new full-corpus ground-truth evaluation or a measured
false-positive/recall estimate. The weaker filename-only web request hints and
corroborated note heuristics identified as separate policy choices are not
silently removed by this repair.
