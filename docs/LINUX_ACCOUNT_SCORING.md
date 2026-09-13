# Linux SUID and account context

Rules **v20 / weights v18** add two bounded evidence families. Earlier policies,
including the AV weighting in v17, remain reproducible. ChronoSIFT is a pipeline
scoring stage: these are prioritisation signals, not incident verdicts.

## SUID artefacts

A `filestat` record receives **24 points** when all of the following are observed:

- a regular file (`file_entry_type: file`);
- root ownership (`owner_identifier` numerically zero);
- set-user-ID mode bit `04000` plus at least one execute bit;
- a full path within configured staging roots: `/tmp`, `/var/tmp`, `/dev/shm`,
  `/var/spool`, `/home` or `/root`.

The allowlisted *locations of concern* are YAML policy, not hard-coded case paths.
Normal `/bin`, `/usr/bin` and other system locations do not receive this signal.
This is not a complete SUID inventory or a package-baseline anomaly detector.
A legitimate custom SUID helper in a staging root can qualify; review remains
necessary. A matching filename, mode text in an unrelated message, a directory,
an ordinary executable, setgid alone or missing owner/mode does not qualify.

The original Honeynet Parquet supplies `mode=2541.0`, the decimal representation
of octal `4755`, and `owner_identifier=0.0`. New normalisation explicitly opts
into `number_format: strict_integer`: decimal integers, integral decimal floats
and `0o`/`0x`/`0b`-prefixed integers are accepted exactly. Fractions, negatives,
scientific notation, symbolic permissions and malformed strings are rejected;
unprefixed numbers are not guessed to be octal. Existing mask policies retain
their previous decimal/hex parser unless they opt in.

[ATT&CK T1548.001](https://attack.mitre.org/techniques/T1548/001/) supplies the
setuid/setgid privilege-abuse rationale. A file's mode establishes a
privilege-capable artefact, not its execution, exploitability, creation time or
successful privilege escalation. Repeated filesystem timestamps are not separate
executions. No chmod operation is inferred from a metadata timestamp.

## Separate Linux account roles

Structured `useradd` completion messages provide the **affected name and UID**.
They do not supply a creator. The new fields never replace `actor_user` with the
child and never interpret the `useradd` daemon name as the creating operator.
SSH authentication uses the existing configured SSH actor output, not a guessed
field alias or arbitrary username mentioned in text.

| Observation | New contribution | Boundary |
|---|---:|---|
| UID-0 account creation | +18 | Additive to existing generic account change 9: normally 27 total |
| Successful SSH use within seven days of observed account creation | +12 | Failed guesses do not qualify |
| Successful use of a recent UID-0 alias outside the configured privileged-name vocabulary | +11 | Equivalent to existing privileged login 6 + privileged context 5; known privileged names do not double count |
| Account created within one hour after privileged SSH success on the same host | +6 | Weak host-level chronology, not a creator/session relationship |
| Successful use within seven days of that creation | +6 | Carries only the weak host association, not the parent's score |

Generic account creation alone stays at 9. This does not suppress legitimate
creation or label every new account malicious; novelty plus successful remote
use is a separate triage dimension. Existing AV contributions remain 32 for
malware/exploit and 33 for ransomware/web shells.

The host association deliberately does **not** require or claim maliciousness of
the preceding privileged login. It is weaker than Windows' structured creator-SID
risk inheritance. A shared host and short interval cannot identify a particular
operator, session or source IP. Supporting row IDs and times expose the actual
link, and descriptions state this limitation. No invented creator edge, shared
administrator travel baseline or recursive risk propagation is introduced.

[T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) and
[T1078.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003/) provide
behavioural vocabulary, not the numerical weights or proof of malicious intent.

## Chronology, lifetime and scope

Account keys require both the existing evidence/host scope and the exact,
case-sensitive account name. Unknown hosts/accounts do not form pooled keys.
There is no global name-to-UID lookup or future-to-past privilege backfill.
Only the observed creation seeds the seven-day window. Repeated logins never
refresh it. Outside the window, this bounded evidence no longer supplies a
privilege assertion; the engine does not assert that the account ceased to exist.

Generic temporal sequences now support optional `reset_signals`. A reset clears
the current key's sequence **before** admitting that row. Thus recreation can
start a new lifetime without retaining the prior UID or host association. New
policy resets on every observed creation and on qualified `userdel` deletion or
`usermod` change messages. Modifications are conservatively invalidating even
when they might leave the UID unchanged. Unobserved changes cannot be detected.
The supported message forms are the configured Plaso and `program[pid]:` syslog
renderings; arbitrary shell commands or documentation are not completion proof.

Reset markers are unweighted but remain temporal dependencies and candidates.
They participate in eligibility checks, applicability checks and compact replay.
Reset signals must be declared and are permitted only on sequence rules. Existing
rules without resets are unchanged. Tied timestamps keep persistent integer row
IDs and stable input order; they are never merged or given fabricated nanoseconds.

These new dependencies require up to **169 hours of compact context** on an
otherwise Linux-only plan; raw feature overlap remains **24 hours**. The overall
conservative mixed/Windows horizon remains 199 hours. This is not seven days of
full nested evidence. Native compact/eager and cross-month tests are required,
as well as original-record replay and full regression, before freezing a run.

This document describes v20/v18; see [rules and weights](../rules/README.md) for
the current CLI defaults. This does not adopt a candidate into main, the
production pipeline or GitHub, and it does not rewrite previous sidecars.
Actual validation and full-run receipts are saved separately under `working/`.
