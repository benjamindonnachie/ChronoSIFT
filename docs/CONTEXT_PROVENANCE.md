# Bounded identity and tool context

Candidate rules **v16 / weights v15** extend the preserved v15/v14 pair.
ChronoSIFT remains an event-scoring stage: context prioritises evidence, not a
final incident verdict. Existing sidecars are not rewritten by this change.

## Chronological continuity across partitions

The prior monthly driver carried geographic, travel and IP-continuity state
after evaluating the whole overlapping window. That included future events
which the next month would replay, potentially comparing an earlier event
against a future reference and suppressing its signal.

The driver now commits state only **strictly before the next input window's
lower bound**. Later observations are still evaluated for contextual signals,
but change a disposable, per-identity copy-on-write overlay. Only the affected
identity entry and its directly mutable history dictionaries are copied once
per window suffix. Observations and history metadata are replaced rather than
mutated. No dataframe, entire state tree or nested explanation map is copied.
This applies to all three continuity detectors, including missing-month gaps
and equal timestamps. Temporal candidate reduction is unsafe whenever any of
these stateful detectors is enabled.

The new travel policy uses `update_if_nearby`: a later observation below the
configured distance threshold refreshes the retained time/location. A distant
observation below the minimum time does not replace that reference; otherwise
duplicate/sub-minute records could conceal subsequent qualifying travel.
The existing 200 km, 60 s and 900 km/h thresholds remain YAML-owned.

Continuity keys include the evidence-image/host scope and Windows SID where
available, otherwise the principal. They do not combine `root`, Administrator
or unrelated administrators into one travelling identity. YAML joins the scope
and actor into one key only when both are present: a known host cannot create
a pooled anonymous-account baseline. Incomplete keys neither seed nor update
continuity state. A GeoIP velocity
anomaly can represent shared credentials, concurrent operators, VPNs or
geolocation uncertainty; it does not identify which operator is malicious.

## One-hop creator-risk inheritance

The configured chain is:

1. A successful authentication has a travel anomaly or same-principal/source
   failures followed by success.
2. Within 24 hours, the **same scoped creator SID** appears as SubjectUserSid
   on a structured Security account-creation event. TargetSid identifies the
   child, not the creator.
3. Within one hour of creation, that child obtains privileged membership.
4. The child's eligible sensitive actions receive this context for seven days
   after the qualifying grant, by direct SID or the existing unambiguous
   profile-owner mapping.

Creation, qualifying grant and subsequent action can each receive **eight
points**, with exactly one weighted owner per event. Travel and brute-force
routes retain separate zero-weight evidence but cannot double the increment.
The eight points are additive to the existing twelve-point new-privilege
context: suspicious provenance and newly conferred privilege are different
dimensions. All scores retain the existing cap of 50.

This is **account-level provenance**, not proof of the same session, IP or
human operator. Raw creator/child fields and each sequence's supporting row
IDs/timestamps remain available. An unobserved session link is not invented.
The parent's total score and inherited-risk signals are never source inputs;
there is no recursive propagation, permanent taint or repeated-action refresh.
Unrelated creators, different images, reverse chronology and expired context
do not qualify. A new account or new source IP alone does not establish this
risk. We use inheritance rather than a pooled administrator travel identity.

The behavioural rationale is [Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/),
[Domain Account Creation (T1136.002)](https://attack.mitre.org/techniques/T1136/002/)
and [Additional Local or Domain Groups (T1098.007)](https://attack.mitre.org/techniques/T1098/007/).
ATT&CK supplies the vocabulary and rationale, not numerical weights or a
prescribed risk-inheritance algorithm.

## Qualified first-observed tool use

The default vocabulary covers the PsExec family, including PsExec64. The
first qualifying execution in the available **seven-day scoped-account
history** receives four points. Names are casefolded, and the 32/64-bit forms
share one family baseline. Extend the vocabulary in YAML, not Python.

Only `windows_program_execution` observations enter this baseline. A download,
file-presence record, failed scheduled-action record or zero/missing-count
UserAssist entry cannot seed it. UserAssist's execution branch now requires a
positive observed count; BAM/SRUM and configured process-execution events keep
their existing admission contracts. The first-observation signal is not an
assertion of first-ever use or a persistent novelty bonus. It can recur after
the entire configured observation window lacks qualifying use.

PsExec already has a specific eight-point tool contribution. We do not add the
generic LOLBin contribution for the same fact. Novelty is a different, weaker
contextual dimension. [T1569.002](https://attack.mitre.org/techniques/T1569/002/)
describes service-based execution; local PsExec use alone does not establish
successful execution on a remote target. Failed deployment attempts retain
their existing attempt and account-context scores.

## Evidence containers are not sensitive-file operations

The weighted `sensitive_file_access` lifecycle branch excludes the configured
registry, EVTX and ESE parser prefixes. Their file path can be the containing
SYSTEM/SAM/other database, not a file accessed by the described program.
The original evidence remains intact. Ordinary filesystem and linked-file
observations continue to use the existing sensitive-path policy; other
lifecycle branches are unchanged. The exclusions are a generic per-branch
YAML option, not a hard-coded PsExec exception.

## Configuration and validation boundary

The composed creator chain requires **199 hours** of partition overlap:
six-hour authentication context, 24-hour creation window, one-hour privileged
grant and seven-day activity context. Omitted overlap resolves automatically;
an explicitly shorter overlap fails. The preceding 174-hour policy remains
available only with its corresponding older rule pair.

Generic extensions are `normalisation.method: casefold`, optional
`condition.signals_any` for admitted value-state observations, optional
`excluded_parser_prefixes` for lifecycle row branches, and the travel
reference-update mode. Unknown keys, invalid values and temporally ineligible
signal inputs retain strict validation. Correctness needs per-row comparison
of chronological and overlapping runs, not merely equal totals.

Development validation must retain stable row IDs, reconcile capped weighted
signals and explanations, verify source/resource hashes, exercise negative
identity/expiry/zero-count cases, and compare actual Windows plus Ubuntu/Case1
evidence. Full-corpus regeneration and main/pipeline adoption are separate
steps; this document alone makes no claim that either has occurred.
