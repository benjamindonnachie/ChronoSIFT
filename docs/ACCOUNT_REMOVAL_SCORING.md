# Additive privileged-group removal scoring

Candidate rules v15 / weights v14 use the existing engine. Earlier policy pairs
and completed sidecars remain unchanged; selecting a new default does not update
previous outputs or the main pipeline checkout.

## Two intentionally additive dimensions

| Dimension | Signal | Weight |
| --- | --- | ---: |
| Account disablement, deletion or group-membership removal | `account_access_removal` | 2 |
| The affected group is a configured privileged/access-enabling group | `privileged_group_access_removal` | 6 |

Ordinary removal contributes **2**. Privileged-group removal contributes
**2 + 6 = 8**, before any other independently supported context and the normal
50-point cap. The six points describe the affected group's privilege, not
merely that an administrator carried out an action. These are configurable
expert priorities, not probabilities or weights prescribed by ATT&CK.

The privilege rule requires a group-removal event (4729, 4733 or 4757) and the
affected group's exact, case-normalised name. It uses the first nonempty
`group_name`, then `target_user_name` (the canonical EventData group target for
these events). The initial configured names are Administrators, Domain Admins,
Enterprise Admins and Remote Desktop Users. Other/localised/custom names require
explicit policy configuration; an unrecognised group retains the base score.
An administrator's name in the subject, removed member, command or message does
not establish that the affected group was privileged. Conflicting nonempty
group fields use the documented first-field precedence, not a favourable match
from anywhere in the record.

## Contribution ownership

The disable/delete-event and general text/group-removal routes retain separate
zero-weight observations (`account_removal_event_evidence` and
`account_removal_other_evidence`) and their original confidence/evidence. One
ordered rule, `account_access_removal_base`, projects these observations or a
privileged-removal match into the existing two-point base signal. It has generic
low confidence; the supporting observations retain their own confidence.

There is one weighted producer per dimension. Multiple observations of the same
base behaviour therefore do not repeat its points, whereas the deliberately
distinct privilege increment does add points. The saved explanation breakdown
is 2 for the base plus 6 for privilege. Repeated execution maximum-merges the
same signals and retains one explanation per rule/signal.

This is a scoped YAML repair, not a global change to explanation allocation.
Other policies must still avoid presenting several explanations of one
maximum-merged signal as independent additive contributions. The explanation
sum validator remains unchanged and must not be disabled to accept a mismatch.

## Evidential rationale and limits

[MITRE ATT&CK T1531, Account Access Removal](https://attack.mitre.org/techniques/T1531/)
describes account/permission changes that deny legitimate access and can impede
response or recovery. That supports prioritising removal of administrative
access above ordinary membership changes. A matching event alone does not prove
malicious intent, complete lockout, account deletion or downstream impact.

Subject/target identity and recent attacker-account/source context are separate
questions. This change does not repair the previously observed target-group
`canonical_actor` selection or add new actor/IP bonuses. It also does not change
other Windows, FTP, malware or web-server rules, temporal windows, confidence
mechanics, persistent integer row IDs or the 174-hour overlap requirement.

## Reproducibility and validation

`benchmarks/build_account_removal_policy.py` generates the new pair from preserved
rules v14 / weights v13 and emits an `apply_patch` patch. After generation its
output must be an empty patch. `tests/test_v231_account_removal.py` covers
ordinary/privileged cases, overlapping event/text evidence, subject/member
negative controls, exact group names, numeric event formats, tied row IDs,
idempotent execution, editable weights and native nested sidecar readback.

The four records that exposed the previous explanation mismatch must also be
replayed from raw evidence into a fresh diagnostic directory. A bounded replay
does not certify the earlier failed full run or substitute for the outstanding
full Windows/Ubuntu ground-truth reviews.
