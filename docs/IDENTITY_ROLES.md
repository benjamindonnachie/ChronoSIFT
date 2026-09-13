# Event-role identity

Candidate rules **v17 / unchanged weights v15** preserve the preceding policies
and outputs. The automatic overlap remains **199 hours**.

## What the identities mean

| Field | Meaning |
| --- | --- |
| `identity_reporting_sid` | Raw Windows event reporting identity; not automatically the remote user |
| `identity_authenticated_account` / `_sid` | Account named by the configured authentication event |
| `identity_acting_account` / `_sid` | Explicit Subject account for configured account/group management events |
| `identity_affected_account` / `_sid` | Account created, changed, or removed from a group |
| `identity_affected_group` / `_sid` | Group whose membership or state changed |

`canonical_actor` in explanations now uses the authenticated account for
configured logon events and the acting Subject for account/group changes.
The existing `actor_user`/`actor_principal` username-format contract is retained
for privilege vocabulary and name-based failure sequences. Domain-qualified
display identities live in the separate role fields, not in those legacy
fields. Existing name-based sequences do not establish a unique domain SID;
the stricter scoped continuity key has the separate admission policy below.
Absent values are JSON null, not the literal string `<NA>`. All role columns
are retained in sidecars; removal explanations also include the separate roles.
Original evidence, integer row IDs and tied timestamps remain unchanged.

Microsoft's [4624 field definitions](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
distinguish the reporting Subject from the New Logon account. The observed
Terminal Services 1149 records instead carry a username and domain in
`UserData/EventXML/Param1` and `Param2`; their System/Security service SID does
not identify that remote account. XML leaf extraction is generic, while YAML
restricts this interpretation to the RemoteConnectionManager provider and 1149.
Missing/malformed XML is not repaired by guessing identities from message text.

## Continuity and uncertainty

Continuity uses an observed target SID where available, otherwise a complete
domain-qualified authentication name. It still requires the evidence-image/host
scope. An unqualified 1149 username remains useful display evidence but does not
create a shared name-only travel baseline. A missing username stays unknown;
neither it nor an unrelated/missing provider can fall back to NETWORK SERVICE.
The null SID `S-1-0-0` does not provide a continuity identity.

SID and name-only observations are not automatically merged. There is no
nearest-event session association, cross-domain name lookup, synthetic SID,
or exact operator/IP attribution from an account association. This may leave
less continuity coverage where the source lacks a domain or SID, deliberately
avoiding a stronger identity claim than the evidence supports.

Creator and child keys remain distinct: creation/grant lifecycle sequences
retain their child key; removal/disable/delete activity uses the explicit
acting SID rather than the affected member's SID. The earlier bounded creator
risk, first qualifying PsExec use and additive **2 + 6** privileged removal
policy remain unchanged. This release adds no weights.

This distinction supports interpretable [Valid Accounts, T1078](https://attack.mitre.org/techniques/T1078/)
and [Account Access Removal, T1531](https://attack.mitre.org/techniques/T1531/)
evidence. Neither ATT&CK nor an identity match proves malicious intent or
prescribes the numerical score.

## Generic configuration mechanism

Normalisation `select_coalesce` has ordered `cases`, each with `field`, regex
`pattern`, and `fields`, plus explicit `default_fields`. The first matching
case owns the output, including a null result; it never falls through because
its values are missing. Empty field lists deliberately clear the value.
Outputs are recomputed on each pass, revoking stale aliases. Regex masks are
cached only within the current normalisation pass and invalidated if their
source is rewritten. There are no dataframe or nested-state defensive copies.

Tests exercise namespaces/entities, missing fields, wrong providers, same-name
different-domain users, SID precedence, creator/child preservation, additive
score reconciliation, tied rows and native sidecar readback. Real-evidence and
full production-profile validation receipts are separate from these tests.
