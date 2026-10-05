# Authentication context: rules v27 / weights v23

ChronoSIFT remains a pipeline triage stage, not a compromised-account verdict.
This revision reuses existing successful SID/IP history, account-scoped geographic
continuity, impossible travel and source-linked failure/success signals. It adds
no trusted-IP list, country ranking, dataset exception or parallel user database.
Historical YAML and completed sidecars are unchanged.

## Evidence and contribution families

| Evidence | V27 contribution and boundary |
|---|---|
| Ordinary privileged, remote or NTLM authentication | Zero for `privileged_login`, `lateral_movement_indicator` and `external_remote_service`; descriptive signals and temporal consumers remain. |
| Newly observed Windows source | Existing seven-day successful SID/IP history, 2 points at first observation. Incomplete history is not evidence of a truly new operator. |
| Privileged execution | Existing 5 points, but a source-qualified execution path or command is now required. Account names, logons and credential events alone are insufficient. |
| SMB | Network-logon inference becomes zero-weight `smb_network_logon_candidate`. Actual share-path/event evidence retains `smb_admin_share` and its 3 points. |
| Credential material | NTLM alone no longer emits `alternate_auth_material`. Explicit-credential/NewCredentials observations retain their low-weight candidate. |
| Source-linked failures followed by success | Account-and-source and source-only findings contribute one 2-point context family, not 8+6 for the same underlying observations. |
| First failure/success episode | An additional 6 points, using the existing first-seen temporal executor, scoped by `continuity_key` and source IP over 6 hours. Repeated successes within that observation history retain 2, not the full initial bonus. |
| Country/ASN/city novelty | One 4-point family, excluded when impossible travel supplies the stronger geographic interpretation. No country is intrinsically suspicious. |
| Corroborated impossible travel | 8 points when successful remote authentication also has source/geographic novelty or a fresh source-linked failure/success episode. Familiar-source return alone retains raw travel evidence without this score. |
| Failure/success episode plus impossible travel | Additional 20 points for the conjunction; administrative privilege adds 4 here, not to every ordinary login. |

For binary inputs, a novel-source privileged takeover candidate normally totals
42 (2 novelty + 2 failure context + 6 episode + 8 travel + 20 conjunction + 4
privilege), before independent behaviour or trust/profile processing. A known
source with fresh failures and impossible travel can still score 40. These are
configured triage weights, not probabilities or MITRE-assigned severity values.

ATT&CK rationale: source-linked failure/success supports a
[T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) candidate; the
combined access context supports possible
[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) abuse.
Neither a normal successful logon nor an ATT&CK label establishes adversarial use.
Underlying explanations retain their outcome, source and confidence limits.

## Existing history, not trust promotion

`WINDOWS_ACCOUNT_NEW_SOURCE` already records successful source novelty; it is not
rebuilt here. The failure episode uses that same generic temporal infrastructure,
but its observations must already carry a source-linked failure/success signal.
Its six-hour rolling observation horizon is explicit: renewed positive observations
can maintain an episode until six hours without such observations. A later burst
can reopen it. Failed guesses alone do not admit an IP to successful-login history.
Known-source status never suppresses direct malicious behaviour.

Raw impossible travel still uses the existing retained-reference policy and GeoIP
snapshot. We do not silently reinterpret its country, suppress its evidence or
claim a perfect trusted-location model. The new scoring gate avoids automatically
penalising an established source returning after an anomalous one; unknown
baseline, VPN/shared-account ambiguity and missing locations remain limitations.

Existing new-source/action, creator-risk and newly privileged-account relationships
remain available for sensitive follow-on actions, even when routine authentication
scores drop. They retain their existing scope, time and attribution limits.

## Compatibility, performance and validation

Policies, weights and the CLI defaults advance together. Python adds only a
qualified-execution fact and optional row-local `all_of_any`/`none` projection gates.
Thresholds, keys, windows, emitted labels, weights and ATT&CK rationale remain in
YAML. Historical policies omit the new gates and preserve their behaviour.
No defensive frame copies, larger raw overlap, live lookups or new engine pass
are introduced. The episode uses existing compact temporal history.

Tests cover normal/repeated/new-source logins, a known source with new suspicious
evidence, unrelated attack failures, duplicate timestamps with distinct row IDs,
episode expiry, missing geography, actual execution/share evidence, gate schema
and dependencies, explanation accounting, and native compact/expanded month-boundary
parity. Native replay receipts state their selected scope: a bounded replay is not
a new full-corpus ground-truth assessment. Downstream dDCA/plots require new inputs
to reflect changed scores; this revision does not overwrite them or change the
surrounding pipeline's published-revision pin.
