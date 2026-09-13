# Evidence calibration history and Windows candidate

This document records the v14/weights v13 calibration stage, not the current
CLI default; see the [current rules and weights](../rules/README.md). See
[remaining dataset improvements](DATASET_IMPROVEMENTS.md) for strict per-rule
metadata, execution/URI corrections, qualified malware-use and same-file web
context. The version-specific statements and scores below are historical;
v14 added the separately witnessed creation-to-download composite discussed
as future work in the earlier web-context section.

The earlier v11/v12 rule calibrations retained the scoring engine and its
performance optimisations. The new Windows candidate v13/weights v12 adds
generic identity/normalisation/sequence-witness and overlap mechanics, while
keeping detection policy in YAML. It does not change completed evidence
outputs. Prior configuration pairs remain available for explicit comparisons.
Numeric weights are expert-set development
choices, not probabilities or fitted estimates of maliciousness.

The [Windows scoring policy](WINDOWS_SCORING_DESIGN.md) documents the new
behaviour/identity/context rules, MITRE ATT&CK rationale, optional upstream
content/hash/transfer contracts and attribution limits. The historical numbers
below describe their stated earlier versions, not automatic rescoring.

## Required YARA resource

Supply the exact YARA corpus used during extraction with
`--yara-metadata-path /absolute/path/to/extraction-rules.yar`. Do not infer or
download a newer corpus merely to obtain matching names. Both its content hash
and parsed metadata participate in the referenced-file manifest source digest;
changed resources or policies invalidate stale manifests.

The v11 policy fails on missing or unparsable metadata. The runner resolves it
before reading the evidence dataset or creating output artefacts and rejects
an empty parsed index under that strict policy. The earlier v10 name-only
fallback remains available only when that configuration is explicitly selected.
Unindexed rule names still retain raw evidence but cannot become qualified web
identities by acquiring invented score/quality values.

The web qualification gate remains **score >= 75 and quality >= 70**. Restoring
metadata is not a promise that every hit qualifies. In the extraction corpus
examined during development, the PHP writer rule has score/quality 50/42,
generic PHP shell 70/0, MySQL shell 70/85, and Uploader 75/85. Only the last of
these passes both thresholds. Do not lower the gate merely to fit this case.

## Signal migration and weights

The internal executor roles and explanation rule IDs remain stable. These
emitted signal keys change in v11; consumers of named signals must use the
matching version. No duplicate scoring aliases are emitted.

| Original signal | Calibrated signal | Original weight | Current weight |
| --- | --- | ---: | ---: |
| `defacement_candidate` | `web_content_modification` | 8 | 3 |
| `mass_file_modification` | `file_modification_burst` | 10 | 4 |
| `ransomware_impact` | `ransomware_activity_candidate` | 9 | 9 |
| `yara_webshell` | unchanged | 9 | 4 |
| `web_malicious_file_access` | unchanged | 3 | 9 |
| `web_sensitive_file_download` | unchanged | 4 | 20 |
| `webshell_activity` | unchanged | 9 | 15 |

Other weights, the 50-point cap and neutral ATT&CK/taxonomy annotations remain
unchanged. Confidence remains explanatory metadata, not a numeric multiplier.
Relative to calibrated weights v9, only sensitive download (10 to 20) and
shell activity (9 to 15) change. The larger download weight prioritises an
observed successful transfer of a linked sensitive file. The smaller increase
for shell activity reflects its weaker, temporal evidence. It also raises
unrelated suspicious requests if they satisfy that same co-occurrence rule;
the weight does not repair or imply identity matching. Mere successful access
to a shell interface without this temporal signal does not gain these points.
Ordinary database filenames, raw shell hits, SQLi attempts and generic web
hints receive no additional weight in this revision.
The raw web-shell category can arise from weak or name-only YARA matches; more
weight now sits on qualified file-access evidence. That access branch includes
attempts: HTTP outcome remains separately visible and must not be inferred from
score alone. Successful sensitive download requires a linked Luhn-positive file,
GET and a successful response. Neither sensitivity nor a public client address
alone proves unauthorised exfiltration.

Web-content modifications remain positive even when no defacement is proved.
The burst counts modification-like timestamp **observations**, not distinct
files. Retaining both at lower weights preserves potentially useful downstream
evidence. Lowering the modification weight also lowers genuine defacement
artefacts; that trade-off must be evaluated rather than described as free.

## Contextual qualifications

Ransomware candidate sources now require a ransomware-extension burst or a
YARA/AV ransomware classification. A generic modification burst is no longer a
source. Earlier support accepts defense impairment, recovery inhibition or
suspicious LOLBin arguments, not the broad execution-family alias that could
match ordinary PHP package installation. Direct ransomware indicators remain
scored even when the contextual candidate does not fire.

The filename branch remains an explicitly qualified co-occurrence: a later
note-like filename does not establish note content or creation. The description
now says so. The web-shell temporal label likewise denotes artefact/request
co-occurrence, not exact identity; its confidence is medium. Qualified
identity-backed access and its separate outcome fields are the stronger route.

## Recent web-client and geographic context (rules v12)

This addition uses existing normalisation and generic temporal executors; the
Python engine is unchanged. All selectors, history lengths, emission anchors,
confidence labels and numerical weights are in the versioned YAML files.
The existing account-based login geography and impossible-travel policies are
unchanged. Anonymous visitors are not treated as a travelling account.

| Feature | Required evidence | Weight |
| --- | --- | ---: |
| `web_client_first_observed` | IP absent from the available six-hour web history | 0 |
| `web_country_first_observed` | Country absent from six-hour history with a preceding geographic observation | 0 |
| `web_asn_first_observed` | ASN absent from six-hour history with a preceding ASN observation | 0 |
| `web_recent_client_sensitive_download` | First-observed client and qualified successful public sensitive-file download within two hours | 8 |
| `web_recent_geo_sensitive_download` | That recent-client download also has country or ASN novelty within two hours | 3 total |

Country and ASN branches emit separate zero-point qualifiers. An existing
generic projection emits one maximum-strength scored signal, so both together
still contribute 3, not 6, with one scored explanation naming the qualifying
branches. No country is hard-coded as risky. Missing geographic
data prevents only the geographic corroboration. A new IP in an already-seen
country/ASN does not gain geographic points. Geographic novelty is relative to
this observed history, not a statistical rarity or an organisational allowlist.

Web history is grouped by the recorded host and web-log parser stream within
the evidence dataset. If host identity is absent, the parser stream is the
fallback scope; this assumes a single evidence asset and does not separate
unrecorded virtual hosts. The parser selector is itself YAML-owned. Empty
client addresses and non-web parsers cannot receive the client composite.

The download endpoint is already linked to a sensitive file by the existing
manifest machinery; its HTTP request must be a successful GET to a public
client. Failed requests, POSTs, ordinary files and private-client transfers do
not receive these new points. The temporal key is the same recorded client IP
and web asset/stream, not a claim of authenticated human identity; NAT/proxies
remain a limitation. Mere novelty and later unrelated requests stay unscored.

The two-hour age is anchored to the first-observed marker. Repeated activity
does not reset it. After absence from the six-hour history an address can be
marked again: this is explicitly **not lifetime first-ever observation**.
Boundaries are inclusive. Co-occurrence allows the very first request to be
a download; the six-hour history exceeds the two-hour follow-on window, so a
new marker cannot re-score an older download in that window.

For the earlier v12 policy, use 24h partition overlap with full preceding web traffic, not
only attacker traffic. The unchanged shipped IP-continuity policy already
enforces at least 24h in the partition runner. This covers the new 6h history
and nested 2h contextual windows. If changing or disabling policies, re-evaluate
that dependency coverage. The new v13 Windows policy increases the minimum to
174h; automatic overlap follows it and explicit insufficient overlap fails.
Direct dataframe callers must supply adequate context.

At the beginning of available evidence, previous history can be incomplete.
An initial client marker remains an explicitly low-confidence observation;
country/ASN first observations are suppressed without a preceding geographic
reference. This is not proof of a complete six-hour baseline or of prior
absence outside the supplied data. Do not present cropped-window results as
full-history novelty validation.

This addition links web-client/geo context to the transfer. It does **not** add
a new same-file creation-to-download rule or transfer another row's score onto
the download. Recent dump creation remains separately observable. Such a
future identity/recency composite must add distinct evidence, not duplicate
the Luhn-sensitive download or the present contextual points.

## Validation boundary

Focused tests cover input preflight, unknown/weak/qualified YARA, successful and
failed sensitive downloads, retention of ordinary file-modification evidence,
non-promotion of mass-only activity, preservation of ransomware-specific
context, unchanged integer keys and cap/neutral taxonomy. Existing v10/v8
regressions remain unchanged.

Real-evidence replays compare (1) original configuration with absent metadata,
(2) original with extraction metadata, and (3) candidate with extraction
metadata. They use bounded Ubuntu setup/attack, Case1 SQLi/shell and Windows
Petya-delivery windows. They are not full-history production reruns or final
pipeline validation: context is bounded, profiling is neutral, GeoIP/NSRL are
not replayed, and the Ubuntu attack replay selects actor HTTP plus non-HTTP
context. Ubuntu informed these changes and is not an independent hold-out.

The later web-context validation additionally compares the preceding calibrated
pair with v12/v11 using identical GeoIP inputs. The Ubuntu attack window must
include preceding all-client traffic to assess geography; the earlier
actor-filtered replay is not an adequate geographic baseline for this change.

Keep full-corpus regeneration and pipeline adoption separate from this local
candidate. In particular, the main Snakemake workflow still explicitly selects
v10/v8 and already passes the extraction YARA corpus; it is not changed here.
