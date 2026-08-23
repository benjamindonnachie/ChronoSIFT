# Rules, weights, and enrichment inputs

The two YAML files in this directory are the versioned ChronoSIFT v2.31 baseline:

Both files use a strict duplicate-rejecting YAML loader. Repeating a mapping
key at any depth fails engine construction instead of silently retaining the
last value, and each document must have a mapping at its root.

- `rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml` defines canonicalisation, normalisation, GeoIP enrichment outputs, atomic rules, temporal rules, the authoritative detector policy, behavioural continuity, schema aliases, and temporal-signal policy.
- `weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml` assigns each emitted signal a numeric contribution and defines the maximum event score.

Copy and version these files when tuning ChronoSIFT. A run is only reproducible when its engine version, rules, weights, overlap, and enrichment inputs are recorded together.

## Canonicalisation and normalisation

The mandatory top-level `canonicalisation` policy owns the preprocessing
judgement that used to be embedded in Python. Its global excluded-network list
and four complete definitions
configure Windows EVTX field aliases and authentication classifications, SSH
selectors and ordered regex patterns, pivot-destination source precedence, and
structured-first IP-recovery sources/context gating. Field names, parser
selectors and selector composition, event IDs, outcome/protocol values,
regexes, pattern provenance requirements, output names, parsed-output merge
precedence, prefixes, excluded networks, and precedence are all YAML-owned.
Windows and SSH extraction require `output_merge`: `preserve_existing` fills
only null, blank, or recognised-placeholder outputs, while `prefer_extracted`
overwrites only with a meaningful extracted value. The shipped policies use
`preserve_existing`. IP recovery may declare any
non-empty subset of the supported source mechanics. Invalid regexes, capture
groups, field-ID references, duplicate outputs, unknown keys, empty source
registries, and dangling references fail engine construction.

`normalisation` is a strict ordered list. Each entry must use exactly one of
`coalesce`, `regex_first`, `ipv4_first`, or `file_extension` with the
method-specific required keys. Output names are unique and regular expressions
are compiled and capture-group checked at startup. Python supplies XML, regex,
IP, coalescing, and path-extension mechanics only; it does not insert aliases,
fallback patterns, event classifications, or unknown-method placeholder
columns. Configured canonical and normalised outputs are retained in sidecar
mode even when they do not use a `chronosift_` prefix.

## GeoIP enrichment

The mandatory top-level `geoip_enrichment.outputs` mapping owns the six
derived column names for City geoname ID, city, country ISO code, latitude,
longitude, and ASN. The input key is not duplicated here: it is inherited from
`canonicalisation.ip_recovery.output_field`. All output names must be non-empty
and distinct, and they cannot overwrite canonical, normalised, or continuity-
result fields.

The `geographic_continuity` country, ASN, and city inputs and the
`impossible_travel` latitude, longitude, and country inputs must match these
outputs exactly. Engine construction rejects a mismatch even when the relevant
detector is disabled. Python retains MaxMind lookup and unique-IP join
mechanics only; renamed outputs are also retained explicitly in sidecar mode.
Geographic continuity also declares its history retention (`lifetime` or a
positive duration), novelty reference (`all_seen` or the previous
observation), first-observation output/emission choices, and country-boundary
reference. Impossible travel separately declares retained-versus-previous
reference selection, reference updates after rejected and qualifying
observations, and inclusive or exclusive distance/time/velocity comparisons.
IP-scope continuity owns the same boundary explicitly through retained or
previous-observation reference selection, configurable state-update timing,
open or closed lookback bounds, and ordered `all_matches` or `first_match`
transition evaluation. These settings govern carried actor state directly,
including across partition boundaries.

## Authoritative detector policy

The rules YAML contains a mandatory top-level `detector_policy` with
`version: 1` and `mode: authoritative`. Its `detectors` mapping must contain
complete definitions for thirty-five detectors:

| Detector ID | Stage | Typed executor |
|---|---|---|
| `clamav_classification` | atomic classification (phase 5) | `clamav_classifier` |
| `yara_classification` | atomic classification (phase 5) | `yara_classifier` |
| `web_request_classification` | atomic web classification (phase 5) | `web_request_classifier` |
| `canonical_authentication` | atomic canonical authentication (phase 5) | `canonical_authentication` |
| `execution_context_classifier` | atomic execution-context classification (phase 5) | `execution_context_classifier` |
| `file_lifecycle` | contextual file-lifecycle classification and windows (phase 15) | `file_lifecycle` |
| `mft_timestomping` | contextual MFT attribute correlation (phase 18) | `mft_timestomping` |
| `geographic_continuity` | temporal successful-auth geography continuity (phase 40) | `geographic_continuity` |
| `impossible_travel` | temporal distance/speed continuity (phase 40) | `impossible_travel` |
| `ip_scope_continuity` | temporal private/public and subnet continuity (phase 40) | `ip_scope_continuity` |
| `persistence_configuration` | contextual ordered persistence/configuration rules (phase 19) | `ordered_row_rules` |
| `repeated_scheduled_execution` | contextual grouped repetition window (phase 19) | `grouped_signal_window` |
| `systemd_service_persistence` | isolated contextual systemd semantics (phase 20) | `systemd_service_persistence` |
| `referenced_file_correlation` | contextual referenced-file correlation (phase 25) | `referenced_file_correlation` |
| `webshell_artifact` | contextual web-shell artefact classification (phase 27) | `webshell_artifact` |
| `direct_attack_semantics` | contextual ordered direct ATT&CK rules (phase 28) | `ordered_row_rules` |
| `contextual_signal_adjustments` | ordered reclassification and benign dampening (phase 35) | `ordered_signal_adjustments` |
| `download_to_execution` | temporal download-to-execution correlation | `signal_sequence_by_artifact` |
| `masquerading` | contextual signal gate | `signal_gate` |
| `automated_collection` | contextual grouped signal gate | `signal_gate` |
| `canonical_persistence_projection` | contextual canonical projection (phase 29) | `signal_projection` |
| `canonical_transfer_projection` | contextual canonical projection (phase 29) | `signal_projection` |
| `canonical_transfer_post_temporal_projection` | post-temporal canonical projection (phase 45) | `signal_projection` |
| `ransomware_impact` | temporal impact-context correlation | `temporal_context_branches` |
| `automated_exfiltration` | temporal counted-signal window | `counted_signal_window` |
| `credential_dump_collection` | temporal artifact follow-on correlation | `artifact_follow_on_sequence` |
| `password_store_exfil_chain` | temporal artifact follow-on correlation | `artifact_follow_on_sequence` |
| `webshell_activity` | temporal signal sequence | `signal_sequence` |
| `web_upload_execution_chain` | temporal signal sequence with target context | `signal_sequence` |
| `execution_lolbin` | atomic canonical alias | `signal_gate` |
| `execution_lolbin_suspicious_args` | atomic canonical alias | `signal_gate` |
| `execution_interpreter` | atomic canonical alias | `signal_gate` |
| `execution_scheduled` | atomic canonical alias | `signal_gate` |
| `execution_privileged_scheduled` | atomic canonical alias | `signal_gate` |
| `suspicious_execution` | atomic execution-family gate | `signal_gate` |

The YAML owns detector enablement, classification mappings, inputs,
projections, branches or sequence, bounds, emissions, suppression, evidence,
and confidence. Detector definitions deliberately have no `merge` key: typed
detector emissions are idempotently maximum-merged as an executor invariant,
while `rule_signal_merge` applies only to ordinary rules. The web-request
definition additionally owns raw and
materialised field names,
parser tokens, bounded decoding, attack patterns, upload methods, query-key and
filename admission, MIME pairing and mismatch fact branches, attempt promotion,
and ranked outcome selection,
SQLi baseline keys, sample admission, scope/lookback, statistic, threshold
formula/comparison, per-emission fact decisions, ordered exploit branches, and
all four emissions. The
referenced-file definition owns its source fields, document roots,
propagation, ordered identity branches, and ordered mapping registries. The
signal-bearing authentication, web-branch, ransomware, artefact-follow-on,
download, and generic sequence blocks each require a non-negative
`minimum_signal_value_exclusive`; source, support, and target roles are
independent and use a strict greater-than comparison. The shipped value `0`
preserves positive-signal admission. Ordered-row `signal_any_positive` and
`signal_all_positive` leaves likewise require their own finite non-negative
`minimum_value_exclusive`; “positive” is the operator name, not an implicit
zero boundary. Every matching `ordered_row_rules` item is retained in explain
output even when multiple items share one emission. The canonical emission
`rule_id` is accompanied by the unique `detector_rule_id` from
`ordered_rules[].id`. The
web-shell artefact definition owns its path/text fields, web-root and script
extension references, support tokens and signals, threshold, emission, and
evidence. Canonical authentication owns its field bindings, success/failure
sources and outcome labels, remote/logon/message/package vocabularies, lateral
threshold, mandatory `all`/`any`/`none` eligibility gate, thirteen emission
roles, and evidence. The shipped eligibility admits a row after conflict
resolution when either success or failure is true. Execution-context
classification owns ordered path/command/actor fields, path and command-name
vocabularies, system-binary and privileged-actor names, SUID regex, ten
emission roles, and evidence. The former fixed execution classification and
emission tables have been removed from Python. File lifecycle owns its fields,
ordered timestamp-kind taxonomy, path and extension classifications, a
mandatory registry of named `all`/`any`/`none` predicates over typed base facts,
row and window decisions, weight-aware conditions, three windows and their
thresholds, eleven emission roles, and per-role evidence. Row decisions may
reference base or derived facts; short-lived clauses use `source_`/`target_`
facts, while mass-modification and ransomware-burst clauses use unprefixed
facts. MFT timestomping owns its fields,
parser/creation/attribute tokens, minimum delta, path exclusions,
parent-directory bulk threshold, emission metadata, and targeted/bulk
explanation branches. `persistence_configuration` owns ordered path,
registry, event, and message predicates and their nine persistence/configuration
emissions. `repeated_scheduled_execution` owns its source signals,
host/command key, message extraction, closed lookback, count threshold,
per-key emission limit, and evidence. `direct_attack_semantics` owns every
remaining non-systemd direct branch, including field resolution,
timestamp-kind classification, literals, regexes, event IDs, signal
conditions, ordered precedence, fifteen emissions, confidence, and evidence.
The shipped SMB ordering treats explicit 5140/5145 administrative-share or
remote named-pipe evidence as authoritative: the fallback
`smb_network_logon_inference` is excluded on those rows. Genuine IPC$/ADMIN$
activity still emits both the explicit `smb_admin_share` and
`external_remote_service` signals; a named pipe over a non-admin share emits
only `external_remote_service` unless independent SMB evidence exists.
`contextual_signal_adjustments` owns discovery reclassification and benign
administrative-query/backup dampening, including its configured inputs,
predicates, target signals, zeroing action, descriptions, confidence, and
evidence. The three continuity definitions own their key/evidence fields,
success sources, bounds, transition logic, output columns, emissions, and
explanation metadata; Python retains state traversal and geo/network math.
Systemd unit artefacts and command semantics remain isolated in the
specialised phase-20 executor. Its command, message, host, path, and timestamp
explain values are bound by its own evidence resolvers rather than Python field
names. The four required
temporal-composite definitions own their source, support, count, and follow-on
signal sets; closed lookbacks; threshold or branch semantics; artifact fields,
label/copy vocabularies, and follow-on qualification; emissions; and evidence.
`follow_on_qualification.any` is an OR of non-empty `all` clauses over the four
typed copy/text/signal/follow-on facts, so Python does not impose that Boolean
topology. Generic temporal rules must declare `lookback_lower_bound`, a
mode-specific `emit_on` anchor, and condition-mode empty-value, first-observation,
and reference-selection behavior. Condition state is bounded by the lookback;
first-observation behavior applies whenever no reference remains in the active
window. The shipped policy includes the exact lower bound, emits on sequence
completion/current co-occurrence/condition match, ignores empty condition
values, suppresses the first change observation, and compares with the latest
surviving observation. Co-occurrences cannot spill onto
unrelated rows after the window becomes satisfied. A counted window lists which
current-row roles may receive its output; the shipped policy permits counted or
current-support rows. Generic temporal rules and counted windows also own their
exclusive signal-admission thresholds. The
three canonical projections own their row-local source/output
mappings, `any`/`all` thresholds, maximum-matched strength scaling, stages,
emission metadata, and matched-signal evidence. Python owns executor mechanics:
ClamAV/YARA grammar, canonical request/path/hash handling, identity merging,
field derivation, efficient candidate evaluation, timestamp/window lookup,
label intersection, and sparse emission. The shipped ClamAV definition contains
27 category-token keys and 28 ordered family-substring overrides; the YARA
definition owns ordered metadata/name classification, strength, category
outputs, and referenced-file qualification. See the complete definitions in
the shipped rules YAML and the
[rule-language documentation](../docs/RULE_LANGUAGE.md).
Every best-effort path resolver declares its ordered `fields`; there is no
runtime default path-field list.

Additional detector IDs may use only the reusable `signal_gate`,
`signal_sequence`, or `signal_projection` executors without a corresponding
Python policy branch. `ordered_row_rules`, `ordered_signal_adjustments`, and
`grouped_signal_window` are reusable implementations bound to required
baseline definitions and fixed schedule points; additional IDs selecting them
are rejected. Signal
gates may run in the `atomic` or `contextual` stage; projections may run in the
`contextual` or `temporal` stage. Inputs must have a known producer available
before that executor runs: policy outputs may feed a strictly later phase, but
same-phase and later-to-earlier dependencies are rejected rather than relying
on YAML mapping order. Web, canonical-authentication, execution-context,
ClamAV, and YARA classification run at phase 5 after ordinary atomic rules and
before atomic gates at phase 10; same-phase classifier dependencies are not
permitted. File lifecycle runs at phase 15 and MFT timestomping at phase 18.
Persistence ordering and repeated-schedule grouping run at phase 19, followed
by isolated specialised systemd persistence at phase 20. Referenced-file
correlation runs at phase 25, web-shell artefact classification at phase 27,
direct ATT&CK semantics at phase 28, contextual projections at phase 29,
contextual gates at phase 30, ordered contextual adjustments at phase 35,
bounded temporal executors at phase 40, and post-temporal projections at phase
45. Trust dampening then runs over the complete signal set, including temporal
and geo outputs; the validated hour-of-week factor applies once to the resulting
event score.
The required persistence, repeated-schedule, direct-semantics, and adjustment
definitions are fixed schedule assertions at phases 19, 19, 28, and 35;
changing those values is rejected rather than rescheduling Python execution.

The mandatory top-level `rule_signal_merge` mapping independently selects
`maximum` or `sum` for ordinary atomic-rule and temporal-rule emission
collisions. The shipped bundle selects `maximum` for both, and all atomic
evaluation paths use the same configured choice.

This is a strict contract. Missing the section or any required detector,
using an unknown key or executor, or supplying a value of the wrong type fails
engine construction. Set `enabled: false` on a complete detector definition to
disable that detector; removing it is not a disable mechanism. The two atomic
definitions, `canonical_authentication` and
`execution_context_classifier`, are mandatory specialised contracts. The
legacy `engine_config.canonical_auth_signals` key is rejected rather than
merged with them. Their mandatory per-emission `all`/`any`/`none` fact
decisions own the truth tables; Python only extracts facts and evaluates the
generic decision form. `file_lifecycle` and `mft_timestomping` are likewise
mandatory complete definitions even when disabled. The obsolete lifecycle
keys under `engine_config.detection_thresholds` are rejected; effective
row-emission truth tables, window source/eligible kinds, grouping, admission
clauses, bounds, threshold comparisons, emission limits, lookbacks, and
thresholds live under `detector_policy.detectors.file_lifecycle`.
The shared `engine_config.path_taxonomy`, `detection_vocabulary`,
`detection_event_ids`, and `detection_thresholds` sections are all obsolete
and rejected. Web-shell and systemd path/extension values are declared
directly in their owning definitions rather than through `*_from` references.
Systemd also declares branch order, first/all-match mode, and OR-of-AND fact
clauses for artefact and command activity.
`engine_config.schema_aliases` and `engine_config.temporal_signal_policy`
contain only the entries present in YAML; Python contributes no default aliases
or ineligible signals.

The top-level `profiling.hour_of_week`, `engine_config.trust_dampening`, and the
weights document are strict contracts too. Profile selection, predictive
validation, uncertainty handling, optional activity-deficit/quiet emission flags,
mandatory signal/value/merge bindings, NSRL exclusion composition, trust
selector composition/reason order, explanation metadata, signal weights, and
the score cap must be present and correctly typed; unknown or colliding names
fail startup.

The shipped hour-of-week policy retains the 100-event safety floor. It first
tries the filtered host-resident activity set, then the full dataset if the
filtered set is too small or fails validation. Only non-boundary calendar weeks
are validation blocks. Each week is held out in turn; the remaining weeks fit a
Laplace-smoothed 168-bin distribution, and mean held-out log-score improvement
is measured against the uniform `1/168` reference. A deterministic whole-week
bootstrap must put the configured one-sided lower confidence bound above zero.
The required `amplification_gate` then requires at least one hour whose
simultaneous upper probability bound lies below the uniform reference. Too few
events, too few complete weeks, a non-positive log-score bound, or no
confidently low-activity hour rejects the profile; rejection after fallback is
neutral and cannot alter scoring. This final gate prevents a statistically
predictive but operationally inert profile from stopping the configured
filtered-to-full-dataset fallback.

`confidence_level` must be greater than `0.5` and less than `1`.
`bootstrap_resamples` must be at least 100 and must provide at least five
expected resamples in each confidence tail. The shipped `0.95` confidence and
2,000-resample settings satisfy both guards; experiments that change them must
record the complete rules file with their results.

For an accepted profile, a simultaneous bootstrap upper probability band makes
the activity deficit conservative:

`deficit(h) = max(0, 1 - p_upper(h) / (1/168))`

`multiplier(h) = 1 + deficit(h)`

The factor is therefore derived from the dataset and bounded to `[1, 2]`. It is
applied once to the complete post-trust event score and then subjected to
`max_event_score`; it neither changes individual signal values nor creates a
score for an otherwise unscored event. The former family-specific `k`
coefficients and `profile_multipliers` section have been removed. The shipped
optional `out_of_hours_activity_deficit` and `quiet_time_event` sparse
emissions remain disabled;
quiet-quantile membership is annotation-only and does not gate amplification.
The dataset manifest records probabilities, simultaneous upper bounds,
per-hour factors, weekly log-score improvements, bootstrap settings, selection
and fallback history. Its `validation` object explicitly reports
`amplifiable_hour_count` and `simultaneous_upper_radius`, while
`validation_attempts` retains rejected filtered-selection attempts. Partition
reports and JSONL telemetry include a compact validation summary;
`profile_manifest_path` persists the full manifest.
The factor is intentionally conservative and becomes less attenuated as the
profile's effective event volume increases. It is therefore a within-dataset
prioritisation factor rather than a directly comparable cross-dataset
measurement. “Out of hours” denotes dataset-relative off-peak bins and may
cover much more than the optional tenth-quantile quiet annotation.

Partition `overlap` must cover the longest lookback of every enabled temporal
policy definition.

## Optional local inputs

Large or independently licensed resources are not committed. Pass their paths on the command line.

| Input | Required fields or format | Purpose |
|---|---|---|
| YARA Forge metadata | A YARA Forge `.yar` bundle | Category and quality metadata for rule matches already present in the timeline |
| ClamAV CSV | `sha256,av_signature,av_hit,av_product` | Hash-indexed AV enrichment and signature-family categorisation |
| Luhn CSV | `sha256,luhn_hit` | Hash-indexed structured-number findings |
| NSRL Parquet | SHA-256 plus an application-type field | Known-file enrichment and baseline noise reduction; convert the NSRL RDS source before use |
| GeoLite2 City | MaxMind City `.mmdb` | City, country, coordinates, and travel distance |
| GeoLite2 ASN | MaxMind ASN `.mmdb` | ASN and organisation continuity |

The engine consumes these results but does not perform YARA, ClamAV, Luhn, or NSRL acquisition/scanning itself. The original NSRL RDS distribution is not accepted directly; it must first be converted to the Parquet lookup schema above. Keep source versions, hashes, conversion details, and acquisition dates with research outputs. All external inputs remain subject to their respective licences and terms.

The YARA corpus path and missing/unindexed behaviour live under
`detector_policy.detectors.yara_classification.metadata`; the CLI path is a
run-specific override. The same definition owns the score/quality/category
gate used for web aliases and SHA-256 upload correlation. See the
[YARA classification reference](../docs/YARA_ENRICHMENT.md).

Referenced-file manifests use schema v7 and record
`clamav_policy_digest`, `yara_policy_digest`, `correlation_policy_digest`, and
`source_digest`. Partitioned processing rebuilds a manifest when its schema or
any expected digest differs, so changing correlation fields, matching,
emissions, web branches, or mappings cannot silently reuse stale derived
identity or aliases.
