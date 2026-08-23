# ChronoSIFT -- Rule Language and Detector Policy

This document describes the executable configuration accepted by ChronoSIFT.
The shipped [v2.31 rules](../rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml)
are the complete baseline and the reference for fields specific to an individual
detector.

## Purpose

ChronoSIFT uses YAML for ordinary rules and for detectors that have been moved
onto the typed policy surface. The configuration has three rule surfaces:

- `rules` contains atomic rules evaluated on one timeline event;
- `temporal_rules` contains generic correlations over multiple events; and
- the top-level `detector_policy` contains typed atomic, contextual, or
  temporal detectors whose execution needs reusable gates, derived fields, or
  specialised state.

The language is designed to be:

-   deterministic
-   explainable
-   tolerant of missing fields
-   easy to audit

Rules and detectors emit **signals**, which are later combined into behavioural
scores. For these three surfaces, YAML owns the declared policy and Python owns
the reusable executor mechanics needed to evaluate it efficiently. The shipped
thirty-five-detector registry is authoritative: incomplete policy fails startup
instead of falling back to code-owned detector judgement.
Rules and weights are loaded with duplicate-key rejection at every mapping
depth. Repeating a key is an error rather than silently replacing its earlier
value; both documents must also have a mapping at their top level.

------------------------------------------------------------------------

## Rule types

ChronoSIFT supports two generic rule categories:

1.  **Atomic rules** -- operate on a single event
2.  **Temporal rules** -- operate on multiple events within a time
    window

------------------------------------------------------------------------

## Atomic rules

Atomic rules evaluate conditions on a single row of the timeline.

### Runnable example

This is the `CRON_EXEC_LINUX` rule from the shipped YAML. It uses the actual
`scheduled_exec` signal.

```yaml
rules:
- id: CRON_EXEC_LINUX
  description: Cron or scheduled command execution observed
  priority: 78
  scope:
    any: []
    all:
    - field: parser
      op: in_ci
      value: [systemd_journal, syslog, text/syslog_traditional]
  when:
    any: []
    all:
    - field: message
      op: contains_ci
      value: cron
    - field: message
      op: contains
      value: 'CMD ('
  emit:
    signals:
    - name: scheduled_exec
      value: 1
    evidence:
    - field: message
    - field: parser
    - field: actor_user
  confidence: medium
```

------------------------------------------------------------------------

### Atomic rule structure

| Field | Description |
|---|---|
| `id` | Unique rule identifier. Do not use the obsolete `rule_id` spelling in YAML. |
| `description` | Human-readable explanation. |
| `priority` | Evaluation ordering; higher values are parsed first. |
| `scope.any` / `scope.all` | Required lists of source or event scope conditions; either list may be empty. |
| `when.any` / `when.all` | Conditions that determine whether the in-scope row matches. |
| `emit.signals` | Signal names and values produced when the rule fires. |
| `emit.evidence` | Timeline fields copied into the explanation. |
| `confidence` | Required explanation confidence: `low`, `medium`, or `high`. |

For each nested block, a non-empty `any` list requires at least one matching
condition and a non-empty `all` list requires every condition to match. An
empty list adds no requirement. `scope_any`, `scope_all`, `when_any`, and
`when_all` are not valid top-level spellings.

------------------------------------------------------------------------

## Conditions

Conditions evaluate a field using an operator.

### Structure

```yaml
- field: username
  op: eq
  value: administrator
```

------------------------------------------------------------------------

### Supported operators

  Operator      Meaning
  ------------- -----------------------------
  exists        field contains a value
  eq            equals
  in            value in list
  in_ci         case-insensitive membership
  contains      substring
  contains_ci   case-insensitive substring
  regex         regular expression
  lt            numeric less-than
  lte           numeric less-or-equal
  gt            numeric greater-than
  gte           numeric greater-or-equal

Operators are **missing-safe**.

If a field is absent or null, the condition evaluates to False.

------------------------------------------------------------------------

## Emit section

Rules emit signals.

Example:

```yaml
emit:
  signals:
  - name: scheduled_exec
    value: 1
```

Signals may be numeric or metadata.

Numeric signals contribute to the final score.

`rule_signal_merge` is a mandatory top-level policy for collisions between
ordinary rule emissions:

```yaml
rule_signal_merge:
  atomic_rules: maximum
  temporal_rules: maximum
```

Each role accepts `maximum` or `sum`. `maximum` retains the strongest value
when more than one ordinary rule emits the same signal on a row; `sum` adds
the configured values. The same policy is used by vectorised and fallback
atomic evaluation and by temporal emission. The shipped configuration uses
`maximum` for both roles.

------------------------------------------------------------------------

## Temporal rules

Temporal rules detect patterns across multiple events.

### Runnable sequence example

This is the shipped `FAIL_THEN_SUCCESS_USER` rule. Both input signals are
produced by the configured phase-5 `canonical_authentication` executor, and the
output signal is present in the shipped weights file.

```yaml
temporal_rules:
- id: FAIL_THEN_SUCCESS_USER
  description: Repeated remote authentication failures followed by remote success for same principal within lookback
  priority: 80
  key_by:
  - actor_principal
  lookback: 6h
  lookback_lower_bound: inclusive
  emit_on: sequence_completion
  minimum_signal_value_exclusive: 0
  sequence:
  - signal: auth_remote_failure
    min_count: 3
  - signal: auth_remote_success
    min_count: 1
  emit:
    signals:
    - name: fail_then_success_user
      value: 1
  confidence: medium
```

------------------------------------------------------------------------

### Temporal rule structure

| Field | Description |
|---|---|
| `id` | Unique temporal rule identifier. |
| `description` | Human-readable explanation. |
| `priority` | Evaluation ordering. |
| `key_by` | Non-empty list of fields used to group related events. |
| `lookback` | Sliding window such as `10m`, `6h`, `30d`, or `1w`. |
| `lookback_lower_bound` | Mandatory `inclusive` or `exclusive` treatment of an observation exactly `lookback` before the current input. |
| `emit_on` | Mandatory mode-specific anchor. Sequences allow `sequence_completion` or `sequence_start`; co-occurrences allow `current_input` or `window_start`; first-seen conditions use `condition_match`; change conditions allow `condition_match` or `reference_observation`. |
| `minimum_signal_value_exclusive` | Mandatory non-negative admission threshold shared by every configured input signal; a value must be strictly greater. |
| `sequence` | Ordered signal requirements. |
| `cooccur.all` | Signal requirements that may occur in any order. |
| `condition.kind` / `condition.field` | Value-state rule: `first_seen_value` or `change_detected`, and the field to observe. |
| `condition.empty_value_behavior` | Mandatory `ignore` or `observe` treatment of normalised empty/placeholder values. |
| `condition.first_observation_behavior` | Mandatory `emit` or `suppress` behavior when no in-window reference exists. |
| `condition.reference_selection` | Mandatory `rolling_window` or `previous_observation` for first-seen rules; mandatory `previous_observation` or `window_start` for change rules. |
| `emit.signals` | Signals produced on the matching event. |
| `confidence` | Mandatory explanation confidence. |

Temporal mode is inferred from exactly one of `sequence`, `cooccur`, or
`condition`. Do not add a top-level `mode`, `cooccur_all`, or `field`. Numeric
emission collisions follow `rule_signal_merge.temporal_rules`; there is no
additional hidden saturation rule. The configured maximum event score remains
the final score bound. Emission placement follows `emit_on`: a sequence may
mark its first or completion input, a co-occurrence may mark the earliest active
input or current completing input, and a change may mark its selected reference
or matching observation. Later unrelated rows never inherit a still-satisfied
temporal window. `lookback_lower_bound: inclusive` preserves an observation at
exactly the lookback duration; `exclusive` evicts it before evaluation.
Condition state is bounded by this same window, so
`first_observation_behavior` applies whenever no reference remains, not only to
the lifetime-first row. `reference_observation` is valid only for
`change_detected` when first observations are suppressed.

------------------------------------------------------------------------

### Temporal forms

#### `sequence`

Signals must appear in order within the lookback window.

For the runnable example above:

    auth_remote_failure x3 -> auth_remote_success

------------------------------------------------------------------------

#### `cooccur.all`

Signals must occur within the window regardless of order.

```yaml
temporal_rules:
- id: CROSS_BORDER_TRANSFER
  description: Transfer tooling coincident with boundary crossing within lookback (canonical principal keyed)
  priority: 60
  key_by: [actor_principal]
  lookback: 6h
  lookback_lower_bound: inclusive
  emit_on: current_input
  minimum_signal_value_exclusive: 0
  cooccur:
    all:
    - signal: transfer_execution
      min_count: 1
    - signal: boundary_crossing
      min_count: 1
  emit:
    signals:
    - name: cross_border_transfer
      value: 1
  confidence: medium
```

------------------------------------------------------------------------

#### `condition.kind`

`first_seen_value` with `reference_selection: rolling_window` triggers when the
current value is absent from the active lookback; `previous_observation` treats
a value as new when it differs from the latest surviving observation.
`change_detected` compares with either that latest surviving observation or the
first observation still in the window. Empty and first observations follow their
explicit behavior fields. The shipped configuration ignores empty values,
suppresses the first observation, and uses the immediately previous reference:

```yaml
temporal_rules:
- id: AUTH_PIVOT_ACCOUNTS_FROM_SAME_SRC
  description: Remote authentication source changed principal within lookback
  priority: 72
  key_by: [src_ip]
  lookback: 6h
  lookback_lower_bound: inclusive
  emit_on: condition_match
  minimum_signal_value_exclusive: 0
  condition:
    kind: change_detected
    field: actor_principal
    empty_value_behavior: ignore
    first_observation_behavior: suppress
    reference_selection: previous_observation
  emit:
    signals:
    - name: auth_pivot_accounts_from_same_src
      value: 1
  confidence: medium
```

------------------------------------------------------------------------

## Engine configuration without rule defaults

`engine_config.schema_aliases` maps a canonical field name to an ordered list
of source aliases applied during normalisation. Both canonical and alias names
must be valid lowercase identifiers, and a field cannot alias itself. The
mapping is entirely configuration-owned: Python does not insert a historical
alias list, and the required section must be present even when its mapping is
empty.

`engine_config.temporal_signal_policy` requires `ineligible_signals`, the
signals excluded from temporal evaluation. Every name must have a declared
producer; enabled profiling emissions must be included because profiling is
not a temporal-rule input, and a temporal rule that consumes an ineligible
signal is rejected. The list is config-only.

### Hour-of-week profiling and trust dampening

`profiling.hour_of_week` is a complete typed policy for profile selection,
smoothing, quiet-hour annotation, the minimum sample floor, predictive
validation, uncertainty estimation, insufficient-profile behaviour,
parser/filename/NSRL filters, derived fields, optional sparse emissions, and the
event-score amplifier. Enabled profile emissions enter the ordinary signal map
during the atomic stage before scoring. The shipped policy leaves both sparse
emissions disabled and unweighted; the dense `out_of_hours_activity_deficit` column carries the
validated activity deficit used by final scoring.
If either optional emission is enabled, its signal must have an explicit weight
entry, including when the intended weight is zero. Missing weights fail engine
construction independently of `engine_config.config_validation.strict`,
matching the detector-policy emission contract.

The `min_profile_events` floor is evaluated before statistical validation. The
filtered host-resident set is attempted first. The shipped
`insufficient_filtered_events: empty_profile` action maps every event to the
neutral multiplier `1` when that selection has too few events or is not
validated. `full_dataset` is a selectable alternative for a deliberately
different experiment. It removes all parser, filename, and NSRL selection
filters, so its profile can describe automated timeline production rather than
the filtered host-resident activity.

`validation.method: leave_one_calendar_week_out_log_score` uses only complete,
non-boundary calendar weeks. For each held-out week, the other weeks fit a
Laplace-smoothed 168-bin distribution and calculate the held-out mean log-score
improvement over `validation.reference: uniform_hour_of_week` (`1/168`). A
deterministic bootstrap resamples whole weeks. The profile is accepted only
when its configured one-sided lower confidence bound is greater than zero and
`amplification_gate: require_positive_activity_deficit` is satisfied after
uncertainty-band construction. The gate requires at least one hour whose upper
probability bound is below the uniform reference. A predictively non-uniform
profile that cannot identify any such hour is rejected. Under the shipped
fail-closed action it remains neutral rather than substituting a profile with a
different estimand.
`minimum_complete_weeks`, `confidence_level`, `bootstrap_resamples`, and
`random_seed` make this inferential contract reproducible rather than silently
engine-defined. Validation requires `0.5 < confidence_level < 1` so the named
lower confidence bound is drawn from the lower half of the bootstrap
distribution. It also requires at least 100 bootstrap resamples and at least
five expected resamples in each confidence tail:
`bootstrap_resamples >= ceil(5 / (1 - confidence_level))`. These are numerical
sanity guards, not evidence that the shipped 2,000-resample setting is optimal;
record and justify any changed setting in experimental provenance.

The comparison uses logarithmic score because it is a strictly proper
probabilistic scoring rule (Gneiting and Raftery, 2007,
[JASA paper](https://sites.stat.washington.edu/people/raftery/Research/PDF/Gneiting2007jasa.pdf)).
Bootstrap units are whole weeks, rather than individual events, to preserve
within-week dependence; this follows the block-bootstrap principle for
dependent observations (Künsch, 1989,
[DOI](https://doi.org/10.1214/aos/1176347265)).

For an accepted profile,
`uncertainty_band: simultaneous_bootstrap_upper_probability` provides
`p_upper(h)`. The configured amplifier method is mechanically fixed as:

```text
activity_deficit(h) = max(0, 1 - p_upper(h) / (1/168))
multiplier(h)       = 1 + activity_deficit(h)
```

The resulting factor is in `[1, 2]`. With
`scope: post_trust_event_score`, it is applied once to the complete weighted
event score after trust dampening and before the ordinary `max_event_score`
cap. It does not mutate signal values, compound across signal families, damp
in-hours scores, or create score from a zero-score event. An explanation is
emitted only for a scored event whose factor exceeds one. It records the
observed and upper-bound probability, uniform reference, deficit, factor, and
validation statistics. The former `profile_multipliers` list and all
family-specific `k` coefficients are intentionally unsupported.

The persisted profile manifest exposes whether the method was operationally
active as well as statistically predictive. Its `validation` object includes
`amplifiable_hour_count` and `simultaneous_upper_radius`; per-hour
`probabilities`, `upper_probability_bounds`, `activity_deficits`, and
`amplifiers` describe the accepted profile. The dataset-wide builder's
`validation_attempts` preserves a rejected filtered-selection outcome before
the configured insufficient-profile action is resolved.

Here “out of hours” means hours whose conservative dataset-relative activity
probability lies below the uniform reference. It is an off-peak measure, not a
rare-event label, and a strongly patterned office-hours system may classify a
large part of the week as off peak. The simultaneous band narrows as retained
event volume and the number of informative complete weeks increase. Two
datasets with the same underlying hourly proportions can therefore receive
different factors: greater evidence permits stronger amplification. Factors
are suitable for within-dataset prioritisation but are not directly comparable
measurements across datasets unless event counts, week coverage, validation
statistics, and the complete profile manifest are considered together.
Do not combine filtered and `fallback_full_dataset` profiles in one result
series. Tables reporting the factor must include `selection_mode`, source and
selected event counts, validation status/reason, complete-week count,
`amplifiable_hour_count`, and `simultaneous_upper_radius`.

Quiet-quantile membership controls only the optional `quiet_time_event`
annotation and never gates the amplifier. Configured NSRL application-type
tokens also govern derivation of `nsrl_is_os_component` when the lookup does not
already assert that boolean; its two configured NSRL field names are the
enrichment targets as well as the profiling inputs. `nsrl_exclusion_combine`
selects combined application-type/component exclusion or component-field
precedence identically for in-memory and DuckDB profiles. The DuckDB cache
itself is policy-neutral.

`engine_config.trust_dampening` requires its enablement, multiplier, principal/
IP/ASN fields, signal targets, trusted literal and regex selectors, and
explanation metadata. `selector_match` declares `any` or `all` composition over
the non-empty selector groups, while `reason_precedence` orders the explanation
reason when multiple groups match. An enabled policy must have at least one selector. It
runs after profiling over the complete signal map. `config_validation` also
requires explicit `enabled`, `strict`, and `notes` fields.

The former shared rule-logic sections `engine_config.path_taxonomy`,
`detection_vocabulary`, `detection_event_ids`, and `detection_thresholds` are
not part of the accepted schema. Engine construction rejects them and directs
each value to its owning `detector_policy` definition. In-policy path,
extension, token, event-ID, timestamp-kind, window, and threshold values are
therefore reviewable at the branch that consumes them.

------------------------------------------------------------------------

## Canonicalisation and normalisation policy

`canonicalisation` is a mandatory top-level mapping with a global
`excluded_networks` registry and four complete typed definitions:

| Definition | Configuration-owned semantics |
|---|---|
| `windows_authentication` | Parser/XML selectors, placeholder values, ordered EVTX field IDs/aliases/system sources, client-address precedence, event-ID outcomes, per-protocol `any`/`all` logon/event matching, first/last branch selection, configured remote-direction qualification, output fields, and parsed-output merge precedence. |
| `ssh_authentication` | Parser/message selectors and their `any`/`all` composition, escaped-control cleanup regex, semantic output/value bindings, ordered accepted/failed/invalid-user/session regexes with explicit capture-group bindings and per-pattern message-provenance requirements, and parsed-output merge precedence. |
| `pivot_destination` | IP/FQDN/hostname output fields, ordered sources, identity precedence/prefixes, and the fields that qualify an authentication-like row. |
| `ip_recovery` | Output/parser fields, Windows parser prefixes, network-context regex, and ordered Windows-field/XML/strings plus guarded or unguarded text sources. |

All keys are exact. Regular expressions, capture groups, and excluded networks
are validated at startup; referenced Windows field IDs must exist, outputs must
be unambiguous, and IP recovery must contain a non-empty ordered subset of its
supported source mechanics. The engine retains only reusable XML traversal,
regex matching, IP validation, ordered coalescing, and vectorised candidate
mechanics. Changing an event ID, SSH pattern/provenance rule, excluded network,
destination precedence, source field, output name, or prefix in YAML changes
the corresponding materialised semantics without a Python edit.

Windows and SSH authentication extraction require `output_merge`.
`preserve_existing` writes an extracted value only when the existing output is
null, blank, or a recognised placeholder; `prefer_extracted` overwrites only
when the extracted value is meaningful. The shipped policies use
`preserve_existing`.

As a parser primitive, the engine also treats the common source sentinels `-`,
`--`, `n/a`, `na`, `none`, and `null` as semantic nulls. This fixed hygiene set
is not detector vocabulary. The Windows policy can add source-specific
placeholders for its canonical extraction.

`normalisation` is a non-empty ordered list with unique output names. Four
methods are accepted:

| Method | Exact keys |
|---|---|
| `coalesce` | `name`, `method`, non-empty ordered `fields` |
| `regex_first` | `name`, `method`, `from`, `pattern`, `group`; optional integer `flags` |
| `ipv4_first` | `name`, `method`, `from` |
| `file_extension` | `name`, `method`, `from` |

Unknown methods do not create empty placeholder columns. Regex syntax and the
selected capture group are checked during construction. After configured IP
recovery, the same declarative list is reapplied so downstream coalesces can
consume a recovered value without a code-owned list of canonical field names.

### GeoIP enrichment outputs

`geoip_enrichment` is another mandatory top-level mapping. Its exact schema is:

```yaml
geoip_enrichment:
  outputs:
    city_geoname_id: geo_city_geoname_id
    city_name: geo_city_name
    country_iso: geo_country_iso
    latitude: geo_latitude
    longitude: geo_longitude
    asn: geo_asn
```

The six output names must be non-empty and distinct. They may not collide with
canonicalisation, normalisation, or continuity-result fields. The lookup key is
the configured `canonicalisation.ip_recovery.output_field`; it is deliberately
not declared twice. The unique-IP MaxMind lookup, global-address check, and join
remain typed engine mechanics, while the derived schema and sidecar projection
come from this mapping.

The following detector bindings are exact cross-policy invariants:

- `geographic_continuity.inputs.country_field`, `asn_field`, and `city_field`
  match `country_iso`, `asn`, and `city_name` respectively;
- `impossible_travel.inputs.latitude_field`, `longitude_field`, and
  `country_field` match `latitude`, `longitude`, and `country_iso`.

A mismatch fails engine construction rather than producing empty continuity
features at runtime. Trust dampening retains its independent ASN binding because
it may intentionally consume another upstream infrastructure classification.

------------------------------------------------------------------------

## Detector policy v1

`detector_policy` is a mandatory top-level section. Version 1 uses
`mode: authoritative`: when this section is present, the detector definitions
in YAML are the complete policy for the thirty-five required detectors. The
engine does not fill missing detector policy from Python defaults.

The shipped thirty-five-detector section has this outer shape:

```yaml
detector_policy:
  version: 1
  mode: authoritative
  detectors:
    clamav_classification:
      # complete atomic classifier definition in the shipped YAML
    yara_classification:
      # complete atomic classifier definition in the shipped YAML
    web_request_classification:
      # complete atomic web classifier definition in the shipped YAML
    canonical_authentication:
      # complete atomic canonical-authentication definition in the shipped YAML
    execution_context_classifier:
      # complete atomic execution-context classifier in the shipped YAML
    file_lifecycle:
      # complete contextual lifecycle classifier/window definition
    mft_timestomping:
      # complete contextual MFT attribute-correlation definition
    geographic_continuity:
      # complete successful-auth geography continuity definition
    impossible_travel:
      # complete distance/speed continuity definition
    ip_scope_continuity:
      # complete private/public and subnet continuity definition
    persistence_configuration:
      # complete phase-19 ordered persistence/configuration rules
    repeated_scheduled_execution:
      # complete phase-19 grouped signal-window definition
    direct_attack_semantics:
      # complete phase-28 ordered direct ATT&CK rules
    contextual_signal_adjustments:
      # complete phase-35 ordered signal-adjustment rules
    referenced_file_correlation:
      # complete contextual correlation definition in the shipped YAML
    webshell_artifact:
      # complete contextual web-shell artefact definition in the shipped YAML
    systemd_service_persistence:
      # complete contextual detector definition in the shipped YAML
    download_to_execution:
      # complete temporal detector definition in the shipped YAML
    masquerading:
      # complete contextual signal-gate definition in the shipped YAML
    automated_collection:
      # complete contextual grouped signal-gate definition in the shipped YAML
    canonical_persistence_projection:
      # complete contextual signal-projection registry in the shipped YAML
    canonical_transfer_projection:
      # complete contextual signal-projection registry in the shipped YAML
    canonical_transfer_post_temporal_projection:
      # complete post-temporal signal-projection registry in the shipped YAML
    ransomware_impact:
      # complete temporal context-branches definition in the shipped YAML
    automated_exfiltration:
      # complete temporal counted-window definition in the shipped YAML
    credential_dump_collection:
      # complete temporal artifact-follow-on definition in the shipped YAML
    password_store_exfil_chain:
      # complete temporal artifact-follow-on definition in the shipped YAML
    webshell_activity:
      # complete temporal signal-sequence definition in the shipped YAML
    web_upload_execution_chain:
      # complete temporal signal-sequence definition with target context
    execution_lolbin:
      # complete atomic signal-gate definition in the shipped YAML
    # execution_lolbin_suspicious_args, execution_interpreter,
    # execution_scheduled, execution_privileged_scheduled, and
    # suspicious_execution are also required atomic signal gates
```

The comments above are a shape illustration, not a replacement configuration.
Read and copy the complete definitions from the
[shipped rules YAML](../rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml).

### Contract and validation

- `version` must be `1` and `mode` must be `authoritative`.
- `detectors` is a mapping keyed by detector ID. Version 1 requires complete
  definitions for `clamav_classification`, `yara_classification`,
  `web_request_classification`, `canonical_authentication`,
  `execution_context_classifier`, `file_lifecycle`, `mft_timestomping`,
  `geographic_continuity`, `impossible_travel`, `ip_scope_continuity`,
  `persistence_configuration`, `repeated_scheduled_execution`,
  `direct_attack_semantics`, `contextual_signal_adjustments`,
  `referenced_file_correlation`,
  `webshell_artifact`, `systemd_service_persistence`,
  `download_to_execution`, `masquerading`, `automated_collection`,
  `canonical_persistence_projection`, `canonical_transfer_projection`,
  `canonical_transfer_post_temporal_projection`,
  `ransomware_impact`, `automated_exfiltration`,
  `credential_dump_collection`, `password_store_exfil_chain`,
  `webshell_activity`, `web_upload_execution_chain`, `execution_lolbin`,
  `execution_lolbin_suspicious_args`, `execution_interpreter`,
  `execution_scheduled`, `execution_privileged_scheduled`, and
  `suspicious_execution`.
- A missing `detector_policy`, a missing required detector, an unknown key,
  an unknown executor, or a value of the wrong type fails engine construction.
  Partial policy never silently reactivates code-owned behaviour.
- Detector definitions do not accept a `merge` key. Typed detector emissions
  are idempotently maximum-merged as an executor invariant. The configurable
  top-level `rule_signal_merge` policy applies only to ordinary atomic and
  temporal rules; it must not be presented as detector policy.
- `canonical_authentication` and `execution_context_classifier` are mandatory
  specialised definitions. They may be disabled only by retaining the complete
  definition and setting `enabled: false`; additional IDs cannot select their
  executors. `engine_config.canonical_auth_signals` is obsolete and rejected.
- `file_lifecycle` and `mft_timestomping` are mandatory specialised
  definitions. Retain their complete schemas when disabled; additional IDs
  cannot select these executors.
- `persistence_configuration`, `repeated_scheduled_execution`,
  `direct_attack_semantics`, and `contextual_signal_adjustments` are mandatory
  reusable-executor definitions. Their
  phase, inputs, predicates or window, emissions, and evidence remain complete
  even when `enabled: false`.
- Shared rule-logic registries under `engine_config.path_taxonomy`,
  `detection_vocabulary`, `detection_event_ids`, and `detection_thresholds`
  are obsolete and rejected. Values must be declared inside the detector that
  owns the judgement. `engine_config.schema_aliases` and
  `engine_config.temporal_signal_policy` are read only from configuration;
  Python contributes no default aliases or ineligible-signal set.
- `profiling.hour_of_week` (including `validation` and `score_amplifier`),
  `engine_config.trust_dampening`, `engine_config.config_validation`, and the
  weights document are complete strict schemas. Missing or unknown keys,
  invalid types, duplicate explanation IDs, and an enabled trust policy without
  a selector fail startup.
- Signal identifiers in rules, policy inputs/outputs, and weights must use
  lowercase `snake_case`. Invalid casing is rejected instead of being silently
  normalised to a runtime name that cannot match.
- Every policy input must have a known producer and must be available before
  its executor runs. An earlier-phase policy output may feed a later-phase
  policy detector. Same-phase dependencies and later-to-earlier dependencies
  fail startup rather than relying on implicit mapping order.
- Set a detector's `enabled` field to `false` to disable it. Keep its complete
  definition in the authoritative policy so the configuration remains
  reviewable and schema-valid. An enabled consumer cannot be left with no live
  producer path; an `any` gate, projection, or sequence side may retain a
  disabled optional input only when another live input remains, while an `all`
  gate or projection may not.

### Typed executors

| Detector ID | Stage | Executor | Policy represented in YAML |
|---|---|---|---|
| `clamav_classification` | `atomic` | `clamav_classifier` | Default category, token mapping, ordered family overrides, generic/category emissions, suppression, evidence, descriptions, confidence, and enablement. |
| `yara_classification` | `atomic` | `yara_classifier` | Metadata path/fallbacks, ordered metadata/name predicates, defaults, distinct-rule strength, category contribution, emissions, confidence, evidence, referenced-file gate, and enablement. |
| `web_request_classification` | `atomic` | `web_request_classifier` | Raw fields and sidecar aliases, parser tokens, bounded decoding, SQLi and attack indicators, upload semantics and outcomes, inference thresholds, ordered exploit branches, emissions, evidence, and enablement. |
| `canonical_authentication` | `atomic` | `canonical_authentication` | Authentication fields and source signals, outcome/source and conflict resolution, remote/logon/message/package facts, eligibility and per-emission Boolean decisions, lateral threshold, thirteen emissions, evidence, and enablement. |
| `execution_context_classifier` | `atomic` | `execution_context_classifier` | Ordered path/command/actor fields, path and command vocabularies, system binaries, privileged actors, SUID regex, per-emission Boolean decisions, ten emissions, evidence, and enablement. |
| `file_lifecycle` | `contextual` | `file_lifecycle` | Fields, ordered timestamp taxonomy, path/extension/suffix classifications, named derived predicates, row and window decisions, weight-aware conditions, bounded lifecycle windows and thresholds, eleven emissions, and per-emission evidence. |
| `mft_timestomping` | `contextual` | `mft_timestomping` | Path/parser/timestamp fields, MFT creation-attribute taxonomy, minimum delta, path exclusions, parent-directory bulk threshold, emission, and targeted/bulk explanation metadata. |
| `geographic_continuity` | `temporal` | `geographic_continuity` | Actor keys, successful-auth sources and threshold, country/ASN/city/IP fields, history retention, novelty/first-observation/boundary semantics, derived output fields, four emissions, and configured evidence resolvers. |
| `impossible_travel` | `temporal` | `impossible_travel` | Actor keys, successful-auth sources, coordinate/country/IP fields, maximum speed and minimum distance/time bounds, derived travel fields, emission, and evidence. |
| `ip_scope_continuity` | `temporal` | `ip_scope_continuity` | Actor keys, ordered IP fields, history/reference and state-update policy, bounded lookback, IPv4/IPv6 subnet prefixes, ordered private/public transition branch mode, four emissions, and evidence. |
| `persistence_configuration` | `contextual` | `ordered_row_rules` | Phase-19 ordered path, registry, event, and message predicates; nine persistence/configuration emissions; confidence and evidence. |
| `repeated_scheduled_execution` | `contextual` | `grouped_signal_window` | Phase-19 source signals, host/command key extraction, message regex/fallback, closed lookback, count threshold, per-key emission cap, and evidence. |
| `direct_attack_semantics` | `contextual` | `ordered_row_rules` | Phase-28 non-systemd direct ATT&CK predicates, inputs, timestamp taxonomy, literals, regexes, event IDs, signal conditions, fifteen emissions, confidence, and evidence. |
| `contextual_signal_adjustments` | `contextual` | `ordered_signal_adjustments` | Phase-35 discovery reclassification and benign admin-query/backup dampening predicates, signal guards, target signals, zeroing actions, descriptions, confidence, and evidence. |
| `referenced_file_correlation` | `contextual` | `referenced_file_correlation` | Filesystem/source fields, exact-path and document-root matching, emissions, propagation, ordered web identity branches and mappings, evidence, and enablement. |
| `webshell_artifact` | `contextual` | `webshell_artifact` | Best-effort path and combined-text fields, web-root and script-extension references, basename/text/signal support, threshold, emission, evidence, and enablement. |
| `systemd_service_persistence` | `contextual` | `systemd_service_persistence` | Derived inputs/facts, explicit branch order and first/all-match mode, OR-of-AND branch predicates, emissions, evidence, and confidence for systemd unit changes and enablement activity. |
| `download_to_execution` | `temporal` | `signal_sequence_by_artifact` | Download and execution source signals, artifact keys, host-field binding and scope, ordering and lookback, emissions, evidence, and confidence. |
| `masquerading` | `contextual` | `signal_gate` | One or more already-emitted source signals, an `any`/`all` threshold gate, emissions, evidence resolvers, and explanation metadata. |
| `automated_collection` | `contextual` | `signal_gate` | Grouped sensitive-access and archive/scheduled-execution requirements, threshold, emission, evidence, and enablement. |
| `canonical_persistence_projection` | `contextual` | `signal_projection` | Row-local source-to-canonical-persistence projections, gates, strength propagation, emissions, and matched-signal evidence. |
| `canonical_transfer_projection` | `contextual` | `signal_projection` | Row-local archive/tool/large-HTTP source projections into canonical transfer signals before contextual gates and temporal consumers. |
| `canonical_transfer_post_temporal_projection` | `temporal` | `signal_projection` | Row-local projection of completed temporal staging, cross-border, and sensitive-staging signals into canonical transfer outputs. |
| `ransomware_impact` | `temporal` | `temporal_context_branches` | Ransomware source signals, prior-support signals, ransom-note path fields/tokens, closed lookback, branch descriptions, emission, and evidence. |
| `automated_exfiltration` | `temporal` | `counted_signal_window` | Row-counted transfer signals, threshold, window/current support signals, closed lookback, emission, and evidence. |
| `credential_dump_collection` | `temporal` | `artifact_follow_on_sequence` | Credential source signals, artifact/text fields and labels, copy-stage vocabulary/support, follow-on signals and qualification clauses, closed lookback, emission, and evidence. |
| `password_store_exfil_chain` | `temporal` | `artifact_follow_on_sequence` | Password-store source signals, artifact/text fields and labels, copy-stage vocabulary/support, follow-on signals and qualification clauses, closed lookback, emission, and evidence. |
| `webshell_activity` | `temporal` | `signal_sequence` | Source and target signal sets, correlation scope, ordering, lookback, source selection, emissions, and evidence resolvers. |
| `web_upload_execution_chain` | `temporal` | `signal_sequence` | Web-shell artefact source, execution targets, web-root/combined-text target predicate, correlation scope, ordering, lookback, emissions, and evidence. |
| `execution_lolbin` | `atomic` | `signal_gate` | Canonical alias from configured Windows/Linux LOLBin sources. |
| `execution_lolbin_suspicious_args` | `atomic` | `signal_gate` | Canonical alias from configured suspicious-argument sources. |
| `execution_interpreter` | `atomic` | `signal_gate` | Canonical alias from configured interpreter sources. |
| `execution_scheduled` | `atomic` | `signal_gate` | Canonical alias from configured scheduled-execution sources. |
| `execution_privileged_scheduled` | `atomic` | `signal_gate` | Canonical alias from configured privileged scheduled-execution sources. |
| `suspicious_execution` | `atomic` | `signal_gate` | Configured union of execution-family sources used by later contextual and temporal consumers. |

Signal-list conditions in canonical authentication, web exploit/mapping
branches, ransomware context, artefact follow-on, download-to-execution, and
generic signal sequences declare `minimum_signal_value_exclusive` at the
condition or source/support/target block that consumes the values. Each value
must be finite and non-negative, and admission is strictly greater than the
configured threshold. Separate source and target thresholds may differ; the
shipped policy uses `0` to retain the previous positive-signal boundary.

`clamav_classifier` has fixed raw inputs (`av_hit`, `av_signature`, and
`filename`) but no code-owned classification table. `category_tokens` is a
non-empty lowercase mapping and `family_overrides` is an ordered list of
`contains`/`category` mappings. `generic` defines its emission, evidence, and
unclassified description. `categories` is a non-empty ordered registry; each
category supplies `suppress_generic`, an emission, and evidence. Categories
can be added, removed, or reordered when the default, tokens, overrides, and
downstream signal references remain valid. The shipped baseline defines
`offensive_tool`, `ransomware`, `exploit`, `malware`, `pua`, and `webshell`,
with 27 token keys and 28 ordered override patterns. See the
[ClamAV classification reference](CLAMAV_ENRICHMENT.md).

`yara_classifier` has fixed raw inputs (`yara_match` and derived
`yara_match_count`) but no code-owned classification or emission table.
`metadata` owns the resource path, missing/parse-error behaviour, indexed
defaults, and unindexed-rule treatment. `classification.ordered_rules` uses
first-match semantics over `rule_name`, combined `tags`, metadata `category`,
and `tc_detection_type`; supported operators are `equals_any`,
`contains_any`, `contains_none`, and `regex`. `categories` is the non-empty
ordered category authority and may be extended, reduced, or reordered when all
classification and gate references remain valid. The shipped baseline defines
`offensive_tool`, `ransomware`, `webshell`, `apt`, `exploit`, `certificate`,
and `malware`. Strength saturation/scaling, the strength and configured
category emissions, confidence, evidence caps, and the web/hash referenced-file
gate are mandatory. See the
[YARA classification reference](YARA_ENRICHMENT.md).

`web_request_classifier` has no fallback detection policy in Python. Its
`inputs` bind the raw Plaso fields and source-IP precedence; `outputs` bind the
configurable `chronosift_` aliases while the canonical sidecar columns remain
available. `matching`, `indicators`, and `upload` own parser qualification,
bounded decoding, ordered SQLi regexes, traversal/LFI/RFI/command/probe and
web-shell-parameter patterns, upload methods, accepted query-parameter names,
the mandatory `filename_extension_admission` mode, nameless-target handling,
extension/MIME indicators, and MIME value pairing. `nonempty_suffix` accepts
only a basename with a non-empty normalised suffix;
`any_nonempty_basename` accepts any meaningful basename. `mime_value_pairing`
is `exactly_one` or `any_pair`. `mime_mismatch` requires `match: any` and a
non-empty list of `{id, all, any, none}` decisions over `image_extension`,
`executable_extension`, and `image_content_type`. `outcomes` owns the
accepted/redirected/rejected ranges and labels and the exact/prefix indicator
selectors that admit an attempt candidate. `outcomes.web.selection` requires
`strategy: maximum_rank` and distinct non-negative ranks for exactly
`observed`, `attempt`, and `probable_success`; the same selector governs initial
materialisation and the later SQLi-inference update. `sqli` owns endpoint-baseline
topology and evidence: ordered grouping roles, required non-empty roles,
partition-wide or prior-row scope, optional finite lookback, sample admission,
median or mean statistic, minimum count, selected threshold terms with
minimum/maximum composition and comparison, absolute fallback, and separate
`all`/`any`/`none` fact decisions for attempt, response anomaly, and probable
success. Thus host/method/endpoint grouping, clean-success admission,
whole-partition inference, the former maximum-of-three formula, and the final
probable-success Boolean are not fixed executor behaviour. `exploit.branches` is an ordered first-match
registry over configured indicators and earlier signals. Unknown indicators,
dead prefixes, overlapping response ranges, ambiguous emission roles, invalid
regexes, and unavailable signal dependencies fail startup.

`canonical_authentication` has no Python fallback policy. `inputs.fields`
binds the outcome, protocol, direction, logon-type, message, and authentication
package columns; `inputs.source_signals` provides independent non-empty success
and failure source sets. `outcomes.outcome_source_match` selects `any` or `all`
resolution between the field value and source-signal group; its conflict mode
selects allow, preference, or suppression when both states resolve true.
Distinct configured outcome labels and the complete
`semantics` mapping own remote, remote-interactive, remote-shell, invalid-user,
new-credentials, service-logon, NTLM-remote, and lateral-movement judgement.
Remote and remote-interactive facts each declare `any` or `all` composition.
The lateral branch configures whether remote context is one of its evidence
dimensions, alongside logon type and authentication package, and applies a
threshold bounded by the active two or three dimensions. The mandatory
`eligibility` decision declares `all`, `any`, and `none` lists over the ten
derived facts. It runs after outcome conflict resolution and before emission
decisions; the shipped policy admits either resolved success or failure. The
mandatory `decisions` mapping gives each of the thirteen semantic roles exact
`all`, `any`, and `none` fact lists; this mapping owns success/failure gating,
remote versus local classification, and every specialised emission
combination. All thirteen semantic emission roles, their values and explanation
metadata, enablement, and `derived_from` evidence are mandatory and YAML-owned.
Python retains field normalisation, fact extraction, generic Boolean decision
evaluation, and sparse max-merge/explain mechanics. The former
`engine_config.canonical_auth_signals` mapping is rejected at startup.

`execution_context_classifier` also has no code-owned classification table.
Its three `first_nonempty` inputs configure ordered path, command, and actor
fields. `classification` owns temporary, user-writable, and suspicious path
tokens; system-binary names; compiler, shell, network, and archive command-name
sets; privileged actors; and a startup-validated SUID regular expression. The
mandatory `decisions` mapping assigns exact `all`, `any`, and `none` fact lists
to each emission. It therefore owns temporary/user-writable overlap, residual
suspicious-path suppression, misplaced-system-binary qualification, the four
command classes, privileged context, and SUID activity rather than relying on
a Python truth table. The detector uses ten mandatory YAML emission roles.
YAML also owns values, rule IDs, descriptions, confidence, enablement, and the
selected path/command/actor/derived evidence. Python retains first-nonempty
coalescing, case/slash/basename normalisation, command tokenisation, regex
execution, and sparse max merge. The former fixed Python path, command-name,
system-binary, privileged-actor, regex, and emission tables have been removed.

`file_lifecycle` is the mandatory phase-15 contextual policy. `inputs` owns the
best-effort path field order and the timestamp-description, host, parser,
message, size, and allocation fields. `classification.timestamp_kinds` must
list `create`, `delete`, `modify`, and `access` exactly once in precedence order
and provides each kind's match tokens. YAML also owns web-root, sensitive,
database-dump, and excluded-update paths; web-script, web-content,
database-dump, and archive extensions; suspicious temporary basenames; and
ransomware suffixes. Extensions must begin with a dot.

`classification.derived_predicates` is a mandatory non-empty mapping. Each
configuration-local predicate declares exact `all`, `any`, and `none` lists
over the mechanical base facts: `path_present`, `extension_present`,
`web_root`, `web_script_extension`, `web_content_extension`,
`archive_extension`, `database_dump_extension`, `database_dump_basename`,
`database_dump_message`, `sensitive_path`, `allocated`, `unallocated`,
`excluded_update_path`, `suspicious_temp_basename`, and
`ransomware_extension_suffix`. At least one `all` or `any` fact is required;
unknown facts, base-name collisions, duplicates, and required/excluded overlap
fail startup.

The lifecycle `conditions.row_emissions` mapping is a mandatory truth table for
all eight row-local roles. Each role selects `all` or `any`, an explicit set of
timestamp kinds, and an explicit set of base or derived predicates. Despite the
field name, `row_emissions.*.derived_predicates` accepts either kind.
This owns generic create/modify/delete handling, unallocated-file delete
promotion, web executable, archive, dump, defacement, and sensitive-path
qualification. `weight_aware_semantics` owns which zero-weight generic outputs
partition mode may omit.

Each lifecycle window is also a complete policy. Short-lived-file policy owns
its source and target timestamp kinds, identity key, source selection,
chronological ordering, open/closed bound, output row, and OR-of-AND admission
clauses. Mass-modification and ransomware-burst policy each own eligible kinds,
grouping, admission clauses, open/closed bound, threshold comparison, and
per-group emission limit as well as lookback and threshold. Base and derived
facts are available throughout: short-lived clauses use `source_` and `target_`
prefixes, while the other two windows use unprefixed facts. All eleven semantic
emission roles and their values, rule IDs, descriptions, confidence,
enablement, evidence type, and per-role evidence selections are YAML-owned.
Python retains best-effort path coalescing, case/slash and extension
normalization, first-kind selection, fact extraction, keyed state traversal,
weight lookup, and sparse max-merge/explain mechanics. The similarly named
legacy lifecycle values under `engine_config.detection_thresholds` are rejected
rather than merged.

`mft_timestomping` is the mandatory phase-18 contextual policy. Its `inputs`
own the best-effort path fields plus parser and timestamp-description fields.
`conditions` owns parser and creation tokens, `$STANDARD_INFORMATION` and
`$FILE_NAME` attribute tokens, the positive minimum delta, excluded update or
installer paths, and the positive bulk-extraction threshold with required
`group_by: parent_directory`. A candidate requires the earliest configured
`$FILE_NAME` creation timestamp to exceed the earliest configured
`$STANDARD_INFORMATION` creation timestamp by more than `minimum_delta`.
Excluded paths do not emit; a parent-directory cohort meeting the bulk
threshold selects the dampened branch.

The single timestomping emission owns its signal value and rule metadata,
while the required `targeted` and `bulk_extraction_likely` branches separately
own analyst description, confidence, and evidence selection. Python retains
field normalization, MFT row filtering, attribute classification, path-keyed
earliest-pair selection, delta comparison, parent grouping, branch selection,
and sparse max-merge/explain mechanics.

`ordered_row_rules` is a reusable contextual executor with an explicit
positive `phase`. Its `inputs` mapping names derived row arrays. Supported
resolvers are `row_field`, `best_effort_file_path`, `first_nonempty`, `concat`,
and `timestamp_kind`; normalisation is `none`, `lower`, or `path_lower`.
`concat` also declares ordered `first_existing` fields appended to its fixed
fields. Selection is row-wise: each row uses its first meaningful configured
value, so an earlier column that merely exists does not suppress a later
populated field. `timestamp_kind` owns both kind precedence and the match
tokens for each configured kind, so timestamp classification is policy rather
than a Python table.

Each item in `ordered_rules` has an `id`, `when` expression, emission ID,
description, confidence, and selected evidence resolvers. Expressions compose
`all`, `any`, `not`, and counted `at_least` nodes. Leaves support
`contains_any`, `equals_any`, `starts_with_any`, `ends_with_any`, `regex`,
`nonempty`, `signal_any_positive`, and `signal_all_positive`. Literal values
preserve leading and trailing whitespace, which is significant for command
tokens such as `' dir'`, `'copy '`, or `' | '`. Same-policy output signals may
be consumed only by a later ordered rule; forward references fail startup.
Both signal operators require a non-empty `signals` list and a finite
non-negative `minimum_value_exclusive`; values qualify only when strictly
greater than that configured boundary. “Positive” is the operator name, not a
hard-coded zero threshold.
The `emissions` mapping owns signal names, values, rule IDs, descriptions, and
confidence. Evidence uses a configured input directly or a validated
`regex_capture`, with an optional character cap. Python derives candidates
from these predicates, evaluates the expression arrays in order, and performs
sparse max merge; it contains no detector-specific token or event-ID table.
Every matching ordered rule produces a distinct explanation even when another
rule already emitted the same signal. `rule_id` retains the canonical emission
identity and `detector_rule_id` records the unique `ordered_rules[].id`;
re-evaluating the executor does not duplicate that provenance.

`ordered_signal_adjustments` reuses the same configured row-input resolvers and
nested predicate language, but applies ordered changes to signals already
present on a row. Version 1 supports explicit `zero` and `multiply` actions over
a non-empty configured target set, optional `any`/`all` signal guards with a
mandatory exclusive minimum value, and configured description, confidence, evidence
type, and evidence fields. The required phase-35
`contextual_signal_adjustments` policy uses it for discovery
reclassification, benign administrative queries, and benign backup/archive
activity. Python retains predicate evaluation and sparse mutation only.

`grouped_signal_window` is a reusable contextual executor for repeated keyed
activity and requires an explicit positive `phase`. `inputs` selects source
signals and an exclusive minimum value. The
`key` mapping owns the host field, ordered command fields, message field,
message extraction regex, fallback length, and lowercase normalisation. A
closed positive `lookback`, positive row `threshold`, and positive
`max_emissions_per_key` determine when and how often the single configured
emission is produced. Evidence is selected from `hostname`, `command`,
`count_in_window`, and `window_seconds`. Python retains grouping and rolling
window mechanics only.

The required phase-19 `persistence_configuration` definition uses
`ordered_row_rules` for cron, firewall, group-policy, Winlogon, COM-hijack,
service-configuration, Defender, account-creation, and privileged-membership
semantics. It owns the path and timestamp field order, timestamp-kind tokens,
parser/message/event/group inputs, ordered branches, all nine emissions, and
evidence. `repeated_scheduled_execution`, also phase 19, uses
`grouped_signal_window` and owns its scheduled-execution sources, host/command
identity, message extraction, ten-minute window, threshold, emission cap, and
explanation contract.

The required phase-28 `direct_attack_semantics` definition uses
`ordered_row_rules` for every remaining non-systemd direct branch:
authorized-keys persistence, recovery inhibition, credential dumping and
password-store access, three discovery families, indicator removal, service
stop, SMB administrative shares, remote services, alternate authentication
material, application protocols, and account-access removal. Its fields,
timestamp taxonomy, command/path/message literals, UNC and other regular
expressions, Windows event IDs, source-signal conditions, branch order,
fifteen emissions, confidence, and evidence are all YAML-owned.

The required temporal continuity policies are specialised stateful mechanics
with complete YAML judgement. `geographic_continuity` owns successful-auth
sources, actor keys, country/ASN/city/IP fields, history retention (`lifetime`
or a positive duration), novelty reference (`all_seen` or
`previous_observation`), first-observation output/emission handling, boundary
reference (`previous_observation` or `any_prior_distinct`), output fields, four
emissions, and evidence. Finite retention prunes carried per-actor values using
the event `DatetimeIndex`; its three GeoIP inputs are cross-validated against
the mandatory enrichment outputs. `impossible_travel` owns the coordinate
fields, distance, elapsed-time and maximum-speed bounds, output fields,
emission, and evidence, with its latitude, longitude, and country bindings
validated the same way. Its mandatory `state` mapping chooses the retained or
immediately previous reference, whether below-minimum observations advance the
retained reference, and whether a time-and-distance-qualified comparison
advances it. Each distance, elapsed-time, and velocity threshold also declares
`greater_than` or `greater_than_or_equal`; the shipped policy retains its anchor
after either minimum rejects an observation, advances after qualification, and
uses inclusive comparisons. This state is carried unchanged across partition
boundaries.
`ip_scope_continuity` owns IP selection, retained-versus-previous reference
selection, state-update timing, lookback duration and open/closed bounds,
IPv4/IPv6 prefixes, address-change requirement, ordered scope/subnet
transitions, `all_matches` versus `first_match` branch evaluation, four
emissions, and evidence. The shipped policy advances its retained reference on
every valid observation, uses a closed 24-hour window, and emits every matching
ordered branch; both overlapping private-IP rules therefore fire on a subnet
change. Carried partition state retains both reference forms. No legacy
top-level geo or private-IP section is merged into these policies.

Systemd persistence stays isolated in the specialised phase-20 executor so it
cannot be duplicated by the generic direct pass. Its definition now owns the
timestamp-kind precedence/tokens as well as service paths, unit extensions,
command tokens, emissions, and evidence. `webshell_artifact` likewise carries
its web-root and script-extension values directly. Neither definition resolves
shared `path_contains_from`, `extension_in_from`, or similar registries.

`referenced_file_correlation` is the authoritative boundary for correlating
filesystem evidence with later rows and web requests. Its `inputs` select raw
filesystem fields plus correlation-owned web identity fields; `matching`
selects exact-path behaviour and document roots. Web parser fields, parser
tokens, upload methods, outcomes, and normalized request aliases are inherited
from `web_request_classification`, giving each judgement a single owner.
Materialised field names must be distinct and remain in the `chronosift_`
sidecar namespace; the engine also retains the canonical sidecar aliases.
Document roots may be empty, explicitly disabling URL alias matching; parser
tokens and upload methods may independently be empty in the web classifier.

`emissions`, `web`, `mappings.outputs`, and `mappings.branches` are ordered
configuration-owned registries. Their IDs are local references and are not a
fixed Python enum. `propagation` may configure any subset of the engine hit
types `av`, `luhn`, and `yara`; the `web` registry may be empty. When mappings
are enabled, both mapping outputs and branches must be non-empty, every branch
must reference known outputs, and mapping signal dependencies must be
available before correlation or be a propagation/web-branch emission from the
same correlation policy. Same-pass mapping outputs and signals first produced
after phase 25 are rejected. Branch order is deterministic and is included in
the policy digest. `web_outcome_merge` assigns every classifier and referenced-
file outcome a distinct rank and uses `maximum_rank`, so later evidence can
promote but cannot silently downgrade an earlier outcome. Python retains only canonical request/path parsing,
exact-hash lookup, identity merging, and sparse executor mechanics.

`webshell_artifact` is the required specialised contextual detector at phase
27. Its `inputs.path` selects the ordered fields used by the best-effort path
resolver. `inputs.combined_text` selects concatenated text fields and an
ordered first-existing field list. The root and script-extension conditions
contain their values directly in the detector. `conditions.support`
matches `any` or `all` of configured basename tokens, combined-text tokens,
and earlier signals above an exclusive numeric threshold. YAML owns those
inputs and conditions, the single max-merged emission, evidence resolvers,
description, confidence, and enablement. Python retains path coalescing and
normalisation, basename/extension extraction, literal predicate evaluation,
and sparse idempotent emission mechanics.
Every `best_effort_file_path` or `best_effort_file_basename` use must declare
its ordered `fields`; the runtime has no legacy default path-field list.

On a multipart event, any resolved upload hash makes the event-wide hash
identity authoritative and basename-only matches are ignored. This is a
conservative response to source formats that expose name and hash lists without
a reliable per-part pairing.

The web feature materialiser is now policy-driven but still deliberately
mechanical: Python performs bounded parsing, canonical URL normalization,
multipart extraction, typed column allocation, and sparse baseline execution.
The configured web classifier owns every detection pattern, threshold,
outcome, branch, signal value, rule ID, description, confidence, and evidence
selection used to emit SQLi or `exploit_public_facing_app` results.

Version 1 deliberately has a narrow enum surface. Systemd policy uses
`branch_mode: first_match` or `all_matches`, an explicit two-entry
`branch_order`, `evidence_type: direct`, and the
`best_effort_file_path`, `timestamp_desc_kind`, and `concat_lower` resolvers.
Its `timestamp_desc_kind` input requires YAML-owned precedence and match-token
lists; Python supplies no timestamp taxonomy fallback. Each branch declares a
non-empty `conditions.any` list of `all` fact clauses. Those clauses control
artifact path/extension/timestamp and persistent/transient/unit-reference
composition; first-match ordering controls selected evidence, while
`all_matches` records each satisfied branch.
Its top-level `evidence` mapping separately binds output names to
`best_effort_file_path`, `row_field`, or ordered `first_nonempty` resolvers, so
command, message, hostname, path, and timestamp evidence do not depend on
literal Python field names. Download policy uses `evidence_type: contextual`,
`emit_on: target`, `window_bounds: closed`, and the
`best_effort_file_basename` resolver. Its supported scope is
`deadbox_global` or `hostname`; `key.host_field` binds hostname-scoped
correlation and hostname evidence. Ordering is `source_at_or_before_target` or
`source_before_target`; and source selection is `earliest_in_window` or
`latest_in_window`. Any other enum value fails configuration loading.

`signal_gate` is reusable for additional atomic or contextual detector IDs. It
accepts `match: any` or `match: all`, an exclusive numeric threshold, one or
more emissions, and evidence resolved with `row_field`, `first_nonempty`, or
`best_effort_file_path`. A gate may additionally partition all of its inputs
into non-overlapping `any`/`all` groups; every group must pass. The shipped
`automated_collection` definition uses one sensitive-access group and one
archive-or-scheduled-execution group. The `matched_signals` resolver records
the sorted, comma-separated configured inputs that passed the gate. Atomic
gates run after ordinary atomic rules and all configured phase-5 classifiers,
but before initial scoring.
Contextual gates run after direct detection and the configured phase-29
canonical projections, but before phase-35 configured signal adjustments.
Canonical authentication runs once in the atomic classifier stage; adjusted
authentication values are not restored by a later refresh. Profiling
score amplification and trust dampening run only after temporal detectors and
phase-45 projections have completed; trust changes signal values before the
single event-score factor is calculated.
Inputs known to be emitted later are rejected at startup.

`signal_projection` is reusable for additional contextual or temporal detector
IDs. Each definition contains a non-empty ordered `projections` list. Every
projection owns a non-empty input-signal set, an `any` or `all` match mode, an
exclusive non-negative threshold, and exactly one emission. The only strength
mode in version 1, `maximum_matched_times_emission_value`, multiplies the
largest qualifying input value by the configured emission value; the typed
executor's maximum-merge invariant prevents a weaker projection from replacing
a stronger value. Evidence uses
the `matched_signals` resolver and records the sorted configured sources that
qualified. Projection is row-local and has no correlation key or lookback;
Python retains numeric coercion, sparse row traversal, max merge, and explain
materialisation.

The required `canonical_persistence_projection` and
`canonical_transfer_projection` definitions run contextually at phase 29, so
their canonical outputs can feed phase-30 gates and phase-40 temporal policy.
The required `canonical_transfer_post_temporal_projection` runs at phase 45
and projects completed temporal staging, cross-border, and sensitive-staging
signals without adding another time window. YAML owns all three ordered
source/output registries, their conditions, strength, enablement, emission
metadata, and evidence policy.

Policy execution phases are ordered: web-request, canonical-authentication,
execution-context, ClamAV, and YARA classification at phase 5, atomic signal
gates at phase 10, file lifecycle at phase 15, MFT timestomping at phase 18,
ordered persistence and grouped repeated-schedule evaluation at phase 19,
isolated specialised systemd persistence at phase 20, referenced-file
correlation at phase 25, web-shell artefact classification at phase 27,
ordered direct ATT&CK semantics at phase 28, contextual signal projections at
phase 29, contextual signal gates at phase 30, ordered signal adjustments at
phase 35, bounded temporal policy executors at phase 40, and post-temporal
signal projections at phase 45. Trust dampening then operates over the complete
row signal set, followed by the single validated event-score amplifier. The required
`persistence_configuration`, `repeated_scheduled_execution`,
`direct_attack_semantics`, and `contextual_signal_adjustments` definitions are
validated at phases 19, 19, 28, and 35 respectively because those are the
engine's actual fixed schedule points; editing their phase numbers cannot
reschedule execution. A policy output is therefore a valid input only for a
strictly later phase. The
five execution aliases and `suspicious_execution` are independent atomic gates
over raw configured source signals; changing or disabling one alias does not
silently alter the input list of another. In the shipped policy,
`suspicious_execution` evidence consequently names the matched raw source
signals rather than the canonical aliases.

Within the atomic pipeline, ordinary YAML rules run first; web-request,
canonical-authentication, and execution-context classification then run before
ClamAV and YARA enrichment, followed by phase-10 atomic gates. All five
classifier types are dependency phase 5: their mapping order cannot create a
same-phase producer/consumer edge, and every output is available to phase 10
and later consumers.

`signal_sequence` is reusable for additional temporal detector IDs. It
supports `deadbox_global` scope with no `field` key, or `field` scope with a
required field name. It uses target/source field and timestamp evidence
resolvers and the same bounded ordering and source-selection enums as the
artifact sequence. An optional `target.where` predicate may match `any` or
`all` of a best-effort path against directly configured `contains_any` values
and configured combined-text tokens. The shipped
`web_upload_execution_chain` uses that generic predicate to require web-root
or web-script execution context. The specialised download executor additionally
derives an artefact basename and supports `deadbox_global` or `hostname` scope
using its configured host field.

`temporal_context_branches` backs the required `ransomware_impact` definition.
It emits on a configured ransomware-source row when a closed dead-box-global
lookback contains configured prior support, or when a later row has a basename
containing a configured ransom-note token. YAML owns the source/support signal
sets, note path fields and tokens, lookback, branch descriptions, emission, and
evidence resolver mapping. `row_field` binds row evidence such as hostname;
`matched_source_signals`, `support_timestamp`, and `ransom_note_timestamp`
bind derived context. Python retains timestamp indexing, typed branch evaluation, path
normalisation, and sparse max-merge mechanics.

`counted_signal_window` counts each row carrying any configured count signal at
most once. The qualifying row must meet the configured integer threshold in a
closed dead-box-global lookback and have either configured support somewhere in
that window or configured support on the current row. Its mandatory `emit_on`
list names the roles that qualify the current row: `counted`,
`current_support`, or `window_support`. The shipped policy selects `counted`
and `current_support`, so an unrelated row between or after qualifying events
cannot receive the composite merely because the window remains populated. The
`automated_exfiltration` definition owns both support sets, the count signals,
integer count threshold, mandatory `minimum_signal_value_exclusive` admission
threshold, lookback, emission, and an evidence mapping using `row_field`,
`count_in_window`, or `window_seconds`; Python retains rolling-window and
sparse-emission mechanics.

`artifact_follow_on_sequence` backs `credential_dump_collection` and
`password_store_exfil_chain`. It resolves configured path and text fields into
case-normalised artifact labels and derives the typed `copy_command`,
`copy_text_support`, `copy_signal_support`, and `follow_on_signal` facts.
`follow_on_qualification.any` is a mandatory non-empty OR of `all` clauses over
those facts. The shipped policy is `(copy_command AND copy_text_support) OR
(copy_command AND copy_signal_support) OR follow_on_signal`; Python does not
impose that topology. A labelled source requires an intersecting follow-on
label; the configured `allow_unlabelled` fallback controls sources without a
label. YAML owns source and follow-on signals, label and copy vocabularies,
fields, lookback, qualification, emission, and evidence resolvers
(`row_field`, `source_timestamp`, or `window_seconds`). Python retains fact
and label extraction and intersection, bounded follow-on lookup, and sparse
max-merge mechanics.

For partitioned processing, `overlap` must be at least the longest lookback of
all enabled policy temporal detectors. The engine rejects a shorter overlap
before reading or writing partitions, because candidate expansion cannot
recover a source row that was never loaded. Candidate signals, projected input
fields, temporal-stage entry, and the effective candidate window are likewise
derived from enabled definitions.

Each windowed temporal detector's own `lookback` controls its effective
candidate and overlap window. A temporal `signal_projection` is row-local and
therefore contributes a zero lookback, although its configured source signals
still participate in temporal candidate selection.
`automated_exfiltration.threshold` controls its counted-row minimum. The
obsolete
`webshell_activity_window`, `web_upload_execution_window`, and
`download_exec_window` threshold keys, plus the obsolete
`ransomware_support_window`, `automated_exfiltration_window`,
`automated_exfiltration_threshold`, and `credential_collection_window` keys,
are rejected. The obsolete `short_lived_file_window`,
`mass_file_modification_window`, `mass_file_modification_threshold`,
`ransom_extension_burst_window`, and `ransom_extension_burst_threshold` keys
are also rejected in favour of `detector_policy.detectors.file_lifecycle`.
Ransom-note vocabulary now lives at
`ransomware_impact.branches.ransom_note.basename_contains`; the former
`ransom_note_name_tokens` vocabulary key is also rejected.

The executor name selects a registered Python implementation; it is not an
arbitrary function name. Python performs mechanics such as cached field
normalisation, candidate selection, sparse/idempotent emission, and bounded
temporal lookup. YAML decides whether the detector runs and supplies the
inputs, projections, branches or sequence, bounds, outputs, and explanation
policy. This keeps implementation details in code without hiding detection
judgement there.
Additional detector IDs may select only `signal_gate` (atomic or contextual),
`signal_sequence` (temporal), or `signal_projection` (contextual or temporal)
without adding a detector-specific Python policy branch. `ordered_row_rules`,
`ordered_signal_adjustments`, and `grouped_signal_window` are reusable
implementations bound to required baseline definitions and fixed schedule
points; additional IDs selecting them are rejected. The
specialised executor types, including `temporal_context_branches`,
`counted_signal_window`, `canonical_authentication`,
`execution_context_classifier`, `file_lifecycle`, `mft_timestomping`, and
`artifact_follow_on_sequence`, remain reserved for their required baseline
definitions.

## Signal weighting

Signals contribute to event scores using the shipped
[`weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml`](../rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml).

Example:

```yaml
max_event_score: 50
weights:
  scheduled_exec: 3
  fail_then_success_user: 8
```

Base event score:

    base_score = Σ(signal_value × weight)

When the hour-of-week profile is accepted, final scoring is:

    score = min(max_event_score, base_score × profile_multiplier)

Otherwise `profile_multiplier` is exactly `1`. A positive base score is
therefore still required. All scores are capped by `max_event_score`.

Both top-level keys are required. `max_event_score` must be a positive finite
number; `weights` must be a non-empty mapping from lowercase signal names to
non-negative finite numbers. The engine does not supply a score cap or coerce
malformed/missing weights from defaults.

------------------------------------------------------------------------

## Explainability

Each rule or detector firing records a structured explanation. Atomic rules
select copied fields with `emit.evidence`; temporal rules record their rule
identity and correlation context; typed detector-policy entries define their
emission and evidence specifications. The engine adds the mechanics-derived
values, such as matched timestamps, without changing the configured rule
identity, description, or confidence.

This supports forensic review and research reproducibility.

------------------------------------------------------------------------

## Design goals

The ChronoSIFT rule language emphasises:

-   deterministic behaviour
-   missing-field tolerance
-   human readability
-   forensic explainability

Rules should prioritise **behavioural semantics** rather than static
signatures. Any future typed executor should preserve the same boundary:
configuration declares auditable policy, while Python supplies tested
mechanics.
