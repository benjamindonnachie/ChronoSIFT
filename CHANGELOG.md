# ChronoSift v2.31 Changelog

This changelog captures the work completed so far on the `v2.31` dead-box ATT&CK expansion and hardening pass.

## Unreleased

- Replaced family-specific quiet-time coefficients with a single
  dataset-derived out-of-hours event-score amplifier. Candidate hour-of-week
  profiles must improve held-out logarithmic score over a uniform 168-hour
  reference under leave-one-complete-calendar-week-out validation; a
  deterministic whole-week bootstrap must place the configured one-sided
  confidence bound above zero. Rejected, inconclusive, and legacy unvalidated
  profiles are neutral.
- Accepted profiles use a simultaneous bootstrap upper probability band to
  derive a conservative activity deficit and multiplier in `[1, 2]`. The
  factor is applied once to the complete post-trust event score before the
  ordinary score cap, cannot create score from zero, and is recorded with the
  profile selection, validation statistics, uncertainty bounds, and fallback
  attempts in reports, telemetry, explanations, and the profile manifest.
- Added a required profile amplifiability gate. A predictively non-uniform
  profile is rejected when its simultaneous upper band identifies no hour
  below the uniform reference; this avoids reporting an accepted but inert
  amplifier and allows the configured filtered-to-full-dataset fallback to
  continue.
- Renamed the optional profiling surface from hour “rarity” to the quantity it
  now carries: `out_of_hours_activity_deficit`. The strict YAML keys,
  materialised contribution field, explanation rule and evidence binding use
  activity-deficit terminology; the former names are not compatibility aliases.
- Added numerical sanity guards for bootstrap validation. Confidence must be
  greater than `0.5` and less than `1`; resampling must include at least 100
  draws and at least five expected observations in each confidence tail.
- Documented that hour-of-week bins use UTC, daylight-saving transitions can
  split a recurring local-time habit, uncertainty and factor magnitude depend
  on retained evidence volume, and “out of hours” is a potentially broad
  dataset-relative off-peak classification rather than a rare-event label.
- Added a mandatory strict top-level `canonicalisation` policy for Windows
  authentication extraction, SSH authentication parsing, pivot-destination
  identity, and structured-first IP recovery. YAML now owns parser/field
  selectors, EVTX aliases, placeholders, event-ID outcomes, protocol rules,
  regexes and capture bindings, output names, source precedence, prefixes, and
  context gating. The former Python alias/event/regex/source tables and unused
  row-level IP fallback were removed.
- Made canonical placeholders, SSH selector composition and per-pattern
  provenance, excluded IP networks, source-registry subsets, configured output
  propagation, and lateral-authentication remote participation effective at
  runtime. File-extension normalisation no longer imposes an undocumented
  suffix-length judgement.
- Added mandatory Windows and SSH `output_merge` precedence. The shipped
  `preserve_existing` policies fill only null, blank, or recognised-placeholder
  outputs; `prefer_extracted` instead overwrites only with meaningful parsed
  values.
- Made Windows protocol truth tables explicit: every protocol declares
  event-ID/logon-type `any` or `all` matching, the policy selects first or last
  matching branch, and remote direction declares whether a client address or a
  classified protocol qualifies it.
- Made the ClamAV and YARA `categories` mappings dynamic ordered registries.
  Category addition, removal, reordering, classification, emission, and
  referenced-file validation now derive from YAML rather than fixed Python
  category universes.
- Made `normalisation` a typed ordered schema supporting only `coalesce`,
  `regex_first`, `ipv4_first`, and `file_extension`. Method-specific keys,
  unique outputs, regex compilation, and capture groups are validated at
  startup; unknown methods no longer silently create placeholder columns.
- Completed the migration of detector judgement into a mandatory top-level
  `detector_policy` v1. The shipped configuration now contains thirty-five
  required definitions covering ClamAV, YARA, web-request,
  canonical-authentication, and execution-context classification,
  file lifecycle, MFT timestomping, persistence/configuration changes,
  repeated scheduled execution, direct ATT&CK semantics, referenced-file
  correlation, web-shell artefact classification, isolated systemd
  persistence, download-to-execution,
  masquerading, automated collection,
  three canonical persistence/transfer projections, webshell activity, the
  web-upload execution chain, five canonical execution aliases, suspicious
  execution, ransomware impact, automated exfiltration, credential-dump
  collection, and the password-store exfiltration chain.
- Removed the detector-level `merge: max` schema marker. Typed detector
  emissions remain idempotently maximum-merged as an explicit executor
  invariant; only ordinary atomic and temporal rules expose selectable merge
  policy through `rule_signal_merge`.
- Made residual explanation field selection authoritative. Systemd command,
  message, hostname, path, and timestamp evidence and temporal impact/count/
  follow-on row evidence now use validated YAML resolvers. Best-effort path
  helpers require a configured field list and no longer expose a legacy default.
- Ordered-row evaluation now records every matching rule even when rules share
  one max-merged emission. Explain entries retain the canonical emission
  `rule_id` and add the unique YAML `detector_rule_id`, with idempotent
  provenance deduplication.
- Restored explicit SMB share/named-pipe precedence over the fallback type-3
  network-logon inference. A remote named pipe on a non-admin share no longer
  acquires `smb_admin_share`; IPC$/ADMIN$ events continue to emit the explicit
  SMB and remote-service signals. Added an exact regression for both edges.
- Added mandatory phase-40 `geographic_continuity`, `impossible_travel`, and
  `ip_scope_continuity` policies. YAML now owns their actor/success inputs,
  geo/IP fields, lookbacks and thresholds, transition rules, derived outputs,
  emissions, and evidence. The legacy top-level geo, impossible-travel, and
  private-IP configuration and the duplicate atomic geo rules were removed.
- Made geographic continuity history behaviour authoritative: YAML now selects
  lifetime or bounded retention, all-seen or previous-observation novelty,
  first-observation output/emission handling, and previous or any-prior country
  boundary comparison. Carried country, ASN, and city histories are pruned and
  evaluated according to those choices.
- Made impossible-travel state advancement authoritative. YAML now selects the
  retained or immediately previous reference, whether rejected observations
  advance the retained reference, whether qualifying comparisons advance it,
  and inclusive or exclusive distance/time/velocity comparisons. The shipped
  policy retains its reference through too-soon or too-near observations,
  advances after qualification, and preserves explicit `>=` semantics across
  partition continuation.
- Made IP-scope history and transition evaluation authoritative. YAML now owns
  retained-versus-previous reference selection, state-update timing, lookback
  duration and open/closed bounds, and ordered `all_matches` or `first_match`
  transition evaluation. The shipped policy preserves the former behavior:
  every valid observation advances state, the 24-hour window is closed, and
  overlapping private-address and subnet-change rules both emit across
  partition boundaries.
- Made generic temporal window, anchor, and condition state policy authoritative.
  Every temporal rule now declares inclusive or exclusive exact-lookback
  treatment and a genuinely selectable mode-specific emission anchor. Condition
  rules additionally declare empty-value handling, first-observation behavior,
  and rolling/selected reference semantics. The shipped policy explicitly
  preserves inclusive windows, completion/current/match anchors, ignored empty
  values, suppressed first change observations, and previous-observation change
  references. Condition state is bounded by the active lookback, so the
  configured first-observation behavior applies again after all references age
  out.
- Added mandatory phase-35 `contextual_signal_adjustments` using the reusable
  `ordered_signal_adjustments` executor. Discovery reclassification and benign
  administrative-query/backup dampening now take predicates, guards, targets,
  zeroing actions, descriptions, confidence, and evidence entirely from YAML;
  the former detector-specific Python passes were removed.
- Made atomic rules, temporal rules, conditions, profiling, profile
  multipliers, trust dampening, config validation, and weights complete strict
  schemas. Required keys and types no longer fall back to code defaults;
  unknown keys, stale targets, duplicate ownership, malformed regexes, and
  missing producer paths fail startup with a configuration path.
- Replaced permissive YAML loading with a safe duplicate-key-rejecting loader
  for both rules and weights. Duplicate mapping keys at any depth and
  non-mapping document roots now fail before policy construction rather than
  silently applying last-value-wins semantics.
- Added mandatory `rule_signal_merge.atomic_rules` and `.temporal_rules`
  choices (`maximum` or `sum`). Scalar, vectorised, fallback, and temporal
  evaluation now resolve duplicate ordinary-rule emissions through the same
  YAML-owned policy; the shipped bundle selects `maximum` for both.
- Asserted the fixed executor schedule for the required persistence,
  repeated-schedule, direct-semantics, and contextual-adjustment definitions at
  phases 19, 19, 28, and 35. YAML can describe the actual schedule but cannot
  claim to reschedule hard-wired orchestration.
- Canonical authentication now runs once in the atomic stage, so contextual
  signal adjustments remain effective. Ordered web-shell, systemd, GeoIP,
  impossible-travel, and IP-scope fallback fields now select the first
  meaningful configured value per row rather than the first column that exists.
- Removed the implicit `1.0` cap from generic temporal emissions. Configured
  positive values are retained and duplicate emissions follow
  `rule_signal_merge.temporal_rules`; the configured maximum event score
  remains the final scoring cap.
- Added mandatory generic-temporal emission anchors. Sequences emit on their
  completion input, co-occurrences on a current configured input, and value
  conditions on the matching row, so satisfied windows no longer mark unrelated
  trailing events. `counted_signal_window.emit_on` now lists explicit current-row
  roles; the shipped exfiltration policy permits counted or current-support rows.
- Added mandatory exclusive input-signal thresholds to every generic temporal
  rule and counted-signal window; the shipped value is zero.
- Added a mandatory `download_to_execution.key.host_field`. Hostname-scoped
  download/execution correlation and hostname evidence no longer read a
  literal Python field name.
- Moved hour-of-week filters, quiet-quantile membership, output names, optional
  emission values/merge modes and explanation metadata into
  `profiling.hour_of_week`, and trust field bindings, selectors, targets,
  multiplier and explanation metadata into `engine_config.trust_dampening`.
  Profile emissions now use the ordinary signal map and scorer; the shipped
  unweighted emissions are disabled to retain sparse scaling, while the dense
  activity deficit drives the validated post-trust event factor. Profiling and trust
  dampening now run after temporal detection and post-temporal projection,
  fixing previously unreachable geo/temporal targets.
- Added explicit NSRL exclusion composition for both in-memory and DuckDB
  profiling, plus trust-selector `any`/`all` composition and configured reason
  precedence.
- Replaced the hard-coded NSRL `Operating System` lookup test with
  `profiling.hour_of_week.exclude_nsrl_application_type_contains`. In-memory
  and DuckDB-backed enrichment now apply the active engine policy after lookup,
  write the two configured profiling field names, and cannot leak one engine's
  classification into another through a cached Parquet view.
- Made upload query-parameter admission, filename-extension admission mode,
  multi-value MIME pairing, MIME-mismatch Boolean branches,
  indicator-to-attempt promotion, and observed/attempt/probable-success outcome
  ranks mandatory web policy. The shipped suffix mode now requires a proper
  non-empty suffix rather than merely a dot somewhere in the basename.
  Referenced-file outcomes separately use a complete configured rank table and
  maximum-rank merge, preventing later contextual evidence from downgrading an
  earlier probable-success classification.
- Added mandatory `geoip_enrichment.outputs` bindings for City geoname ID,
  city, country, latitude, longitude, and ASN. The unique-IP builder, required-
  field exclusions, and sidecar projection now use those configured names.
  Startup cross-validates every geographic-continuity and impossible-travel
  input against the enrichment schema, so renaming either side cannot silently
  disable the detector.
- Added the ordinary `LUHN_SENSITIVE_DATA_HIT` YAML producer for the `luhn_hit`
  enrichment field. Luhn evidence now reaches `sensitive_data_staged` through
  the configured temporal sequence instead of remaining a ghost input.
- Added a central detector registry. Additional IDs may use contextual or atomic
  signal gates, temporal signal sequences, and contextual or temporal signal
  projections without detector-specific policy wiring. Ordered-row,
  ordered-adjustment, and grouped-window implementations are bound to their
  required baseline IDs and fixed schedule points; additional IDs selecting
  them are rejected.
- Moved the five canonical execution aliases and `suspicious_execution` onto
  required atomic `signal_gate` definitions. Their source sets, thresholds,
  outputs, rule IDs, descriptions, confidence, enablement, and
  `matched_signals` provenance now come from YAML; the former Python mapping
  and execution-family helpers have been removed.
- Moved `automated_collection` onto a required contextual `signal_gate` with
  two configuration-owned input groups. YAML now requires sensitive access and
  one of archiving or repeated scheduled execution without a detector-specific
  Python branch.
- Moved canonical authentication onto the mandatory phase-5
  `canonical_authentication` definition. YAML now owns the six input field
  bindings, success/failure source signals and outcomes, remote/logon/message/
  package vocabularies, lateral threshold, all thirteen emission roles and
  metadata, evidence, and enablement. The legacy
  `engine_config.canonical_auth_signals` mapping is rejected; Python retains
  only normalisation, candidate selection, typed semantic evaluation, and
  sparse emission mechanics.
- Replaced the remaining canonical-authentication truth table with mandatory
  YAML fact decisions. Outcome/source composition, conflict resolution,
  remote and remote-interactive composition, local exclusions, success/failure
  gates, and all thirteen emission predicates are now executable policy. A
  mandatory `eligibility` decision now gates candidate rows after conflict
  resolution; the shipped policy admits either resolved success or failure.
- Moved execution-context classification onto the mandatory phase-5
  `execution_context_classifier` definition. YAML now owns the ordered
  path/command/actor fields, path vocabularies, system-binary, command-family,
  and privileged-actor names, SUID regex, all ten emission roles and metadata,
  evidence, and enablement. The former hard-coded Python lookup and emission
  tables were removed; Python retains coalescing, normalisation, command
  tokenisation, regex execution, and sparse max merge.
- Replaced the execution-context emission truth table with mandatory YAML
  `all`/`any`/`none` fact decisions, including temporary/user-writable overlap,
  residual suspicious-path suppression, misplaced system binaries, command
  families, privilege, and SUID handling.
- Moved file-lifecycle policy onto the mandatory phase-15 `file_lifecycle`
  definition. YAML now owns all input fields, timestamp-kind precedence and
  tokens, path/extension/suffix classifications, a mandatory registry of named
  `all`/`any`/`none` predicates over typed base facts, all eight row-emission
  truth tables, weight-aware conditions, and all three window definitions. Base
  and derived facts are reusable across row and window decisions. Window
  policy includes source or eligible kinds, identity/grouping, OR-of-AND
  admission clauses, ordering and bounds, threshold comparison, and emission
  limits as applicable. YAML also owns all eleven emission roles and metadata
  and per-role evidence. Python retains path/timestamp normalization, fact
  extraction, keyed bounded-window traversal, weight lookup, and sparse
  emission mechanics. The five former lifecycle keys under
  `engine_config.detection_thresholds` are rejected.
- Moved MFT timestomping policy onto the mandatory phase-18
  `mft_timestomping` definition. YAML now owns its path/parser/timestamp fields,
  parser/creation/attribute tokens, minimum delta, path exclusions,
  parent-directory bulk threshold, emission metadata, and targeted versus bulk
  explanation descriptions, confidence, and evidence. Python retains MFT
  filtering, normalized path identity, earliest SI/FN timestamp pairing, delta
  comparison, parent grouping, branch selection, and sparse max merge.
- Added reusable contextual `ordered_row_rules` and
  `grouped_signal_window` executors. Ordered-row policy owns derived inputs,
  configurable timestamp-kind classification, nested `all`/`any`/`not`/
  `at_least` predicates, literal/regex/signal leaves, ordered branch metadata,
  emissions, and direct or regex-captured evidence. Signal leaves require a
  finite non-negative `minimum_value_exclusive`, removing their former implicit
  zero boundary. Grouped windows own source
  signals, normalised host/command keys, message regex/fallback extraction,
  closed lookback, count threshold, per-key emission cap, and evidence.
- Moved persistence and configuration judgement onto the mandatory phase-19
  `persistence_configuration` ordered-row definition. YAML now owns cron,
  firewall, group-policy, Winlogon, COM-hijack, service, Defender, account, and
  privileged-membership fields, timestamp taxonomy, tokens/event IDs, ordered
  predicates, all nine emissions, confidence, and evidence.
- Moved repeated scheduled execution onto the mandatory phase-19
  `repeated_scheduled_execution` grouped-window definition. Its scheduled
  source signals, host/command key, message extraction, ten-minute window,
  threshold, one-emission-per-key limit, metadata, and evidence now come from
  YAML.
- Replaced the non-systemd body of the former direct dead-box loop with the
  mandatory phase-28 `direct_attack_semantics` ordered-row definition. YAML
  owns `authorized_keys`, recovery-inhibition, credential, discovery, cleanup,
  service-stop, SMB/remote-service, alternate-authentication, application-
  protocol, and account-removal inputs, timestamp taxonomy, literals, regexes,
  Windows event IDs, source-signal conditions, ordered precedence, all fifteen
  emissions, confidence, and evidence. Python retains generic vector
  evaluation and sparse max-merge mechanics only.
- Isolated `systemd_service_persistence` in its specialised phase-20 executor
  and moved its timestamp-kind precedence and tokens into YAML. Systemd and
  web-shell artefact paths/extensions, plus web-upload execution target values,
  are now declared directly in their owning definitions instead of shared
  `*_from` registries.
- Made systemd branch topology authoritative: YAML now owns explicit branch
  order, first-match versus all-match handling, and OR-of-AND fact clauses for
  artefact and command activity. The executor evaluates those clauses instead
  of imposing its former fixed persistent/transient/unit-reference expression.
- Removed and now reject the shared `engine_config.path_taxonomy`,
  `detection_vocabulary`, `detection_event_ids`, and `detection_thresholds`
  rule-logic sections. `engine_config.schema_aliases` and
  `engine_config.temporal_signal_policy` are config-only as well: omitted
  aliases or ineligible signals no longer receive Python defaults.
- Moved canonical persistence and transfer derivation onto the required
  `canonical_persistence_projection`, `canonical_transfer_projection`, and
  `canonical_transfer_post_temporal_projection` definitions. Each ordered
  projection now owns its inputs, `any`/`all` exclusive gate,
  maximum-matched-input strength propagation, emission metadata, enablement,
  and matched-signal evidence. Contextual projections run at phase 29 before
  contextual gates; the post-temporal transfer projection runs at phase 45.
  Python retains row-local numeric evaluation, max merge, and sparse explain
  mechanics.
- Moved ClamAV classification onto the required
  `clamav_classification`/`clamav_classifier` definition. YAML now owns the
  default category, 27 category-token mappings, 28 ordered family overrides,
  generic suppression, all seven emissions, rule metadata, confidence, and
  evidence; Python retains only signature grammar and executor mechanics.
- Moved YARA classification onto the required
  `yara_classification`/`yara_classifier` definition. YAML now owns metadata
  resource handling, defaults and unindexed behaviour, ordered metadata/name
  predicates, distinct-rule strength and score scaling, all eight emissions,
  confidence/evidence, category contribution, and the web/hash referenced-file
  gate; Python retains only corpus grammar and executor/index mechanics.
- Moved exact-path, web-path, and upload-hash referenced-file correlation onto
  the required `referenced_file_correlation` detector at contextual phase 25.
  YAML now owns its filesystem/web-identity field bindings, document roots,
  all propagation emissions, ordered web identity branches, and ordered
  evidence-qualified mapping outputs and branches. These registries accept
  arbitrary configuration-local IDs; Python retains canonical request/path,
  hash-index, identity-merge, and sparse execution mechanics.
- Moved web-shell artefact judgement out of the direct dead-box pass and into
  the required `webshell_artifact` detector at contextual phase 27, after
  referenced-file correlation. YAML now owns its path and text fields,
  web-root and script-extension references, basename/text/signal support,
  exclusive threshold, emission, evidence, confidence, and enablement. The old
  `webshell_name_tokens` and `web_upload_tokens` vocabulary keys are rejected;
  Python retains only path/text normalisation and sparse executor mechanics.
- Added the required `web_request_classification` detector at atomic phase 5.
  YAML now owns raw web fields and sidecar aliases, parser tokens, bounded
  decoding, SQLi/traversal/LFI/RFI/command/probe patterns, upload semantics and
  outcomes, endpoint response baselines, ordered direct-exploit branches, all
  four emissions, and explanation metadata. The old Python SQLi table,
  thresholds, upload verdicts, and direct public-facing exploit pass were
  removed. Nameless configured upload methods promote an executable request
  target such as `PUT /shell.aspx` into the normalized upload identity.
- Made SQLi response inference topology authoritative. YAML now owns baseline
  grouping and required keys, sample admission, partition-wide versus prior-row
  scope, optional lookback, median/mean statistic, threshold-term selection and
  min/max composition, comparison, fallback, and separate fact decisions for
  attempt, anomaly, and probable-success emissions.
- Made upload filename and MIME judgement authoritative. YAML now selects
  non-empty-basename versus non-empty-suffix admission, declares MIME mismatch
  as `all`/`any`/`none` branches over typed extension/content-type facts, and
  supplies distinct ranks used by both initial and SQLi-inferred web-outcome
  selection.
- Moved `web_upload_execution_chain` onto the generic `signal_sequence`
  executor. Its source and execution target signals, dead-box scope, ordering,
  lookback, web-root/combined-text target predicate, emission, and evidence are
  now YAML-owned and independent of `webshell_activity`.
- Exposed strict positive-signal admission in the typed authentication, web
  exploit/mapping, ransomware, artefact-follow-on, download, and generic
  sequence policies. Each signal-bearing condition or source/support/target
  role now requires its own non-negative `minimum_signal_value_exclusive`;
  Python no longer supplies an implicit `> 0` boundary.
- Moved `ransomware_impact`, `automated_exfiltration`,
  `credential_dump_collection`, and `password_store_exfil_chain` onto required
  temporal policy definitions. Their source, support, count, and follow-on
  signals; closed lookbacks; threshold or branch semantics; artifact fields and
  label/copy vocabularies; emissions; and evidence now come from YAML.
  Artefact follow-on qualification is a mandatory configured OR of AND clauses
  over copy-command, text-support, signal-support, and follow-on-signal facts,
  so Python no longer fixes that Boolean topology. The
  `temporal_context_branches`, `counted_signal_window`, and
  `artifact_follow_on_sequence` executors retain only typed validation,
  timestamp/window lookup, path/text normalisation, label matching, and sparse
  emission mechanics. The former temporal-composite threshold keys and
  Python-owned ransom-note vocabulary are rejected.
- Added classifier phase 5 before atomic signal gates at phase 10. Web-request,
  canonical-authentication, and execution-context classification run after
  ordinary atomic rules and before ClamAV/YARA enrichment; same-phase
  dependencies are rejected. Later gates, temporal candidate selection,
  ransomware impact, and credential-dump composites resolve configured
  classifier output names dynamically.
  Disabling either malware classifier removes its direct outputs and category
  support while preserving raw exact-path identity for referenced-file
  propagation.
- Advanced referenced-file manifests to schema v6. Manifests retain and union
  dataset and external-CSV signatures under their respective hit masks, record
  both classifier-policy digests and an input `source_digest` that fingerprints
  YARA corpus bytes and the effective parsed metadata index, rebuild when the
  schema or any digest differs, and reject incompatible direct in-memory reuse.
  Weak or certificate-only YARA is filtered from SHA-256 upload correlation as
  well as URL aliases, with qualification and identity tracked per exact hash
  so reused paths cannot cross-qualify different file versions. AV and Luhn
  hash tags and AV identity are likewise accumulated at exact-hash scope rather
  than reconstructed from path-aggregated evidence.
- Advanced the manifest again to schema v7 with a
  `correlation_policy_digest`, making field, matching, propagation, web-branch,
  and mapping changes part of cache compatibility and source fingerprinting.
  URL aliases and upload basenames that resolve to multiple hit-bearing
  filesystem paths are now omitted instead of unioning unrelated identities,
  resolved exact upload hashes take precedence over basename evidence, and
  access/upload branch explanations retain source-specific identities. Mapping
  conditions may not depend on same-pass mapping outputs.
- Made detector-policy phases explicit. Atomic policy outputs may feed later
  contextual or temporal definitions, while same-phase and backwards
  dependencies fail startup. File lifecycle runs at phase 15, MFT timestomping
  at phase 18, persistence and repeated-schedule policy at phase 19, isolated
  systemd persistence at phase 20, referenced-file correlation at phase 25,
  web-shell artefact classification at phase 27, direct ATT&CK semantics at
  phase 28, contextual canonical projections at phase 29, bounded temporal
  executors at phase 40, and post-temporal projections at phase 45. Downstream
  candidate selection, dampening, and temporal policy executors resolve
  configured inputs and outputs from the registry instead of hard-coded signal
  names.
- Added strict startup validation for the complete policy, required detector
  definitions, known keys and types, lowercase signal names, producer
  availability, executor phase, output ownership, weights, temporal keys, and
  policy dependency constraints. `enabled: false` now disables a required
  detector and removes its outputs from the effective emit registries without
  removing its auditable definition.
- Candidate selection, required-column projection, temporal-stage entry, and
  partition-overlap validation are derived from all enabled temporal policy
  definitions. The obsolete `web_upload_execution_window` threshold is
  rejected in favour of
  `detector_policy.detectors.web_upload_execution_chain.lookback`.
- Added parity, disablement, policy-mutation, generic-extension, execution-order,
  candidate-window, overlap, and invalid-configuration tests for this migration
  tranche.

## 2.31.3 — August 2026

Fixed a crash that aborted an entire dataset when a partition's derived year
fell outside Python's `datetime` range.

- `process_parquet_dataset_partitioned()` built each month window with
  `pd.Timestamp(year=..., month=..., day=...)`, which constructs through
  Python's `datetime` and is capped at `datetime.MAXYEAR` (9999). The
  July 2026 wide-year conversion work deliberately widened the partition
  column to `Int32` and retained implausible-but-parseable timestamps as
  evidence, so the loop could be handed years the constructor cannot
  represent. Four junk rows out of 1,382,975 aborted a full Case1 run after
  28 minutes; ENISA-LOT3 failed the same way on three rows out of 2,552,690,
  one of them the `utmp` false positive over an Office font with year 44567.
- A second boundary case failed even within range: for December the loop
  computed `year + 1`, so a valid `9999-12` partition overflowed to 10000.
- Added `_month_start_timestamp()`, `_month_window_utc()`,
  `_next_year_month()` and `_iter_year_months()`. Windows are now built from
  `numpy.datetime64`, which bypasses the component path; `datetime64[us]`
  spans roughly +/-292,277 years, so every retained timestamp is
  representable. The same component-constructor pattern was also replaced in
  both partition-range loaders, which would have failed once wide-year
  windows reached them.
- **No timestamp is discarded, clamped, or judged implausible.** Deciding
  which timestamps are "valid" is not safe in a forensic tool, where
  anti-forensic tampering is itself the evidence; wide-year rows are now
  processed and scored like any other. They cannot match a bounded temporal
  window, so they remain inert for correlation.
- Behaviour is unchanged for representable years, verified against the
  previous construction for 1970, 2024-01, 2024-12 and 2026-02. Sidecars
  produced by 2.31.2 for datasets without an out-of-range partition are
  therefore unaffected and need no reprocessing.
- Replaced four `Timestamp.to_pydatetime()` calls that bound DuckDB query
  parameters in the two partition-range loaders. These hit the same
  `datetime.MAXYEAR` limit and were not caught by the initial sweep, which
  looked only for the component constructor. Added
  `_duckdb_timestamp_param()`, which binds ISO text instead; DuckDB coerces it
  to the column's timestamp type, preserving the previous tz-aware semantics.
- Added regression coverage for years 23746, 29326, 44567, the 9999-to-10000
  December rollover, wide-year row/window containment, and month iteration
  across a wide-year boundary, plus an end-to-end
  `process_parquet_dataset_partitioned()` run over a Hive dataset holding both
  an ordinary and a wide-year partition. That end-to-end test is what exposed
  the `to_pydatetime()` sites: the unit tests covered the window arithmetic and
  passed while the real code path still failed.

## 2.31.2 — August 2026

Adds injection-probe evidence and removes the whole-partition cost of web
feature materialisation.

- Added the `injection_probe` indicator and the `web_injection_probe` signal
  for requests that test whether a parameter can be broken out of quoting
  without yet forming valid injection syntax — for example
  `?id=2'gejf<'">skpv`. This is recorded at `low` confidence with weight `1`,
  well below `web_sqli_attempt` (4), and is deliberately excluded from
  `exploit_public_facing_app` so probing cannot raise the scored exploitation
  signal. It is emitted only when no stronger web evidence exists on the row,
  so a full payload is never counted twice. Probes map to T1190 as an attempt
  through the usual zero-weight label path.
- On the Case1 Apache corpus this recovers 26 rows that carried no indicator
  at all after the `2.31.1` precision fixes, while all 29 benign
  `?id=<n>&Submit=Submit` lookups remain unflagged.
- Added a vectorised prefilter to `_materialise_normalised_web_features()`.
  The candidate test — non-empty `http_request`/`url`, or a web parser token —
  is the same condition the row loop previously applied one row at a time. On
  a partition with no web records the loop is skipped entirely and the 25
  `chronosift_web_*` columns are created by broadcasting the NA scalar rather
  than validating per-row object arrays.
- On 200,000 non-web rows this reduced the pass from 1,339 ms to 185 ms
  (7.2x) and traced peak allocation from 101.4 MB to 76.1 MB. The column set
  and dtypes are identical between web and non-web partitions, so the sidecar
  schema is unchanged.
- Corrects a measurement error in the `2.31.1` notes below: the figure given
  there as "3.45 s / 101 MB" was recorded with `tracemalloc` active during the
  timed call, which inflates allocation-heavy code. The true `2.31.1` cost of
  that pass was 1,339 ms.

## 2.31.1 — August 2026

Released as `2.31.1` because web request evidence is now interpreted
differently: sidecars written by `2.31.0` and by this version can disagree on
which rows carry web attack indicators and the derived ATT&CK labels, so runs
should not be compared across the two versions without re-processing. The
sidecar column set and the `chronosift_row_id` join key are unchanged.

Covers the three sections below: web attack indicator precision, web-server
file-identity propagation, and the whole-partition contextual optimisation.

## Web Attack Indicator Precision — August 2026

Corrected four web attack indicators that fired on ordinary request syntax.
ChronoSIFT prioritises artefacts for later pipeline stages rather than acting
as a standalone detector, so an indicator that fires on routine traffic
displaces genuine evidence in the ranking.

- `command_injection` now requires a command token in *command position* —
  directly after a shell separator, optionally via a program path. The previous
  form treated the `&` query delimiter as a shell separator and matched `id`,
  `cat`, `type`, and `sh` anywhere in the request; because those are among the
  most common query-parameter names, a stock CMS URL such as
  `/index.php?option=com_content&view=article&id=5` was flagged, contributing
  `exploit_public_facing_app` and a T1190 label. On the Case1 Apache logs this
  affected 2,144 rows, including all 29 unambiguously benign
  `?id=<n>&Submit=Submit` lookups; after the change none are flagged.
- `boolean_tautology` now requires a quote/paren breakout artefact, or a
  numeric operand compared against a number, subquery, or function call.
  `+`-decoded prose such as `?q=cats+and+dogs=1` previously matched the generic
  `and X=Y` shape and emitted `web_sqli_attempt`.
- `path_traversal` now requires an encoded *double* dot in the raw request.
  Bounded decoding already covers singly and doubly encoded traversal, so the
  previous bare `%2e` test only added false positives on ordinary escaped
  filename dots such as `/img/logo%2Epng`.
- `remote_file_inclusion` now requires an inclusion-shaped parameter name or a
  remote target that is itself a script, so redirect and OAuth callback
  parameters carrying absolute URLs no longer match.
- Added `sqli:inline_subquery` for parameter values that open with a subquery,
  such as `?id=(select concat(...))`. These were previously caught only
  incidentally, because `concat` contains the `cat` command token.
- Restricted the referenced-file manifest's SHA-256 index to hit-carrying rows
  in the chunked build path. It previously accumulated every hashed row into a
  dataset-wide `sha256 -> filenames` dict retained across all partitions, with
  a regex per row, even though `_finalise_referenced_file_hit_manifest`
  discards non-hit hashes. The DuckDB fast path already applied this
  restriction through its `WHERE` clause.
- Net effect on the Case1 Apache corpus: flagged rows fall from 2,171 to 2,115
  of 6,243. Every dropped row was flagged solely by the previous
  `command_injection` rule and is either a benign lookup or a quote-breakout
  fuzz probe carrying no SQL syntax; `union_select`, `time_delay`,
  `ordered_probe`, `schema_enumeration`, `stacked_query`, `file_access`,
  `database_function`, and `path_traversal` counts are unchanged.
- Added regression coverage for the benign and exploitation cases in both
  directions, and for the manifest hash-index restriction.

## Whole-Partition Contextual Optimisation — August 2026

Reduced the time and memory cost of non-temporal contextual processing without
changing its whole-partition coverage.

- Reused normalised path, parser, message, hostname, and timestamp-kind arrays
  through an ephemeral per-partition cache. The cache is discarded after the
  contextual stage and does not copy or attach state to the source DataFrame.
- Added conservative vector prefilters to direct dead-box and MFT timestomping
  detection so Python-level interpretation is limited to rows that can match a
  detector or already carry relevant sparse state.
- Hoisted lifecycle taxonomy sets and vectorised path classifications that were
  previously rebuilt or interpreted per row.
- Stopped materialising generic `file_created`, `file_modified`, and
  `file_deleted` signal/explanation payloads in partition mode when the
  individual configured weight is zero. Scored, specialised, and downstream
  lifecycle evidence remains intact. Direct contextual API calls retain the
  legacy payloads by default, and the partition CLI exposes
  `--retain-zero-weight-lifecycle-signals` for compatibility exports.
- On a synthetic 100,000-row ordinary-filestat partition, suppressing those
  score-neutral payloads reduced traced Python peak allocation from 164.4 MB to
  75.8 MB. Shared normalisation reduced the four affected core passes by 11%,
  and the complete optimised non-temporal stage ran in 3.29 seconds. These
  figures describe the synthetic benchmark and are not a projection for a full
  forensic partition.
- Added regression coverage for specialised-signal preservation, optional
  legacy retention, and working-array identity reuse without DataFrame copies.

## Web-Server File-Identity Propagation — August 2026

Extended dataset-wide referenced-file propagation into Apache, nginx, IIS,
MS-IIS, and W3C request records without imposing a temporal proximity window.

- Canonicalised request paths by removing query strings/fragments, decoding
  URL escapes, normalising separators, and resolving dot segments.
- Added configurable document-root aliases that correlate filesystem paths
  such as `/var/www/html/exports/data.sql` with later `/exports/data.sql`
  requests.
- Added direction-aware `web_file_access`, `web_malicious_file_access`,
  `web_sensitive_file_download`, and `web_malicious_file_upload` signals.
  Successful download inference requires a GET response in the 2xx
  range; the base access signal remains available when status is absent or an
  error is recorded.
- Limited web YARA propagation by configurable score, quality, and category
  thresholds; certificate-only and lower-quality matches remain excluded.
- Versioned referenced-file manifests and automatically rebuild older cached
  manifests that lack web-path indexes.
- Added referenced-file manifest schema v3, preserving propagated AV
  signatures/families/categories and strong YARA rule/category/score/quality
  metadata for later web accesses and uploads.
- Advanced the referenced-file manifest to schema v4 with SHA-256 hit and
  identity indexes for hash-first upload correlation. Older v3 manifests are
  rebuilt automatically.
- Added bounded structured multipart/request-body metadata extraction for
  multiple quoted or RFC 5987 filenames, part MIME types, content length and
  SHA-256 values. Stable scalar sidecar columns record these values and classify
  upload outcomes as accepted, redirected, rejected or unknown.
- Added typed, sidecar-stable `chronosift_web_*` feature columns and qualified
  outcomes. SQLi response baselines are now separated by host, HTTP method and
  canonical endpoint.
- Added score-neutral evidence-qualified ATT&CK mappings for T1190,
  T1505.003, T1105 and T1213.006. Successful public sensitive-file responses
  remain an internal transfer signal rather than being over-mapped to an
  exfiltration technique without channel evidence. Web-upload T1105 now
  requires an accepted 2xx response; rejected and status-unknown malicious
  upload attempts retain their source signal without asserting transfer.
- Corrected web atomic-rule scopes to recognise Plaso `parser` values rather
  than relying only on a usually absent `sourcetype` field.
- Added bounded decoding and high-confidence SQLi syntax detection. Probable
  success requires SQLi syntax, a 2xx response, and a response-size anomaly
  against successful non-SQLi responses for the same canonical endpoint;
  redirects, errors, and large unrelated responses are not promoted.
- Fixed candidate-window expansion across pandas datetime resolutions by using
  `DatetimeIndex.searchsorted()` with timestamps and timedeltas directly rather
  than combining resolution-dependent `asi8` values with nanoseconds.
- Declared `pytz` as a runtime dependency because DuckDB requires it when
  materialising timezone-aware Parquet values into Python.
- Made sidecar nested payload schemas deterministic across partitions:
  `chronosift_signals` is now Arrow `MAP<string,double>` and
  `chronosift_explain` is Arrow `LIST<string>` containing canonical JSON
  explanation entries. Heterogeneous web evidence therefore remains nested and
  queryable without switching an entire partition to JSON-text columns.
- Restored those stable on-disk payloads to the existing Python dict/list API
  in ChronoSIFT's DuckDB loaders.

## Wide Forensic Year Partitioning — July 2026

Preserved parseable forensic timestamps whose derived years exceed the signed
16-bit range during JSONL.XZ-to-Parquet conversion.

- Widened derived `year` partition columns from nullable `Int16` to `Int32` in
  both `jsonl_to_parquet_cli_logging.normalise_chunk()` and
  `chronoSIFT_v2_31.normalise_for_parquet()`.
- Retained implausible-but-parseable timestamps as evidence rather than
  clipping or silently discarding them. The triggering ENISA LOT3 record was a
  `utmp` false positive over an Office font with a derived year of `44567`.
- Added regression coverage for the triggering microsecond timestamp and its
  expected partition year.

## Nested Explain Write Hardening — March 2026

Fixed a targeted nested Parquet write failure that showed up in a single `20240212-decrypted-Windows_Server_2022.E01` partition under Arrow nested encoding. The failure was caused by mixed `str`/numeric `file_size` values inside `chronosift_explain` payloads, which forced per-subchunk JSON fallback for `chronosift_signals` / `chronosift_explain`.

- Normalised explain `file_size` values to a stable integer type inside `_normalise_explain_item()` for both the top-level item and nested `evidence` payload.
- Preserved the existing nested-write strategy and chunking model; no dataset-wide rewrite or forced JSON-text fallback was introduced.
- Added compiled-path regression coverage so string-backed `file_size` values are normalised before write-out.
- Added a parquet-write regression that mixes float and string `file_size` inputs and asserts `_write_parquet_subchunk(..., nested_columns_encoding="arrow")` stays on the nested Arrow path.

Validation after rebuilding the compiled module: `198` tests passed.

## Versioned Surface

- Added [chronoSIFT_v2_31.py](chronoSIFT_v2_31.py) as the `v2.31` engine target
- Added [rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml](rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml)
- Added [weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml](rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml)
- Updated [run_chronosift_sidecar_cli.py](run_chronosift_sidecar_cli.py) to point at the `v2.31` engine/config path

## New ATT&CK and Dead-Box Coverage

Implemented direct or composite coverage for the techniques that were previously tracked as `Plaso-possible`, including:

- `T1543.002` systemd service persistence
- `T1098.004` SSH authorized keys persistence
- `T1505.003` web shell artefacts, activity, and upload-to-execution chaining
- `T1036` masquerading
- `T1490` inhibit system recovery
- `T1105` ingress tool transfer
- `T1204` user execution after download
- `T1021.002` SMB/admin-share lateral movement heuristics
- `T1070` indicator removal on host
- `T1486` ransomware-style impact composite
- `T1190` exploit public-facing application
- `T1133` external remote services
- `T1003` credential dumping
- `T1555` credentials from password stores
- `T1083`, `T1018`, `T1033` discovery heuristics
- `T1119` automated collection
- `T1071` application layer protocol
- `T1020` automated exfiltration
- `T1531` account access removal
- `T1550` alternate authentication material

## Engine Improvements

- Added direct dead-box signal families and contextual composites in [chronoSIFT_v2_31.py](chronoSIFT_v2_31.py)
- Added EVTX XML extraction for:
  - group/member names
  - share name, share local path, and relative target name
  - workstation and authentication package context
- Added HTTP fallback parsing from sparse web-log rows, including request-line and W3C/IIS field recovery
- Added upload-filename recovery from multipart data, URL query strings, request paths, and W3C-style request fragments
- Added Windows event handling for:
  - `5140` and `5145` share access
  - `4648` explicit credentials
  - `4725`, `4726`, `4729`, `4733`, and `4757` account/group removal paths
- Expanded EVTX share/account depth so `5140/5145` admin-share and named-pipe access can promote directly to remote-service activity, and privileged-group removals carry stronger `account_access_removal` confidence
- Added bounded temporal composites for:
  - `credential_dump_collection`
  - `password_store_exfil_chain`
  - `web_upload_execution_chain`
  - `webshell_activity`
  - `user_execution_after_download`
  - `ransomware_impact`

## Calibration and False-Positive Hardening

- Added benign admin-query dampening for read-only Windows and Linux inspection commands
- Added benign backup/archive dampening for routine backup-style archive activity
- Reclassified discovery-like commands such as `net view`, `nslookup`, one-shot `ping`, `nltest /dclist`, and `Resolve-DnsName` from generic LOLBin execution to explicit discovery signals
- Tightened noisy status/admin cases including:
  - `schtasks /query`
  - `wmic ... get/list`
  - `reg query`
  - `sc query`, `sc qc`, `sc queryex`
  - `wevtutil qe`
  - `Get-MpPreference`
  - `Get-NetFirewallProfile`
  - `Get-Service`
  - `Get-ScheduledTask`
  - `Get-NetTCPConnection`
  - `Get-Process`
  - `Get-CimInstance`
  - `tasklist /svc`
  - `netstat -ano`
  - `ipconfig /all`
  - `route print`
  - `arp -a`
  - `qwinsta`
  - `quser`
  - `net user <user>`
  - `net localgroup <group>`
  - `net accounts`
  - `gpresult /r`
  - `whoami /groups`
  - `whoami /priv`
  - `klist`
  - `Get-ComputerInfo`
  - `Get-LocalUser`
  - `Get-LocalGroup`
  - `Get-HotFix`
  - `Get-NetIPAddress`
  - `Get-NetRoute`
  - `Get-DnsClientCache`
  - `Get-NetNeighbor`
  - `netsh interface ip show config`
  - `uname -a`
  - `hostnamectl status`
  - `cat /etc/os-release`
  - `ifconfig -a`
- Fixed a Linux interpreter-rule false positive where `sh` matched `ssh` as a substring
- Tightened web exploit heuristics so benign file uploads and ordinary page loads do not raise `exploit_public_facing_app`
- Added bounded query-style web upload detection so sparse `POST /upload.php?name=shell.php` and W3C `cs-uri-query=filename=cmd.aspx` style rows can raise exploit activity without treating every POST as an upload
- Tightened credential-theft chaining so `credential_dump_collection` and `password_store_exfil_chain` prefer same-artifact copy, archive, and transfer evidence instead of unrelated host-level transfer coincidence
- Added direct remote-service inference for Windows share-access events involving `ADMIN$`, `IPC$`, and remote admin pipes like `svcctl`
- Increased confidence for `account_access_removal` when Windows group-removal events target privileged groups such as `Administrators` and `Remote Desktop Users`
- Added `ransomware_extension_burst` so bursts of ransomware-style encrypted file extensions can act as a ransomware source signal even when classic per-directory mass modification is weak or absent
- Expanded `ransomware_impact` so it can derive from either `mass_file_modification` or `ransomware_extension_burst` when paired with recovery inhibition, suspicious execution, or ransom-note timing
- Tightened Windows-network heuristics so ordinary Kerberos network logons do not raise `smb_admin_share` or `external_remote_service`

## Compiled Explain Materialization Fix — March 2026

Fixed a compiled-path regression that blocked every dataset in `prepare_output_partition` after the recent review-column materialization optimisations.

- `_materialise_sparse_event_columns()` now passes NumPy-backed canonical actor / source-IP arrays into `_normalise_explain_item()` without tripping Cython's runtime argument type checks.
- `_normalise_explain_item()` now accepts the array-backed inputs that the caller already materialises on hot partitions, eliminating the batch-wide `Argument 'canonical_actor_values' has incorrect type (expected list, got numpy.ndarray)` failure.
- Added a compiled-module regression test that imports the built `.so` and calls `_normalise_explain_item()` with `np.ndarray` canonical value arrays, so the exact failure mode is covered on the compiled path rather than only in pure Python.

Validation after rebuild:

- `tests/test_v231_regression.py`: `32 passed`
- full `v2.31` suite: `197 passed in 91.37s`

## Batch Startup Regression Fix — March 2026

A fresh four-way rerun exposed a startup regression in the hash-hit CSV loader used by `prepare_file_hit_manifest`.

- Fixed `_load_hash_hit_set_from_csv()` in [chronoSIFT_v2_31.py](chronoSIFT_v2_31.py) so the truthy-hit filter works on the pandas `Index` returned by the normalized enrichment cache path. The broken code called `.ne("")` on an `Index`, which raised before partition processing began.
- Added a regression case in [test_v231_regression.py](tests/test_v231_regression.py) that exercises the direct CSV loader path with mixed truthy/falsy rows and blank hashes.
- Revalidated the `v2.31` suite after the fix: `196` tests passed.

## Tests Added

Added `v2.31` test coverage in:

- [test_v231_integration.py](tests/test_v231_integration.py)
- [test_v231_canonical_auth_or_context.py](tests/test_v231_canonical_auth_or_context.py)
- [test_v231_regression.py](tests/test_v231_regression.py)

These tests cover:

- direct dead-box signals
- temporal composites
- parser-aware Windows EVTX handling
- sparse web-log handling
- benign admin/status query suppression
- backup/archive dampening
- discovery reclassification
- `v2.30` regression safety
- Winlogon helper registry persistence (T1547.004) — positive and negative cases
- COM hijacking registry persistence (T1546.015) — positive and negative cases
- service stop commands and EVTX 7036 detection (T1489) — positive and negative cases
- MFT timestomping detection (T1070.006) — positive, negative, and parser-scoping cases

## Post-Review Hardening (March 2026)

Deep review of v2.31 identified and patched the following:

- **`.ashx` added to `web_script_extensions`**: ASP.NET HTTP handlers were treated as web-executable in temporal composite context checks but were missing from the `web_script_extensions` vocabulary, so `webshell_artifact` and `web_executable_file_created` would not fire on `.ashx` files. Added to both Python defaults and YAML config.
- **Benign admin dampening command-chaining guard**: `_looks_like_benign_admin_query_command` now rejects commands containing shell chaining operators (`&&`, `||`, `;`) before matching benign patterns. Prevents evasion by prepending a benign query to a malicious payload. Single pipe (`|`) is allowed since piped commands like `ps aux | grep` are legitimate admin patterns.
- **`web_script_target` tightened**: Substring extension matching (e.g., `.pl`, `.asp`) was applied to the full combined text, risking false positives on unrelated words. Now checks `http_path` or file path only, using `endswith` and query-string positional checks.
- **Discovery reclassification explain enriched**: Explain entries now include `preserved_discovery_signals` and `dampened_signals` keys (previously only `signals` key documenting what was zeroed, with no record of what was preserved).
- **Duplicate `combined` computation removed**: Copy-paste artifact in `_apply_deadbox_temporal_composites_sparse` where `combined` was computed identically twice in succession.
- **`webshell_events` type annotation fixed**: Corrected from `Dict[Tuple[str, str], ...]` to `Dict[str, ...]` to match actual keying by hostname string.
- **Redundant `startswith` in backup archive check removed**: `s.startswith(f"{name} ")` is a subset of `f"{name} " in s`; simplified.
- **Missing canonical auth weights added**: `auth_remote_interactive_success` and `auth_remote_shell_success` were emitted by Python canonical auth derivation but had no weight entries. Added at weight 0 (canonical taxonomy signals, not independently scored).
- **`path_l` undefined in persistence detection**: `_apply_persistence_and_config_signals_sparse` referenced `path_l` for winlogon and COM hijack token matching, but the variable was never computed in that method's loop (it existed in the sibling deadbox method). Added `path_l = _safe_str(path).strip().lower().replace("\\", "/")`.
- **Timestomping archive-extraction false-positive dampening**: Files extracted from archives (ZIP/RAR/7z/tar) produce `$FN creation > $SI creation` because Windows sets $SI to the original in-archive timestamp while $FN reflects extraction time. Added two dampening heuristics: (1) OS-update/installer path exclusion, (2) bulk directory threshold — when ≥5 files in the same parent directory show the pattern, confidence is downgraded from "high" to "low" with `bulk_extraction_dampened` evidence flag. Empty-parent sentinel prevents rootless-path files from aggregating falsely.
- **`"service stop"` command token removed from detection vocabulary**: The token false-positived on EVTX 7036 messages like "The X service stopped" where `"service stop"` is a substring of `"service stopped"`. The standard Linux SysV syntax (`service <name> stop`) does not produce a contiguous `"service stop"` substring, so the token had no valid match targets. Linux service-stop is already covered by `"systemctl stop"`.
- **Duplicate weight entries removed**: `auth_remote_interactive_success` and `auth_remote_shell_success` appeared twice in the weights file (lines 12-13 and 18-19). Removed the duplicates.

## Performance Hardening for Full-Dataset Use (March 2026)

Deep review for full-dataset readiness identified and fixed the following performance issues:

- **Pre-extracted DataFrame columns in temporal composites**: `relative_path`, `pathspec`, and `link_target` column values were being accessed via `df["col"].values[i]` inside a list comprehension, which re-created numpy arrays on each iteration. Pre-extracted to Python lists before the comprehension.
- **`itertools.chain` replaces list concatenation in temporal composites**: Three locations in `_apply_deadbox_temporal_composites_sparse` used `archive_events.get(host, []) + transfer_events.get(host, []) + copy_stage_events.get(host, [])` which allocated a new list on every call. Replaced with `itertools.chain()` for zero-allocation iteration. Also fixed inside `_has_staged_then_exfil` inner loop where `archive_events.get(host, []) + transfer_events.get(host, [])` was being concatenated per outer-loop iteration.
- **Two-pass value caching in temporal composites**: The second pass of `_apply_deadbox_temporal_composites_sparse` redundantly recomputed `host`, `path`, `base`, `combined`, `combined_norm`, `password_labels`, and `dump_labels` for every row — identical work to the first pass. Added parallel cache lists populated during pass 1 and consumed in pass 2, eliminating redundant `_safe_str`, `os.path.basename`, `_extract_password_store_labels`, and `_extract_credential_dump_labels` calls. Also pre-extracted `df.index` to a Python list for faster timestamp access.
- **`combined` → `combined_norm` in web execution context check**: The second-pass `web_execution_context` token check referenced `combined` which was no longer computed after caching refactor. Switched to `combined_norm` — functionally equivalent since the web-root tokens (`/var/www/`, `.php`, `.aspx`, etc.) do not contain backslash-space sequences.

## Duplicate-Timestamp Stability and Sparse-Path Hardening (March 2026)

Deep review of the post-optimisation code identified and fixed the following:

- **Stable duplicate-timestamp ordering**: added `_stable_sort_datetime_frame()` and routed parquet load, atomic entry, and parquet normalisation through it. Equal timestamps now use stable `mergesort` with `chronosift_row_id` as the tie-break when available, preventing nondeterministic positional temporal behaviour on non-unique `DatetimeIndex`.
- **Auth sparse prefilter bounds/skip fix**: `_apply_canonical_auth_signals_sparse()` now uses positional boolean arrays instead of testing integer row positions against a `DatetimeIndex`. This restores the cheap skip for rows already carrying `auth_outcome` and safely ignores stale out-of-range sparse-state keys.
- **Candidate subsetting made positional and cheaper**: `_subset_sparse_state()` now uses `np.flatnonzero(mask)` plus `.iloc[...]` instead of a Python mask walk followed by boolean `.loc[...]`, reducing mask re-scans and staying aligned with the non-unique-index safety rule.
- **Candidate window de-duplicates identical hit timestamps**: `_build_candidate_window_mask()` now computes `searchsorted()` bounds once per unique hit timestamp instead of once per hit row, reducing wasted work on bursty same-timestamp partitions.
- **File-path coalescing now actually vectorised**: `_best_effort_file_path_vectorised()` now uses a column-wise `_normalise_reference_path_series()` helper instead of looping row-by-row through unresolved positions.
- **Atomic required-column contract includes row-id tie-break**: `chronosift_row_id` is now always projected into the atomic pass so the stable duplicate-timestamp ordering rule can be enforced consistently during sidecar and base-dataset processing.

### Regression coverage

Added regression tests for:

- stable duplicate-timestamp ordering in `_restore_datetime_index()` and `apply_atomic()`
- vectorised file-path coalescing parity with the scalar reference helper
- positional sparse-state subsetting under duplicate timestamps
- candidate-window equivalence with duplicate hit timestamps
- auth sparse prefilter safety with stale sparse-state keys

Test status after these changes:

- `171` tests pass

## Contextual Hot-Path Vectorisation and Copy Reduction (March 2026)

Follow-on optimisation of the reviewed hot paths focused on removing avoidable DataFrame copies while preserving the non-unique-`DatetimeIndex` safety rules.

- **Vectorised `yara_match_count` normalisation**: added `normalise_yara_match_count_series()` and replaced the remaining scalar `apply/map(normalise_yara_match_count)` paths in atomic normalisation, generic normalisation, and hit-manifest derivation.
- **Shared zero-copy column accessor**: added `_column_values_or_none()` so sparse contextual passes can reuse `to_numpy(copy=False)` arrays instead of rebuilding `list(df[col].values)` snapshots for missing-safe reads.
- **File lifecycle now reuses vectorised path/kind helpers**: `_apply_file_lifecycle_signals_sparse()` now precomputes `_best_effort_file_path_vectorised()` and `_timestamp_desc_kind_vectorised()` once per partition, then derives extensions and flags from those arrays.
- **Timestomping detection avoids row-wise path coalescing**: `_apply_timestomping_detection_sparse()` now uses the vectorised path precompute instead of calling `_best_effort_file_path_values()` for every candidate row.
- **Dead-box direct contextual path de-duplicated**: `_apply_deadbox_direct_signals_sparse()` now uses precomputed file paths, timestamp kinds, and zero-copy arrays for the remaining referenced columns, cutting repeated scalar extraction in one of the hottest contextual passes.
- **Persistence/config pass copy reduction**: `_apply_persistence_and_config_signals_sparse()` now reads its supporting columns through zero-copy arrays instead of list materialisation while keeping the prior vectorised path/kind classification.
- **Referenced-file propagation avoids redundant filename normalisation**: the propagation pass now normalises the current filename column once up front and reuses those values when matching referenced hit files.

### Regression coverage

Added regression tests for:

- series-based `yara_match_count` normalisation parity with the scalar reference helper
- file-lifecycle detection when the resolved path comes from `pathspec`, exercising the vectorised path precompute

Test status after these changes:

- `173` tests pass

## Sparse Utility and Dampening Pass Copy Reduction (March 2026)

Continued optimisation of the remaining low-risk hot paths focused on replacing scalar normalisation and Python-list column snapshots with shared zero-copy array access.

- **Vectorised `ipv4_first` normalisation**: added `normalise_ipv4_first_series()` and replaced the remaining scalar `apply(normalise_ipv4_first)` path in generic normalisation.
- **Execution-context pass avoids Series positional access**: `_derive_execution_context_signals_sparse()` now converts the coalesced path and command candidates to arrays once and reads actor values through zero-copy column access instead of repeated `.iloc[...]` and list materialisation.
- **Dampening/reclassification passes use zero-copy arrays**: trust dampening, benign admin dampening, discovery reclassification, and benign backup dampening now read their supporting columns through `_column_values_or_none()` rather than rebuilding Python lists.
- **AV signal injection avoids list materialisation**: `_inject_av_signal_sparse()` now uses array-backed reads for `av_hit`, `filename`, and `av_signature` while preserving category-aware ClamAV signal semantics.
- **Private-IP continuity grouping now uses array-backed keys**: `_apply_private_ip_continuity_sparse()` now groups on `to_numpy(copy=False)` arrays instead of `list(df[k].values)`, reducing per-partition allocation overhead in the contextual continuity pass.

### Regression coverage

Added regression tests for:

- series-based `ipv4_first` normalisation parity with the scalar helper

Test status after these changes:

- `174` tests pass

## Cached HTTP Parsing and Dead-Box Composite Follow-On Optimisation (March 2026)

Continued optimisation of the higher-cost contextual paths focused on repeated string parsing and duplicate follow-on scans inside dead-box logic.

- **Cached HTTP request semantics**: `_extract_http_request_semantics()` now delegates to an LRU-cached string-tuple helper so repeated request-line, W3C, and URL parsing across similar rows does not redo the same regex and `urlparse()` work.
- **Cached upload-name extraction**: `_extract_http_upload_name()` now also uses an LRU-cached string-tuple helper, reusing derived upload filenames across repeated multipart and request-line patterns.
- **Referenced-file propagation precomputes direct path normalisation**: execution-context columns now carry both raw values and pre-normalised direct path arrays, avoiding a per-row `_normalise_reference_path()` call inside the propagation inner loop.
- **Mixed-object coalescing drops `Series.map()` fallback**: `_normalise_coalesce_candidate_series()` now uses array-backed normalisation for mixed object columns instead of `values.map(normalise_coalesce_value)`, reducing overhead in the generic coalescer path.
- **Dead-box direct path hoists constant vocab**: `_apply_deadbox_direct_signals_sparse()` now resolves detection-term lists and event-id sets once per partition instead of on every row.
- **Dead-box temporal follow-on checks merged**: `_apply_deadbox_temporal_composites_sparse()` now builds a combined archive/transfer follow-on index so labelled follow-on and staged-exfil checks stop scanning the archive and transfer structures separately.

### Regression coverage

Added regression tests for:

- mixed-object coalescing parity with the scalar reference helper
- cached HTTP request/upload helper behaviour on upload-style request strings

Test status after these changes:

- `176` tests pass

## Persistence and Dead-Box Direct Loop Hoisting (March 2026)

Applied another small optimisation pass focused on eliminating repeated lookups and string work inside the persistence/config and dead-box direct sparse passes.

- **Persistence/config lookups hoisted**: `_apply_persistence_and_config_signals_sparse()` now resolves the repeated detection-term token sets and event-id sets for Defender disablement, firewall changes, account creation, privileged-group changes, and Winlogon persistence once per partition instead of once per row.
- **Dead-box direct lookups hoisted further**: `_apply_deadbox_direct_signals_sparse()` now precomputes the remaining shared detection vocab including share-access event IDs, `systemd` unit suffixes, admin-share suffixes, and the web-script extension set before entering the row loop.
- **Per-row URL/message normalisation reused**: the dead-box direct loop now derives `message_l`, `url_text`, and truncated URL evidence once per row and reuses them across the remote-service, webshell, share-access, and service-control checks instead of repeatedly re-reading and re-normalising the same values.

Test status after these changes:

- `176` tests pass

## Referenced-File Propagation and JSON Fallback Reduction (March 2026)

Applied another optimisation pass focused on the referenced-file propagation path and the parquet JSON fallback path, both of which were still doing avoidable scalar work on large partitions.

- **Reference-path normalisation and basenames cached**: `_normalise_reference_path()` now routes through a cached string helper, and repeated basename derivation for hit manifests and propagation reuse a dedicated cached helper instead of re-normalising the same paths.
- **Referenced-file propagation avoids redundant text extraction**: `_apply_referenced_file_hit_signals_sparse()` now separates true free-text execution-context columns from direct-path columns, so columns like `new_process_name`, `file_path`, `parent_process_name`, and `service_dll` stop paying regex extraction costs on every row.
- **Hit-manifest accumulation stays array-backed**: `build_global_referenced_file_hit_manifest()` now reuses vectorised normalised filenames and boolean/numeric arrays instead of converting filenames and hit flags into Python lists before accumulation.
- **JSON fallback only serialises populated rows**: both `_prepare_nested_columns_json_fallback()` and `normalise_for_parquet()` now serialise only non-null object payload rows into JSON text, preserving nulls cheaply and avoiding full-column `map(...)` work on sparse nested/object columns.
- **Small helper cleanup**: the cached HTTP request/upload helpers and EVTX `strings` IP extraction now avoid a few remaining duplicate `_safe_str(...).strip()` calls and generator re-evaluations.

### Regression coverage

Added regression tests for:

- referenced-file propagation via direct path columns
- referenced-file propagation via free-text extraction columns
- JSON fallback / parquet normalisation preserving nulls while serialising nested payloads

Test status after these changes:

- `179` tests pass

## Command Classification and Parquet Object Classification Reduction (March 2026)

Applied another small optimisation pass focused on removing repeated tokenisation in execution-context derivation and repeated pandas scans in parquet object-column normalisation.

- **Execution-context command parsing is now single-pass**: `_derive_execution_context_signals_sparse()` now classifies compiler, shell, network, and archive tool mentions through one cached token scan instead of tokenising the same command four separate times.
- **Command token extraction is cached and basename-aware**: the new command classifier reuses the cached basename helper for path-like command tokens, preserving the existing exact-name semantics while avoiding repeated `re.findall(...)` and `os.path.basename(...)` work in this hot pass.
- **Object-column type classification is now one-pass**: `normalise_for_parquet()` now classifies non-null object payloads through one NumPy-backed pass, replacing the previous `map(isinstance)` plus `map(type).value_counts()` pair of pandas scans.
- **Nested payload handling remains unchanged**: nested dict/list/tuple payloads still route through JSON-text serialisation, but the type-classification path now reaches that decision without the extra intermediate Series allocations.

### Regression coverage

Added regression tests for:

- multi-class command-tool detection through the cached classifier helper
- parquet object-column coercion preserving the expected string / boolean / integer / float / JSON-text outputs

Test status after these changes:

- `181` tests pass

## Canonical Auth and Dampening Command-Text Reuse (March 2026)

Applied another targeted optimisation pass focused on the canonical auth sparse pass and the three command-based dampening/reclassification passes.

- **Canonical auth fields are normalised once per partition**: `_apply_canonical_auth_signals_sparse()` now precomputes stripped/lowercased arrays for auth outcome, protocol, direction, logon type, message, and authentication package instead of repeating `_safe_str(...).strip()` work inside the candidate-row loop.
- **Auth outcome prefilter now reuses the same normalised arrays**: the candidate selection path uses the precomputed auth-outcome array directly, removing the extra `Series.astype(...).str...` pipeline that previously existed only for the prefilter.
- **Command text is built once and reused across dampening passes**: `_apply_benign_admin_dampening_sparse()`, `_apply_discovery_reclassification_sparse()`, and `_apply_benign_backup_dampening_sparse()` now share a cached combined `actor_cmd + command_line + message` array instead of rebuilding the same string three times.
- **No semantic broadening in dampening logic**: the `looks_like_*` helpers still receive the same raw joined command text, so this change is strictly about reuse and allocation reduction rather than changed heuristics.

### Regression coverage

Added regression tests for:

- shared combined command-text joining and cache reuse
- canonical auth remote / invalid-user inference under pre-normalised auth fields

Test status after these changes:

- `183` tests pass

## Hash and NSRL Enrichment Alignment Pass Reduction (March 2026)

Applied another targeted optimisation pass focused on the two enrichment helpers that were still performing repeated per-column `Series.map(...)` lookups over the same normalised hash keys.

- **Generic hash enrichment now aligns once per lookup**: `_apply_hash_enrichment_csv()` now reindexes the cached enrichment frame against the normalised hash Series in one pass, then overlays the aligned columns back onto the timeline instead of remapping each enrichment column independently.
- **NSRL cache enrichment now reuses an aligned lookup frame**: `_apply_nsrl_enrichment_from_cache()` now resolves `nsrl_application_type` and `nsrl_is_os_component` through one aligned lookup frame rather than two separate dict-map passes over the masked hash subset.
- **Prepared NSRL caches now retain a reusable lookup frame**: `_prepare_nsrl_cache_df()` stores the hash-indexed lookup DataFrame alongside the legacy dict caches so repeated enrichments can reuse the same aligned structure without rebuilding it.
- **Hash alignment helper is shared**: a new `_reindex_lookup_frame_for_hashes()` helper handles the common “normalised hash Series -> aligned enrichment frame” path, keeping the generic and NSRL enrichment logic consistent.

### Regression coverage

Added regression tests for:

- generic hash enrichment preserving unmatched existing values while overlaying aligned CSV columns
- NSRL cache enrichment preserving candidate-mask semantics and duplicate-hash alignment

Test status after these changes:

- `185` tests pass

## Canonical Collapse Copy Removal and Trust-Dampening Cleanup (March 2026)

Applied another small optimisation pass focused on the canonical signal-collapsing helpers and the trust-dampening path.

- **Canonical signal collapsers stop copying `signal_map.items()`**: `_derive_canonical_execution_signals_sparse()`, `_derive_canonical_transfer_signals_sparse()`, `_apply_execution_family_signals_sparse()`, and `_derive_canonical_persistence_signals_sparse()` now iterate the existing signal-map view directly instead of materialising a throwaway list copy when they are only mutating nested values and explain notes.
- **Trust dampening keeps the faster scalar lookup path**: an attempted full-array normalisation for trust dampening was benchmarked and rejected; the final version keeps the lower-allocation scalar normalization path while preserving the new regression coverage for normalized principal/IP/ASN matching.
- **Batch kept only measured wins**: this pass explicitly drops the regressing trust-array experiment and retains only the copy-removal cleanup that still improved the targeted benchmark paths.

### Regression coverage

Added regression tests for:

- trust dampening matching trusted principals / IPs / ASNs despite whitespace and case variation
- the existing canonical execution / transfer / persistence collapse coverage continues to pass unchanged

Test status after these changes:

- `186` tests pass

## Persistence/Config Sparse Pass Normalisation Reuse (March 2026)

Continued optimisation of the contextual sparse passes focused on the lower-risk persistence/config path before moving deeper into the dead-box direct loop.

- **Persistence/config field normalisation is now precomputed once per partition**: `_apply_persistence_and_config_signals_sparse()` now reuses stripped/lowercased arrays for `parser`, `message`, `xml_string`, `event_identifier`, `target_user_name`, `group_name`, `hostname`, and `timestamp_desc` instead of repeating `_safe_str(...).strip()` work inside the row loop.
- **Path taxonomy checks now reuse the vectorised lowercased path**: the cron, firewall, group-policy, Winlogon, COM hijack, and service-config path checks now operate on the already-normalised `path_l` array instead of re-running the `_looks_like_*_path()` helpers and path normalisation for every branch.
- **Evidence payloads reuse normalized text**: service-config, firewall, group-policy, Winlogon, and COM-hijack explain entries now reuse the pre-normalised parser/timestamp/hostname/message strings, trimming repeated scalar cleanup in a hot contextual pass.

### Regression coverage

Added regression coverage for:

- persistence/config detection still firing when parser, timestamp description, and hostname arrive with extra whitespace/casing variation

Test status after these changes:

- `187` tests pass

## Dead-Box Direct Normalisation Reuse and Lazy HTTP Parsing (March 2026)

Continued optimisation of the higher-cost contextual direct pass after the persistence/config cleanup, focusing on normalisation reuse without changing the detection branches themselves.

- **Dead-box direct field normalisation is now precomputed once per partition**: `_apply_deadbox_direct_signals_sparse()` now reuses stripped/lowercased arrays for path, parser, message, URL, hostname, actor, auth, share, group, member, workstation, XML, and timestamp fields instead of repeating `_safe_str(...).strip()` work inside the row loop.
- **Path and parser helper checks now reuse normalised values**: systemd-unit, `authorized_keys`, password-store, log/history, web-root, and web-log parser checks now operate on the pre-normalised `path_l` / `parser` values instead of re-entering the corresponding helper normalisers on each branch.
- **HTTP request parsing is now lazy**: `_extract_http_request_semantics()` and `_extract_http_upload_name()` are now only invoked for rows that already exhibit web-request semantics, instead of running on every row through the dead-box direct pass.

### Regression coverage

Added regression coverage for:

- dead-box direct `authorized_keys` persistence still firing correctly when path, timestamp description, and actor identity arrive with whitespace/casing variation

Test status after these changes:

- `188` tests pass

## Continuity Key Normalisation Reuse (March 2026)

Continued optimisation of the continuity-style contextual passes, focusing on the remaining row-by-row actor/IP key cleanup.

- **Private-IP continuity now reuses normalised actor and IP arrays**: `_apply_private_ip_continuity_sparse()` now precomputes stripped actor-key and IP text arrays once per partition instead of rebuilding them via `_safe_str(...).strip()` inside the grouping and comparison loops.
- **Geo continuity now reuses normalised actor-key and IP arrays**: `_apply_geo_continuity_sparse()` now builds its actor key tuples from pre-normalised arrays and reuses stripped IP text directly in evidence payloads instead of re-normalising each key component per auth-success row.
- **Geo marker columns use direct column creation**: the `geo_new_*` and `geo_boundary_crossing` booleans are still created lazily when missing, but now use direct column assignment rather than `.loc[:, ...]` setup.

### Regression coverage

Added regression coverage for:

- private-IP continuity still correlating the same actor when actor and IP values arrive with whitespace variation
- geo continuity still correlating the same actor when actor key fields arrive with whitespace variation

Test status after these changes:

- `190` tests pass

## Dead-Box Temporal Precompute Reuse (March 2026)

Returned to the temporal composite path and tightened the precompute phase without changing the composite correlation logic itself.

- **Temporal composite pass now reuses normalised path and text inputs**: `_apply_deadbox_temporal_composites_sparse()` now precomputes lowercased/trimmed path, filename, message, and command-line values once before pass 1 instead of re-running `_safe_str(...).strip().lower()` inside the per-row cache builder.
- **Composite basename fallback reuses cached filename normalisation**: the `base` derivation now falls back to a cached lowercased filename string rather than re-normalising the filename inside the hot pass-1 loop.
- **Combined text assembly no longer lowercases twice**: the pass-1 cache builder now joins already-lowercased message/command/path/base components directly, avoiding an extra `.lower()` on the combined string.

### Regression coverage

Added regression coverage for:

- dead-box download-to-execution correlation still matching filenames correctly when download and execution rows differ only by whitespace/casing in the filename field

Test status after these changes:

- `191` tests pass

## File-Lifecycle Normalisation Reuse (March 2026)

Continued optimisation of the remaining high-cost direct sparse passes, focusing on file lifecycle because it was the heaviest remaining measured hotspot.

- **File-lifecycle path/message normalisation is now precomputed once per partition**: `_apply_file_lifecycle_signals_sparse()` now reuses normalised path, message, hostname, parser, and timestamp-description arrays instead of re-running string cleanup and path helper normalization across multiple lifecycle branches.
- **Path-taxonomy checks now reuse normalised paths directly**: web-root, sensitive-path, and database-dump heuristics now operate on the pre-normalised `path_lower` values instead of re-entering `_looks_like_*` helper normalisers per row.
- **Lifecycle follow-on groupers reuse normalised host/path values**: the short-lived-file, mass-file-modification, and ransomware-extension accumulators now build keys from cached lowercased host/path strings rather than re-normalising those values in each follow-on loop.

### Regression coverage

Added regression coverage for:

- database-dump candidate detection still firing correctly when both the file path and message text arrive with whitespace/casing variation

Test status after these changes:

- `192` tests pass

## Execution-Context Normalisation Reuse (March 2026)

Continued optimisation of the remaining scalar execution-family helpers after the file-lifecycle pass.

- **Execution-context path/cmd/actor normalisation is now precomputed once per partition**: `_derive_execution_context_signals_sparse()` now reuses stripped/lowercased path, basename, command, and actor arrays instead of re-running `_safe_str(...).strip()` and `.lower()` inside the row loop.
- **Execution path token checks now reuse normalised path tokens**: the temp, user-writable, and suspicious-path lookups now operate on pre-normalised token tuples and cached lowercased path strings rather than re-normalising both sides for each branch.
- **Command classification is cached for repeated command strings**: repeated `cmd_l` values now reuse a small per-pass classification cache instead of re-running `_classify_command_name_mentions()` for identical command lines.

### Regression coverage

Added regression coverage for:

- execution-context signals still firing correctly when path, command, and actor fields arrive with whitespace/casing variation

Test status after these changes:

- `193` tests pass

## Trust and Timestomping Normalisation Reuse (March 2026)

Took the next two measured hotspots after execution-context and kept only the changes that were still positive against the `247f2fc` baseline.

- **Trust dampening now reuses pre-normalised identity fields**: `_apply_trust_dampening_sparse()` now reads lowercased `actor_principal` plus stripped `ip_address` / `geo_asn` arrays through `_normalised_text_array()` instead of re-running `_safe_str(...).strip()` inside the sparse row loop.
- **Timestomping detection now reuses pre-normalised parser and timestamp-description arrays**: `_apply_timestomping_detection_sparse()` now precomputes stripped/lowercased `parser` and `timestamp_desc` arrays once per partition rather than normalising both fields for every row in the MFT scan.
- **Timestomping path keys are now built once per row**: the MFT pass now precomputes lowercased slash-normalised `path_key` values from the vectorised file-path array and reuses them when partitioning `$STANDARD_INFORMATION` and `$FILE_NAME` creation events.

### Benchmark

Measured against commit `247f2fc`:

- trust dampening: `0.3609s` -> `0.2842s` (`21.3%` faster)
- timestomping: `1.8526s` -> `1.6950s` (`8.5%` faster)

### Regression coverage

Added or retained coverage for:

- trust dampening still matching trusted principal/IP/ASN values when those fields arrive with whitespace/casing variation
- timestomping still firing when `parser` and `timestamp_desc` values carry mixed case and surrounding whitespace

Test status after these changes:

- `194` tests pass

## Discovery Command-Line Context Fix (March 2026)

Closed a dead-box discovery blind spot in the direct contextual pass.

- **Discovery gating now accepts command-line-only rows**: `_apply_deadbox_direct_signals_sparse()` no longer requires `actor_cmd` specifically before checking `file_discovery_command_tokens`, `remote_discovery_command_tokens`, and `system_owner_discovery_command_tokens`. It now gates on `bool(actor_cmd or cmdline)`, so Windows process-creation rows with only `command_line` populated are not silently skipped.
- **Discovery evidence now preserves the actual command context used**: the three discovery explain payloads now emit `actor_cmd or cmdline` in the `command` evidence field instead of leaving that field blank on command-line-only rows.

### Regression coverage

Added integration coverage for:

- command-line-only discovery rows still emitting `file_and_directory_discovery`, `remote_system_discovery`, and `system_owner_user_discovery`, with the recovered command text preserved in evidence

Test status after these changes:

- `195` tests pass

## YARA Forge Category-Aware Scoring (March 2026)

Implemented category-aware YARA signal scoring using metadata parsed from YARA Forge `.yar` rule files. Previously, all YARA hits were treated identically (count-based `yara_hit_strength` saturating at 3 hits). Now, when a YARA Forge metadata file is configured, the engine classifies each matched rule into a forensic category and applies differential weighting.

### YARA Forge Metadata Parser

- New `parse_yara_forge_metadata()` function parses YARA Forge concatenated `.yar` files (~17MB / 10.5K rules in ~1.5s)
- Extracts `score`, `quality`, and classifies rules into forensic categories
- New `extract_yara_rule_names()` function parses variable-format `yara_match` column values into individual rule name lists

### Category Classification

Rules are classified using a priority hierarchy: `tc_detection_type` metadata → inline tags → `category` metadata → rule name pattern matching → default `malware`.

| Category | Signal | Weight | Rule Count (Extended) | Examples |
|---|---|---|---|---|
| `offensive_tool` | `yara_offensive_tool` | 10 | 899 | Mimikatz, Cobalt Strike, Rubeus, hacktools |
| `ransomware` | `yara_ransomware` | 8 | 463 | LockBit, Conti, BlackCat, Akira |
| `webshell` | `yara_webshell` | 9 | 547 | PHP/JSP/ASPX webshells |
| `apt` | `yara_apt` | 9 | 181 | APT-attributed malware |
| `exploit` | `yara_exploit` | 7 | 227 | Shellcode, CVE payloads, rootkits |
| `malware` | `yara_malware` | 7 | 6,678 | Generic trojans, backdoors, infostealers |
| `certificate` | `yara_certificate_blocklist` | 0 | 1,566 | Revoked certificate blocklist (dampened) |

### Certificate Blocklist Dampening

Certificate blocklist matches (~15% of the extended ruleset) are excluded from `yara_hit_strength` computation. A file with 3 cert blocklist hits now produces `yara_hit_strength = 0.0` instead of `1.0`. The `yara_certificate_blocklist` signal is still emitted at weight 0 for analyst visibility.

### YARA Score Passthrough

YARA Forge's per-rule `score` metadata (60–100) is used as a multiplier on `yara_hit_strength`: `strength × min(1.0, score / 100)`. The 86% of rules at score=75 produce a 0.75 multiplier; the high-confidence rules at score=90-100 produce near-full strength.

### Composite Feeding

- `yara_ransomware` → alternative `ransomware_source` in ransomware impact composite (alongside `mass_file_modification` and `ransomware_extension_burst`)
- `yara_offensive_tool` → alternative `credential_source` in credential dump collection composite (alongside `credential_dumping`)
- `yara_webshell` → feeds webshell detection via existing `webshell_artifact` path

### Configuration

- `engine_config.yara_forge_metadata_path` in rules YAML specifies the `.yar` file path
- Also available as `yara_metadata_path` parameter to `from_yaml()` and `__init__()`
- When no metadata file is configured, falls back to legacy undifferentiated scoring (backwards compatible)

### Changes Applied To

- `chronoSIFT_v2_31.py`: Parser, classifier, `extract_yara_rule_names()`, modified `_inject_yara_signal_sparse()`, composite wiring
- `rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml`: Added `yara_forge_metadata_path` to engine_config
- `weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml`: Added 7 category-specific weights

## v2.30 Cross-Partition State Fixes (March 2026)

Carried forward from v2.30 hardening:

- **IP continuity carried state**: `_apply_private_ip_continuity_sparse` now accepts and persists `carried_last` state across partitions, matching the pattern used by impossible travel and geo continuity. Previously, IP continuity state was lost at partition boundaries, causing missed detections when an actor's IP changed across a partition seam.
- **Mass file modification OS-update exclusions**: `os_update_path_patterns` added to `path_taxonomy` (Windows: `\winsxs\`, `\softwaredistribution\`, `\windows\assembly\`, `\windows\installer\`; Linux: `/usr/lib/`, `/usr/share/doc/`, `/usr/share/man/`, `/var/cache/apt/`, `/var/cache/dnf/`, `/var/cache/yum/`, `/var/lib/dpkg/`, `/var/lib/rpm/`). Directories matching these patterns are excluded from mass file modification grouping.

## ClamAV Category-Aware Scoring (March 2026)

Parallels the YARA Forge category-aware scoring, applying forensic categorisation to ClamAV detections via structured signature name parsing. Previously, all AV hits were treated identically (`av_hit` weight 8); now the engine parses the `av_signature` column into platform, category token, family name, and forensic category.

### Classification Hierarchy

1. **Family name overrides** (highest priority): 28 known substring patterns (Mimikatz, CobaltStrike, Meterpreter, SharpHound, BloodHound, LockBit, Conti, REvil, Ryuk, C99shell, C99, R57shell, Weevely, etc.) override category-based classification
2. **Category token mapping**: 27 ClamAV category tokens (Trojan, Backdoor, Ransomware, Exploit, Rootkit, Hacktool, Adware, Coinminer, etc.) mapped to 6 forensic categories

### Forensic Categories and Weights

| Category | Signal | Weight | Description |
|---|---|---|---|
| `offensive_tool` | `av_offensive_tool` | 10 | Mimikatz, CobaltStrike, Metasploit, hacktools |
| `ransomware` | `av_ransomware` | 9 | Ransomware family detection |
| `webshell` | `av_webshell` | 9 | C99shell, R57shell, B374k, Weevely, WSO |
| `exploit` | `av_exploit` | 8 | Exploit payloads, rootkits |
| `malware` | `av_malware` | 8 | Generic malware (trojan, backdoor, worm, infostealer, dropper, etc.) |
| `pua` | `av_pua` | 2 | PUA/adware/coinminer/joke — suppresses `av_hit` to avoid score inflation |

### PUA Dampening

PUA detections (adware, coinminer, joke, and `PUA.*` prefix signatures) suppress the `av_hit` signal (weight 8) and emit `av_pua` (weight 2) instead. This prevents low-forensic-relevance detections from inflating event scores.

### Temporal Composite Integration

- `av_ransomware` wired into `ransomware_source` (alongside `mass_file_modification`, `ransomware_extension_burst`, `yara_ransomware`)
- `av_offensive_tool` wired into `credential_source` (alongside `credential_dumping`, `yara_offensive_tool`)

### Multi-Platform Coverage

The parser handles all ClamAV platform prefixes: Win, Linux, Unix, Osx, Php, Html, Js, Java, Doc, Multios, and more. Platform information is preserved in evidence for analyst review.

### Changes

- `chronoSIFT_v2_31.py`: Added `parse_clamav_signature()`, `ClamAVSignatureMeta`, `_CLAMAV_CATEGORY_MAP` (27 tokens), `_CLAMAV_FAMILY_OVERRIDES` (28 patterns), `AV_CATEGORY_SIGNALS`; rewrote `_inject_av_signal_sparse()` for category-aware scoring; wired `av_ransomware` and `av_offensive_tool` into temporal composites
- `weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml`: Added `av_offensive_tool: 10`, `av_ransomware: 9`, `av_exploit: 8`, `av_malware: 8`, `av_pua: 2`, `av_webshell: 9`
- `tests/test_v231_integration.py`: Added `ChronoSiftV231ClamAVCategoryTest` class with 85 tests covering structural parsing, PUA prefix handling, all 27 category tokens, 27 of the 28 family-override patterns, 9 platform variants, and 14 engine integration tests. The standalone `c99` pattern was added to the current 86-test class under Unreleased.

## City-Level Geo Continuity Signal (March 2026)

Added `new_city` signal to the geo continuity detection pipeline, complementing the existing `new_country`, `new_asn`, and `boundary_crossing` signals. Emits when a successful remote authentication originates from a GeoLite2 city not previously seen for the actor.

- **Signal**: `new_city` at weight 3 (low — city changes are common for mobile/VPN users)
- **Confidence**: `medium` (GeoLite2 city-level accuracy is ~70-80% vs ~99% for country)
- **Requires**: `geo_city_name` column from GeoIP enrichment pre-step
- **State**: Tracks per-actor `seen_cities` set, carries across partitions
- **Profiling**: Added to `QUIET_TIME_BOUNDARY` multiplier (k=0.5) alongside country/ASN/boundary signals
- **Graceful degradation**: If `geo_city_name` column is absent, existing country/ASN signals continue to work unaffected

### Changes

- `chronoSIFT_v2_31.py`: Extended `_apply_geo_continuity_sparse()` with city tracking and `new_city` signal emission
- `weights_v8.yaml`: Added `new_city: 3` (replaced commented-out `user_moved_city` placeholder)
- `rules_v10.yaml`: Added `new_city` to `QUIET_TIME_BOUNDARY` profiling multiplier
- `tests/test_v231_integration.py`: Added `ChronoSiftV231NewCityTest` with 11 tests

## Bisect-Optimised Temporal Composites (March 2026)

Replaced all O(n) linear scans inside the `_apply_deadbox_temporal_composites_sparse()` pass-2 loop with O(log n) `bisect`-based window lookups. Previously, each temporal window check (download→execution, webshell activity, ransomware impact, automated exfiltration, credential dump collection, password store exfil chain) scanned the full event list for the host linearly — giving O(n²) overall when a single host had hundreds of thousands of events.

### Changes

- `chronoSIFT_v2_31.py`: Added `import bisect`; after pass-1 accumulation, builds sorted timestamp index arrays for all 8 event accumulators; replaced all inner-loop scans with `_any_in_window_before()`, `_any_in_window_after()`, `_count_in_window_before()`, `_has_labelled_follow_on_bisect()`, `_has_staged_then_exfil_bisect()`, `_any_follow_on_unlabelled_bisect()` — all using `bisect.bisect_left/right` for O(log n) window boundary lookups
- Registered YARA category, ClamAV category, and `new_city` signals in `_collect_emitted_signals_from_rules()` to eliminate spurious "weights defined but not currently emitted" config warning
- `tests/test_v231_integration.py`: Added `ChronoSiftV231ConfigAlignmentTest` asserting no config alignment warnings

### Benchmark (WinSrv 2023-09 partition, 1,340,299 rows)

| Version | Temporal composites | Total | Status |
|---|---|---|---|
| v2.31 pre-fix | stuck (>2h, 100% CPU) | never finished | ❌ |
| v2.30 baseline | 861s | ~1,854s | ✓ |
| **v2.31 bisect fix** | **134s** | **2,297s** | ✓ |

Total time is slightly longer than v2.30 due to additional signal sources (ClamAV/YARA category scoring, timestomping, etc.) but the temporal composites are now 6.4× faster than v2.30.

## Current Verification State

Latest verified results:

- `python3 -m pytest tests/test_v231_integration.py -q` -> `159 passed` (70.85s)

## Required Dependencies Hardening — March 2026

Consolidated conditional imports into hard requirements to eliminate dual-path code and simplify maintenance:

- **DuckDB**: `import duckdb` — required since v2.31. All PyArrow-only fallback paths removed (dataset, partition, sidecar loaders, hour-of-week manifest, file hit manifest, NSRL enrichment). Removed unused imports: `defaultdict`, `copy`, `itertools`, `sqlite3`, `pyarrow.dataset`.
- **GeoIP2**: `import geoip2.database` — required since v2.31. Removed try/except guard and `geoip2_database is None` checks. Fixed resource leak where ASN reader failure left city reader unclosed.
- **YARA Forge metadata**: `yara_metadata_path` or `engine_config.yara_forge_metadata_path` — required since v2.31. Removed legacy undifferentiated `normalise_yara_strength` scoring path. The metadata-aware path recomputes strength from category-filtered non-certificate hit count with score multiplier; the old `min(1.0, count/3.0)` pre-computation was dead weight.

Also removed:
- Dead row-wise helpers (`_best_effort_file_path`, `_extract_scheduled_command_text`)
- All `df.copy()` calls (traced data flow — none were protecting external state)
- Fixed regex backreference bug in `_strip_user_prefix` (`\\1` → `\1`)
- Fixed ClamAV 2-part signature parser (ambiguous prefix treated as category not platform)
- Registered missing geo signals (`new_country`, `new_asn`, `boundary_crossing`) in merge-back

## Vectorisation and Acceleration Pass — March 2026

Systematic performance optimisation targeting million-row timelines. Replaced per-row Python loops and `.apply()` calls with vectorised pandas/numpy operations and sparse pre-filtering.

### Vectorised operations (replacing per-row `.apply()`)

| Operation | Before | After |
|---|---|---|
| `regex_first` normalisation | `re.compile()` per row inside `.apply(lambda)` | Pre-compiled regex + `pd.Series.str.extract()` (one compile, C-level loop) |
| File extension extraction | `.apply(normalise_file_extension)` per row | `pd.Series.str.extract(r'(\.[^./\\]{1,11})$')` vectorised |
| `_timestamp_desc_kind` classification | Per-row `_safe_str().strip().lower()` + substring checks in list comprehension | `_timestamp_desc_kind_vectorised()` using cascaded `str.contains()` regex masks |
| File path coalesce | Per-row `_best_effort_file_path_values()` across 5 columns | `_best_effort_file_path_vectorised()` with positional numpy indexing |
| Geo column cleaning | Full-column `_safe_str().strip().upper()` list comprehensions | `pd.Series.str.strip().str.upper()` with `np.where` for None preservation |
| Actor/src_ip materialisation | `[val if val else None for val in series.tolist()]` | `series.where(series.ne(""), other=None).to_numpy()` |
| IP normalisation | `ip_vals.map(_normalise_ip_literal)` on full column including empties | Pre-filter to non-empty rows before calling `ipaddress.ip_address()` |
| Hash set construction | `.tolist()` + generator filter | Index filtering with `idx[idx.notna()]` then `set()` |

### Sparse pre-filtering (skip 95-99% of rows)

| Loop | Before | After |
|---|---|---|
| Auth signals (`_apply_canonical_auth_signals_sparse`) | `for row_i in range(len(df))` — every row | Vectorised `auth_outcome.isin({"success","failure"})` mask + signal_map rows |
| File-hit propagation (hit_map construction) | `for i in range(len(df))` — every row | `np.flatnonzero(av_mask \| luhn_mask \| yara_mask)` — only hit rows |
| YARA signal injection | `for i in range(len(df))` gated by `yhs > 0` | `np.flatnonzero(ymc_arr > 0)` — direct to candidate rows |
| Profile multiplier application | `for i in range(len(df))` — every row | `sorted(signal_map.keys())` when quiet-hour detection disabled |

### Other optimisations

- **Cached `df.columns.get_loc()`**: Geo continuity loop called `get_loc()` for 4 columns inside every auth-position iteration (O(n_cols) per call). Cached to integer variables before loop.
- **Removed dead `_fallback_condition_mask`**: `df.itertuples` fallback in condition evaluation was unreachable (all ops covered by fast-path `OP_MAP`). Exception/else branches now return `np.zeros`.
- **Detection term/event ID lookup caches**: `_detection_terms_cache` and `_detection_event_ids_cache` dicts avoid repeated dict-get + tuple conversion on hot config lookups.
- **Hour-of-week surprisal**: Replaced per-element `math.log` with vectorised `np.log`.

### Integer addressing for DatetimeIndex safety

All new vectorised code uses positional (integer) indexing rather than label-based `.loc[]` to handle non-unique DatetimeIndex safely. `_best_effort_file_path_vectorised` uses `np.flatnonzero` + `col_vals[pos]`; geo continuity uses `np.where` for object-dtype output (Python `None`, not `pd.NA`).

### Test results

159 tests pass. Test suite time reduced from 109s (pre-optimisation baseline) to 70.85s.

## ATT&CK Coverage Expansion — March 2026

Implemented 4 additional ATT&CK techniques to close remaining dead-box gaps:

- **T1547.004 Winlogon Helper DLL**: Registry path matching for `\Microsoft\Windows NT\CurrentVersion\Winlogon` with write-context detection. Emits `winlogon_helper_persistence` when value tokens (`shell`, `userinit`, `notify`, `appinit_dlls`, `taskman`) are found in the path or message. Weight: 9 (high-impact persistence mechanism).
- **T1546.015 Component Object Model Hijacking**: Registry path matching for `\Classes\CLSID\` and `\Classes\Wow6432Node\CLSID\` with write-context detection. Emits `com_hijack_persistence` when `InprocServer32` or `TreatAs` appears in the path or message. Weight: 7 (medium-high, stealthier persistence).
- **T1489 Service Stop**: Dual detection via command token matching (`sc stop`, `net stop`, `Stop-Service`, `taskkill /f`, `systemctl stop`, `service stop`) and Windows Event ID 7036 with "stopped" message text. Emits `service_stop`. Weight: 3 (common in both adversary and admin contexts).
- **T1070.006 Timestomping**: MFT `$STANDARD_INFORMATION` vs `$FILE_NAME` creation timestamp comparison. Groups MFT parser rows by file path, separates SI and FN creation timestamps, and emits `timestomping` when `$FN creation > $SI creation` by >1 second (indicating the visible SI timestamps were back-dated). Weight: 10 (strong forensic indicator of anti-forensics activity). Includes archive-extraction false-positive dampening: OS-update/installer paths are excluded, and when ≥5 files in the same parent directory all show the $FN > $SI pattern (indicating bulk extraction rather than targeted timestomping), confidence is downgraded from "high" to "low" with a `bulk_extraction_dampened` evidence flag.

Changes applied to:
- `chronoSIFT_v2_31.py`: New helper methods (`_looks_like_winlogon_path`, `_looks_like_com_hijack_path`), persistence detection extensions, new `_apply_timestomping_detection_sparse` method, signal registration
- `rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml`: Added `winlogon_path_patterns`, `com_hijack_path_patterns` to `path_taxonomy`; `service_stop_command_tokens`, `winlogon_persistence_value_tokens` to `detection_vocabulary`; `service_stopped: ['7036']`, `service_start_type_changed: ['7040']` to `detection_event_ids`
- `weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml`: Added `winlogon_helper_persistence: 9`, `com_hijack_persistence: 7`, `service_stop: 3`, `timestomping: 10`

## Remaining Work

The remaining work is mainly depth rather than breadth:

- parser-specific web request and upload semantics
- richer credential-theft and exfiltration chains
- broader Windows EVTX edge-case coverage
- deeper ransomware and impact modeling
- post-implementation weight tuning for low-confidence signals
- ATT&CK coverage gaps: T1546.001 (file association), T1547.009 (shortcut modification), T1529 (shutdown/reboot), T1548.002 (UAC bypass), T1550.003 (Pass the Ticket), T1564.001 (hidden files)
- evaluate switching from YARA Forge extended to full ruleset after first full-dataset validation run
- consider `referenced_file_yara_hit` category-awareness (currently propagated without category differentiation)
