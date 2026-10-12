# Monthly activity profiles

The v27 default policy builds quiet-hours profiles from the **previous UTC calendar month**. It freezes each profile for the following month. Scored activity cannot update that month's profile. Missing months do not borrow a profile from a more distant month. Missing, insufficient and statistically rejected profiles are neutral (1×).

This lifecycle is native to `ChronoSiftEngine`: in-memory `apply`, eager monthly Parquet processing, compact-history processing and the sidecar CLI use the same profile construction and application methods. Existing historical policies without `profiling.monthly` retain their original global-profile behaviour.

## Two training populations

**Filesystem:** use the existing configured parser/path exclusions, then exclude known NSRL OS components or Operating System application types. Build 168 hour-of-week bins from complete Monday–Sunday UTC weeks wholly inside the previous month. Weeks without qualifying activity are omitted rather than treated as observed all-zero weeks. At least the configured number of weeks and events must support the profile. Monthly mode does not fall back to the whole dataset.

**Web:** accept only exact registered access-parser IDs. Apache requires the configured request field; IIS requires a method and a URI stem. Error logs and similarly named parsers are excluded. Parser-specific ordered status bindings cover Apache `http_response_code` and Plaso IIS `http_status` (with legacy `sc_status` and canonical-field fallbacks). Coverage uses all response statuses; training counts use HTTP **200 only**, with NSRL OS exclusion during training. HTTP 206 does not populate the baseline.

The default web window is the first four consecutive observed interior UTC days in the previous month's retained access-log span. Its first and last observed days are excluded because they can be partial. Window selection occurs before validation: a rejected window does not trigger a search through other windows for a favourable result. Missing days break a consecutive run; an observed day containing no successful responses remains a zero-success training day. No dataset dates, incident labels, or detector scores choose the window.

Observed interior days are a retention-coverage proxy, not proof of uninterrupted logging. The four-day profile describes a daily pattern; it does not establish a weekly recurrence. The manifest records this limitation.

## Validation and scoring

Both populations use the repaired native leave-one-block-out log-score gate against a uniform reference, whole-block bootstrap, per-bin jackknife scales and a Bonferroni Student-t floor for simultaneous upper probability bounds. Filesystem blocks have 168 bins; web daily blocks have 24. Confidence is approximate and conditional on representative blocks. Individual events are not treated as independent confidence samples.

A validated conservative deficit produces a factor of `1 + deficit`, from 1× to 2×. For registered web requests, the web profile owns quiet-hours application **for all response statuses**; filesystem quiet hours do not multiply those requests again. Other events use the filesystem profile. NSRL excludes training observations only: an OS-labelled scored event is still eligible for application.

The selected factor multiplies the normal post-trust danger score, then the existing event-score cap applies. A zero base score remains zero. The separate `web_service_disruption` danger contributor remains an ordinary weighted signal and is included before amplification. This is retrospective scoring context, not a blocking decision.

Normal `chronosift_explain` entries include the multiplier and training/scoring boundaries. Sidecar columns include `chronosift_web_activity_deficit`, `chronosift_web_quiet_multiplier`, `chronosift_web_profile_eligible` and `chronosift_profile_quiet_hour`, alongside the existing filesystem profile columns. Compact caches retain web eligibility so raw requests need not be rehydrated for amplification.

## Configuration and cache

The generated v27 policy owns this closed configuration:

```yaml
profiling:
  monthly:
    enabled: true
    web_enabled: true
    web_training_window_days: 4
    web_minimum_complete_days: 3
    web_rule_id: WEB_QUIET_HOURS_AMPLIFIER
    parser_adapters:
      text/apache_access: apache
      text/winiis: iis
    apache_request_field: http_request
    iis_method_field: http_method
    iis_target_fields: [requested_uri_stem, cs_uri_stem]
    status_fields:
      apache: [http_response_code]
      iis: [http_status, sc_status, http_response_code]
```

A complete fixed window must be available even when the validator's minimum is smaller. Window size and minimum are integers from 3 to 28; the minimum cannot exceed the window. Disabling `web_enabled` leaves monthly filesystem profiling enabled. Disabling the existing top-level hour-of-week policy disables profiling application entirely. To reproduce historical global profiling, disable both monthly flags.

The CLI's existing `--profile-manifest-path` stores a versioned monthly bundle. Its fingerprint covers the raw Parquet file inventory (paths, sizes, modification times), configured NSRL source, profiling policy and engine source. A canonical payload digest detects changed cached bins. Old global manifests, changed data/resources/policy/source and modified payloads trigger rebuilding; malformed JSON raises an error. Each scoring-month entry records its previous-month training interval, selected blocks, acceptance and neutral-fallback reason. Run telemetry includes these per-month decisions.

Construction uses one thin DuckDB day/hour census and bounded block matrices. Where raw records lack NSRL labels, the existing distinct-hash lookup supplies training exclusions; there is no full-timeline enrichment or per-event profile scan. Profiles are selected by each row's UTC month, including temporal overlap rows. Raw timestamps and previous result files are not rewritten. Frame metadata retains only its active months, and application uses numeric UTC month arrays rather than per-event month strings.

## Verification

`tests/test_monthly_activity_profiles.py` covers month lag, NSRL lookup and training-only exclusion, fixed web window selection, HTTP-200 training/all-status application, UTC offsets, missing days, zero scores/caps, expiry, separate profile ownership, cache round-trip/tampering/inventory invalidation, raw versus in-memory profile equality, compact cache restoration, and public CLI full/sidecar score and cache parity.
