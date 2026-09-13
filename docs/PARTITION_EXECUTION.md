# Dataset-aware windows and compact contextual history

Rules **v18 / weights v15** change execution, not any detector definition,
weight, ATT&CK mapping or score cap. The v17 scoring policy is preserved
verbatim beneath the new YAML `partition_execution` section. Historical YAML
without this section retains the historical driver. The later v19/v16 pair
inherited this execution policy and added the separate
[Linux/SSH scoring changes](LINUX_TOOL_SCORING.md). For the current CLI defaults,
see [rules and weights](../rules/README.md). Later policies can increase the
applicable dependency horizon; the v18 examples below are not fixed current
defaults. These changes do not adopt a version into another checkout or pipeline.

## Two distinct windows

| Evidence admitted by the policy | Raw features | Temporal history |
| --- | --- | --- |
| Known Linux parsers, no Windows input indicators | Calendar month + 24h each side | 24h each side |
| Windows, mixed, unknown or inconclusive evidence | Calendar month + 24h each side | Applicable dependency horizon; currently 199h each side |

The old raw window was calendar month plus 199 hours **on each side**. A larger
`--overlap` increases temporal history, not the raw-feature window. An explicit
overlap shorter than applicable dependencies is rejected. Non-temporal bounded
lookbacks can raise the configured feature overlap. Full-row output retains
eager history processing; the two-level cache is for sidecar mode.

The seven-day `QUALIFIED_MALWARE_PATH_USE` and
`QUALIFIED_MALWARE_EXACT_HASH_USE` rules have generic names but **Windows-only
execution prerequisites** in this policy. The first directly requires
`windows_program_execution`; the second requires
`evidence_exact_hash_program_use`, whose producer also requires that signal.
They belong in the Windows applicability group. They are not Linux seven-day
requirements. Windows creator-risk chains still require the complete 199 hours.

## Conservative applicability, owned by YAML

The planner inspects the complete Parquet schema and distinct parser/data-type
values across the entire dataset, not a sample or the evidence image's name.
The YAML declaration requires every parser to be allowed, at least one explicit
Linux parser, absence of guarded Windows input/derived columns, and absence of
Windows data-type values. Null/unknown/mixed parsers, missing parser fields,
Windows structured columns (even all-null), Windows data types or neutral-only
filestat/PE evidence retain the long history. Linux `command_line` is not a
Windows indicator. No IP, country, account or ground-truth label is hard-coded.

Only explicitly listed temporal rules can be omitted. An outside temporal
consumer of their output prevents omission. Retained definitions still determine
the complete composed dependency horizon. Changing detector applicability
requires maintaining this explicit contract and its producer-level tests;
rule names alone are not a semantic proof. The plan and its evidence are
reported in telemetry and partition reports. Engine rule scope is restored
after success or failure; independent dataframe APIs are unchanged.

## Long-history sidecar execution

1. Generate atomic and non-temporal features for each month with short raw
   overlap, using unchanged global profile/file-hit manifests and enrichment.
   Store only core-month rows in a fresh intermediate Parquet cache.
2. Read only keys, baseline/context inputs and signal maps for the long window.
   **All observations remain**, including zero-signal rows needed by novelty,
   authentication, geographic and IP baselines. The cache has no already-applied
   temporal signals, trust adjustments or final profile score amplification.
3. Run temporal rules with the existing chronological carry checkpoint strictly
   before the next input window's lower bound. Preserve empty source months as
   checkpoints. Generic first-seen/sequence history is not shortened for Windows.
4. Load raw message/path fields only for composite source/target rows after
   temporal signals are known. Unscored note-name/copy-text support is admitted
   by a non-scoring, row-local flag computed in bounded batches. Negative
   admission thresholds conservatively retain every row. Final predicates remain
   in the normal executors; there is no score-threshold prefilter.
5. Load saved review fields/explanations in batches of at most 65,536 rows, join
   by persistent integer row ID, combine temporal explanations, apply trust/profile
   adjustments once, score and write unique sidecar chunks. Duplicate/missing
   keys or timestamp disagreement fail, never fall back to timestamp joins.

No defensive dataframe or recursive evidence copy is added. On-demand hydration
uses bounded ID queries, not one query per event. Raw-support markers are internal
and excluded from exported sidecars. Existing nested-map/list encoding is retained.
Cache reads preserve nullable integer and boolean types, including integers above
2^53; they must not silently pass through floating point. Final core batches
restore the same validated global profile probabilities/validation metadata so
activity-score amplification and its explanation are applied exactly once.

## Results are not promised to be byte-identical

Reducing the raw-feature window changes the available context for **frame-scoped
SQLi/web baselines and identity/file-hash lookups**. Global manifests remain
corpus-wide, but are not substitutes for those frame-local references. Cached
features for overlap rows come from their own month plus short overlap, rather
than being recomputed for every surrounding month's large frame. These are
deliberate, documented execution-scope changes; compare relevant evidence and
ground-truth anchors before adopting regenerated results. Reverting to v17
retains the historical wide-feature path for a controlled comparison.

## Artifacts, failure and memory limits

Choose a fresh output under `working/<UTC-date-time>/sidecar` with the normal
CLI. Compact execution creates a sibling `sidecar.history-<unique>/` containing
`manifest.json`, monthly Parquets/receipts and a final `complete.json` only after
success. Its path is logged immediately. The manifest records parsed policy
digests; freeze source/YAML/resources and input provenance externally for a
reproducible run, as with other ChronoSIFT runs. Caches are invocation-local and
**never reused across runs**. They are retained for diagnosis, including after
failure; deletion is a separate explicit action. They are sensitive evidence,
not anonymous statistics. Allow additional disk capacity for them.

This is not weekly processing, a memory guard, or a bounded-memory guarantee:
raw feature generation remains month-sized, sparse maps may still be large,
and the complete narrow temporal window remains in memory. A required adjacent
month is prepared in full once, so a one-month test can include setup work for
neighbouring months when compact history is needed. A 131,353,244 kB node offers
about **125.3 GiB physical RAM**, but scheduler limits, other processes, expansion
and peak allocations still matter. No full May fit/time claim follows from
small regression fixtures. No HPC job or full corpus run is started by this change.
