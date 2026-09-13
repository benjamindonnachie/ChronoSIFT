# Large-window performance work

## September 13 audit F-04: prepare textual storage once

After enrichment and normalisation, the atomic pipeline prepares genuinely textual
columns once as explicit `string[pyarrow]` storage. This does not convert the entire
frame: numeric, binary, mixed, nested, categorical and compact-null columns remain
unchanged. Object-column admission examines all non-null values, not a sample.
Existing Arrow strings reuse their buffers; other string dtypes retain their missing
value convention. Unencodable Unicode remains in its original column with a warning,
rather than being repaired or discarded. The operation detaches sparse state and
does not copy the DataFrame, attach caches to its attributes or change global pandas
options. Raw text, integer identifiers and timestamp resolution are not normalised
by this storage step. It runs after producer writes, not in `ensure_required_fields`.

The audit's claim that every operation on an object input uses Python is too broad:
on the required pandas 3.0.3 with PyArrow installed and the default string-storage
option, the engine's existing `.astype("string")` calls already select Arrow.
Unsupported regular expressions and flags may still require pandas' Python fallback;
removing those fallbacks or changing case rules is not part of this optimisation.
Consequently, the audit's standalone 4.5–6.2× kernel ratios are **not** engine speedups.

A bounded deterministic 20,000-event synthetic fixture (rules v24, weights v21,
profiling disabled) measured median apply time of 11.238 versus 11.213 seconds over
three calls: effectively unchanged. A separate fresh-process 50,000-event pair
measured 28.617 versus 29.929 seconds and peak process RSS at return from `apply` of
1,153,077,248 versus 1,029,480,448 bytes (about 10.7% lower). The 50,000-event pair is
a single observation, not a robust timing comparison; other work was running on the
host. Output serialization and deep-size inspection happened after the RSS capture.
Pandas' deep frame accounting fell from 148,587,310 to 87,083,785 bytes, but that is
not an additional measured RSS saving: object accounting can count shared strings
repeatedly. These are synthetic measurements, **not** a complete-dataset comparison,
a May runtime forecast, or a guarantee that a large month will fit in memory.

Validation includes the storage/no-copy/Unicode/null tests in
`tests/test_arrow_text_storage.py`, the existing native compact/eager sidecar tests,
and independent-source replay. Compare process outputs with a fixed
`PYTHONHASHSEED`: existing canonical-authentication explanations derive source-name
order from a frozenset. Initial 20,000-row cross-process differences were exclusively
permutations of those names; scores, signals and all other values agreed. The fixed
seed 17-event Windows/Linux/web replay matched complete explanations as well.
This change does not alter that existing ordering, scoring, YAML, overlap or stage
dependencies. The direct contextual-only API does not perform the preparation step.

## September 10 follow-up: dataset-aware and compact history

The later v18 execution candidate separates 24h raw-feature overlap from long
context history, while proven Linux input can omit Windows-only dependencies.
See [partition execution](PARTITION_EXECUTION.md). The earlier memory-only v17
results below remain historical measurements, not claims about v18 parity or
full-May memory fit.

## September 10: compact missing fields and bounded evidence materialisation

The memory candidate retains v17 rules, v15 weights and the automatically computed
199-hour overlap. It does not subdivide the calendar, introduce a memory guard,
skip low-scoring rows or change the stable integer row identifier.

- Missing required fields remain visible, but use the public pandas Arrow null
  dtype with no per-row value buffers. Normalisers recognise wholly absent inputs
  and preserve missing-value/alias semantics. A producer allocates a writable
  object column only when a partial assignment needs real values. Consequently,
  callers must not assume every wholly missing field has NumPy object dtype.
- Atomic condition/text/numeric caches are released after the last possible rule
  consumer, including short-circuited conditions. Evidence arrays are constructed
  only for matches, in batches of at most 65,536 rows.
- The row-local systemd executor operates in 65,536-row batches. Its conditions
  still inspect every row and all configured command/path inputs; explanations
  are built only for effective matches. This is not temporal chunking. Sparse
  map positions remain global, including at duplicate timestamps.
- Disposable contextual text/path caches are released between detector families.
  Internal sidecar execution releases raw fields after their final declared stage
  consumer. Configured output fields, temporal dependencies, trust/profiling
  inputs and explanation identities are retained. Full-frame APIs do not prune
  their raw input fields. Previous partition frames/maps are explicitly released.
  Core-output projection also omits its unused old-to-new position dictionary
  and the temporary Python list of selected positions. Candidate remapping keeps
  its existing default map; completed-month masks are explicitly released.
- In sidecar mode, raw fields used **only** as atomic explanation evidence can
  be omitted from the initial projection and fetched for matched integer row IDs.
  Conditions, normalisation inputs/outputs, schema-alias participants, enrichment
  inputs, later detector dependencies and exported fields remain eager. Queries
  are batched, window/Hive-month restricted and restore request order. Missing,
  duplicate or mismatched keys and read failures raise errors; the legacy fallback
  cannot silently continue without deferred evidence. This requires the existing
  immutable base-Parquet/stable-key contract, not a database query for each row.

The Ubuntu input already projects 30 present source fields plus datetime out of a
68-field schema. The current policy has no additional evidence-only field to defer
there. The principal Ubuntu benefits are therefore compact placeholders and shorter
array lifetimes, not a further reduction in source-column count. At 21,400,380 rows,
250 dense placeholder columns imply 39.86 GiB of object-pointer arrays alone; this
is an allocation estimate, **not** measured RSS savings. Some placeholders later
become legitimate populated fields. Signal/explanation dictionaries and required
temporal history still consume memory, so this does not guarantee that a full
mega-month fits in available memory.

Validation uses `tests/test_v231_memory.py`, the existing no-copy/regression suite,
and `benchmarks/memory_replay.py` against frozen engine `725ca445` with identical
v17/v15 configuration. The replay checks per-ID scores, signals, explanations and
all exported derived values, treating missing sentinels as equivalent but retaining
the distinction between null, empty text, empty list and empty map. Allocation
tracing is separate from timing; neither is an extrapolated full-May runtime.

The first memory candidate (`80d2180`) matched all scores, signals, explanations
and exported derived values on 861,371 bounded fixture rows plus 204,875 selected
native monthly rows against `725ca445`. Five-fixture peak process RSS was about
8–16% lower; native monthly peak RSS was 10,346,962,944 versus 7,582,720,000 bytes
(about 27% lower). These are single paired runs, not a full-May memory forecast.
At 100,000 rows the isolated 250-placeholder probe measured 200 MB versus zero
value buffers; a separate systemd probe measured 297.6 MB versus 105.1 MB peak
Python allocations, excluding input storage and native Arrow allocations.

The follow-up core-position-map cleanup changes only `_subset_sparse_state` and
the monthly driver. `benchmarks/validate_memory_cleanup.py` verifies every other
engine AST node is unchanged, checks that the helper has no other engine callers,
and repeats the affected native path alongside the complete suite. Its final
receipt records the precise source hash; the initial comparison remains preserved.

## September 2026: metadata copying and SQLi baselines

This optimisation preserves the configured processing window, detector policy,
weights, row coverage, stable row identifiers and output schema. It does not
introduce weekly subdivision or skip low-scoring evidence.

### Sparse-state ownership

Pandas propagates frame attributes when constructing many Series and DataFrame
objects. In pandas 3.0.3 this includes the Series internally constructed by a scalar
`df.iat[row, column]` read. If `chronosift_sparse` is attached, the read can recursively
copy the partition's complete nested signal and explanation maps. A subsequent
`to_numpy(copy=False)` does not prevent this earlier metadata copy, and
`df.copy(deep=False)` is not a remedy.

Internal contextual stages now temporarily detach only `chronosift_sparse`, retaining
profiling and provenance attributes. The sparse maps continue to be passed by reference
as explicit arguments. Detachment is reentrant and restores the original object after
success or an exception; it creates neither a frame copy nor a second mutable wrapper.
The public materialisation API retains its existing attribute-clearing behaviour.

The partition runner holds the maps separately through candidate selection, scoring
and core-output preparation. Candidate merging also avoids copying attached candidate
state while reading its output columns. Direct web-classifier, referenced-file and
web-mapping calls have the same protection as their enclosing contextual stages.

Web mapping reads each existing technique column once and buffers only matching-row
updates before assigning them by position. It preserves aliases, missing unmatched
values, sorted technique unions and the existing persistent row IDs. Timestamp labels
are not used to join these updates, so duplicate evidential timestamps remain intact.

Classifier outcome columns are also assigned in batches. A separate post-cache
profile found that 4,000 scalar outcome assignments to Arrow-backed strings consumed
about 42% of profiled classifier time. Batching preserves both canonical and configured
aliases, their string-storage types, and non-HTTP rows' existing values.

### Exact endpoint baseline caching

For `scope: partition` and `lookback: unbounded`, all requests in one configured
baseline group share the same sample set. Its sample count, median/mean and threshold
are now calculated once, including the insufficient-sample result. Samples remain in
their original order for the numeric reduction. Raw group records can be released
after their summary has been cached.

Prior-row and finite-lookback policies retain row-specific selection. The cache is
local to one classifier call and cannot cross partitions or policy changes. Evidence
still records the same sample count, statistic and threshold, not merely the same
resulting signal value.

### First-pass validation and measured results

Reference: revision `03b581887c478d58f26f6b07e051e3c846604b79`.
Environment: Python 3.14.6, pandas 3.0.3, NumPy 2.5.1 on the same host for both versions.
The existing long-running evidence job was left untouched. These are bounded synthetic
measurements, not production throughput or a prediction of the Ubuntu job's duration.

Median of three wall-clock runs, excluding fixture setup and explicit pre-run garbage
collection. Neither profiling nor allocation tracing was enabled during timing:

| Fixture | Reference | Optimised | Ratio |
|---|---:|---:|---:|
| 600 matching web-mapping rows, nested state attached | 3.331 s | 0.01646 s | 202× |
| 4,000 ordinary requests sharing one baseline group | 2.112 s | 0.12944 s | 16.3× |

Both fixtures produced exactly matching DataFrames, signal maps and explanation maps.
A separate synthetic 12-event partitioned run produced exactly matching complete scored
sidecars with unique persistent row IDs and duplicate input timestamps.

In a **separate** tracemalloc pass, incremental peak Python allocations for mapping
were 1,917,007 bytes before and 746,676 bytes after. Classifier peaks were 5,542,103 and
5,720,446 bytes: buffering outcome writes added about 3.2% to the small fixture's peak,
whilst removing repeated work. This first pass did not reduce the classifier's retained
row-context memory. Fixtures were constructed
before tracing; these numbers exclude input storage and native allocations and are not
RSS, total memory, or measured production savings.

Regression tests assert operation counts rather than wall time. They cover forbidden
sparse-state deepcopy, scalar-read avoidance, exceptions and nested detachment, public
metadata ownership, output aliases and nulls, temporal candidate merging, per-group
median/mean counts, empty/missing-key baselines, and exact baseline values across
partition/prior-row scope, bounded/unbounded lookback and s/ms/us/ns timestamp units.
Outcome-write checks cover both Python- and Arrow-backed string columns.

The first-pass complete suite ran 431 tests: 423 passed and eight corpus-dependent tests
were skipped as expected. There were no failures. The candidate engine SHA-256 used
for the reported benchmark and final suite was
`e8f157b07f0d61870f63b8cb1d0984787c1d622103a29ba7b18b1710f248badb`.

### Second pass: per-row work and temporary state

String inputs now bypass `pd.isna`, preserving the same stripping and placeholder
rules. IP scope classification caches up to 8,192 canonical input strings; inputs
longer than 128 characters bypass the cache so oversized evidence cannot inflate
it. Missing, invalid, private, public and excluded address classes keep their previous
semantics. This cache does not alter the separate unique-IP GeoIP enrichment stage.

The classifier retains slotted records instead of per-row dictionaries, calculates
each baseline key only once, and releases records as they are consumed. Static
partition/unbounded groups retain response values without redundant row/timestamp
tuples. Other baseline policies still retain and select those exact records. Evidence
is constructed only when an emission increases a signal. Existing per-HTTP-row empty
signal dictionaries and explanation lists are preserved; no missing/empty distinction
or sidecar schema was changed.

Referenced-file correlation collects updates only for matching positions and writes
each feature/outcome column once. Outcome branches read the latest pending value for
their own alias, preserving configured ranking, branch order and pre-existing alias
differences. No manifest identities or input evidence are modified.

The following **incremental** measurements compare the frozen first-pass engine
`e8f157b0…` with second-pass engine
`45900d78cb3c3f3730f2a31402036ca5b8cd0c863dabb82d0fe489f1c871d6f5`.
Medians of three untraced runs in the environment above:

| Synthetic fixture | First pass | Second pass | Additional speed-up |
|---|---:|---:|---:|
| 50,000 matching mapping rows | 1.357 s | 0.846 s | 1.60× |
| 50,000 benign requests, one baseline group | 1.573 s | 0.901 s | 1.75× |
| 10,000 mixed referenced-file requests | 4.809 s | 0.975 s | 4.93× |

Frames, signals and explanations matched exactly in all three comparisons, as did
the complete 12-event partitioned sidecar. These are not whole-May runtime measurements.

Separate incremental peak Python allocations, with fixture setup excluded:

| Fixture | First pass | Second pass | Change |
|---|---:|---:|---:|
| Mapping | 61,694,900 bytes | 61,893,788 bytes | +0.3% |
| Classifier | 73,762,318 bytes | 45,746,198 bytes | −38.0% |
| Referenced-file correlation | 40,601,594 bytes | 43,352,038 bytes | +6.8% |

The classifier reduction concerns temporary stage allocations, not total process memory
or the final retained output maps. Referenced-file buffering trades a modest peak increase
for fewer repeated array writes. Native/Arrow allocations, input storage and production
RSS are not measured by these figures.

The benchmark also passed 96 mixed-request classifier policy/storage variants and six
referenced-file alias/ranking/branch-order variants against the untouched original engine.
It checks exact evidence values, duplicates and timestamp units, not only aggregate counts.

The second-pass full suite ran 435 tests in 108.129 seconds: 427 passed and eight
corpus-dependent tests were skipped. All 15 focused performance regressions passed.
The original checkout remained clean on `main`, with identical engine, rules and
weights fingerprints. No environment changes, production restart or publication occurred.

### Third pass: identity reuse, prepared mapping and SQLi results

Referenced-file correlation now normalises immutable manifest snapshots once per
admitted identity object, not for every reference, branch and serialisation. The
cache is local to one policy-validated invocation, holds at most 1,024 entries and
admits only identities with at most 256 members/metadata records and 16,384 total
string characters. Larger identities remain fully processed without retention.
Already-normalised row identities can be merged and inspected without another
normalisation pass. Cached sets and metadata records are immutable; merged rows and
each explanation still own independent mutable metadata. Access/upload separation,
hash precedence, branch order and outcome ranking are unchanged.

Mapping predicates bind policy constants once per invocation and accumulate the same
group booleans without temporary lists. Every configured group is still evaluated in
the original order, so an earlier false group does not conceal malformed signal input.
Branches resolve output identifiers and fallback techniques once; evidence common to
multiple emissions is calculated once per matching row. Matching still observes the
pre-mapping signal state. No parser-based or atomic-signal-only row filter was added.

SQLi classification caches final indicator tuples for exact, already-normalised request
targets under one fixed policy invocation. The LRU has 8,192 entries and bypasses targets
over 4,096 characters. It neither truncates requests nor folds distinct query targets
together. Existing URL-decoding caching and compiled regular expressions remain in place.
Benefits depend on target reuse; a high-cardinality workload has less opportunity.

The focused regressions cover immutable snapshots, mutable event/explanation ownership,
cache bounds and oversized inputs, subsequent manifest/policy changes, and every one of
32,768 combinations of mapping-group presence, truth values and all/any mode. Differential
checks add 24 mapping variants covering exclusions, multiple outputs, fallback technique
IDs, pre-mapping state, aliases and three column-storage modes to the previous 102 cases.

Final candidate SHA-256:
`084174cb2f422b97ced5d16960b88845758bfa6ee4a72fb5e56b586d2f1709f8`.
Reference: frozen second-pass engine `45900d78…`. Medians of three untraced runs:

| Synthetic fixture | Second pass | Third pass | Additional speed-up |
|---|---:|---:|---:|
| 50,000 matching mapping rows | 0.83885 s | 0.70887 s | 1.18× |
| 50,000 requests with repeated targets | 0.89856 s | 0.70216 s | 1.28× |
| 10,000 mixed referenced-file requests | 0.96362 s | 0.45049 s | 2.14× |

Frames, signal maps and explanations matched exactly. In a separate allocation pass,
mapping peaks were 61,893,868 / 61,900,503 bytes; classifier peaks 45,746,230 /
45,748,320 bytes; referenced-file peaks 43,352,174 / 43,351,325 bytes. Each difference
was below 0.02% on these fixtures. These are incremental Python allocations, not RSS
or full-corpus memory measurements.

A separate cache-miss stress run used 12,000 distinct request targets and 2,048 distinct
manifest identities, exceeding both cache capacities. Referenced-file time fell from
0.26960 to 0.15300 seconds (1.76×). Classification took 0.25288 versus 0.25580 seconds:
about 1.2% longer in that three-run comparison, with no repeated-target benefit.
Outputs, all 126 differential cases and the complete synthetic sidecar still matched.
The optional `--diverse` switch reproduces these inputs. These ratios do not forecast May.

The full suite ran 440 tests in 109.147 seconds: 432 passed and eight corpus-dependent
tests were skipped. All 20 focused performance regressions passed. Original `main`,
its rules/weights, the shared environment and the existing job remained unchanged.

### Reproducing the checks

Run from the candidate checkout using an existing compatible Python environment.
Use a separate checkout for the unmodified reference; neither command installs or
updates dependencies. The benchmark reads no evidence and writes its synthetic
partition inputs and outputs only in an automatically cleaned temporary directory.

```sh
python -B -m unittest discover -s tests
python -B benchmarks/benchmark_web_hotpaths.py --reference /path/to/reference/ChronoSIFT --memory
python -B benchmarks/benchmark_web_hotpaths.py --reference /path/to/rules/checkout --reference-engine /tmp/frozen-engine.py --mapping-rows 50000 --classifier-rows 50000 --referenced-rows 10000 --memory
python -B benchmarks/benchmark_web_hotpaths.py --reference /path/to/rules/checkout --reference-engine /tmp/frozen-engine.py --mapping-rows 10000 --classifier-rows 12000 --referenced-rows 2048 --diverse
```

The benchmark emits source SHA-256 fingerprints, individual timing samples, exact
output-comparison results and optional separately measured allocation peaks. Defaults
are deliberately small; increase them cautiously, especially for the unoptimised
mapping path.

### Remaining work

The classifier still creates empty signal/explanation containers for benign HTTP rows.
Removing these outright would
change existing materialised `{}`/`[]` values to missing values (and can remove columns
on all-benign inputs). That change is not included in this output-equivalent patch.
A future compact-flag representation must support every sparse-map consumer and preserve
the existing public mutable-dictionary/list contract before it can replace those containers.
The second pass reduced temporary context memory without that wider representation change.

Lightweight row-progress telemetry and broader representative workload benchmarks
remain useful follow-ups. Updating source files does not accelerate an already-loaded
process; any restart remains a separate operational decision.
