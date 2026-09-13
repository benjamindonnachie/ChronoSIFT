# ChronoSIFT v2.31.3 — code assessment, 13 September 2026

Assessment of the performance work, the rules-versus-engine boundary, and overall
completeness/correctness. Every finding here is backed by something executed; the
scripts and raw outputs in this directory reproduce all of it.

- **Report:** [`AUDIT_20260913.html`](AUDIT_20260913.html) — open in a browser
- **Published copy:** https://claude.ai/code/artifact/8fda3811-ede9-4e89-8739-f120cb74f816

Target: the working tree of `ChronoSIFT-performance-20260905`. Policy as originally
assessed: rules v23 / weights v21. Policy at re-assessment: **rules v24 / weights v21**,
the pair `run_chronosift_sidecar_cli.py` now defaults to.


## Status: re-assessed, 7 of 7 closed

The findings below were raised against **rules v23**. They were addressed while the report
was being written, and every one has been re-verified against the current tree (**rules
v24**, new `attack_metadata.py`, bundled ATT&CK catalogue). Full suite on the now-correct
floor: **815 passed, 0 failed, 8 skipped** (pandas 3.0.5).

All seven findings are closed. F-04's recommended conversion was already implemented as
`_prepare_arrow_text_columns()`; reviewing it showed the audit had justified that finding
badly, and the report now carries the correction.

### Corrections to the original audit

1. **Detector count.** The required set contains **35** IDs, not 36 — a miscount;
   `docs/DETECTOR_POLICY_CONTRACT.md` is right.
2. **`T1685.005`**, flagged as unverifiable, is valid in Enterprise ATT&CK 19.2
   ("Clear Windows Event Logs").
3. **F-04's justification was wrong on two counts.** The dtype diagnostic
   (`dtype_check.py`) inspects a frame after `ensure_required_fields()`, which runs *before*
   `_prepare_arrow_text_columns()` — a pre-conversion snapshot presented as the
   detection-stage state. And the 4.5×/6.2× ratios were measured on **pandas 2.3.3**, where
   `string` defaults to Python storage; on the project floor of pandas 3.0.3 `.astype("string")`
   is already Arrow-backed, so the engine's existing helpers were never on the Python path in
   a supported install. Object input dtype does not imply Python execution, and some regex
   patterns/flags need pandas' fallback regardless. Measured on the engine the conversion is a
   **memory** win (~10.7% lower peak RSS), not a speed one — runtime is flat at 20k events.
   Remaining string-path optimisation is an open profiling question, not a located bottleneck.

Reproduce the re-assessment with `scripts/attack_v24.py` (ATT&CK coverage of v24) and the
pandas 3 environment below.

## Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| F-01 | **Critical** | Timestamps outside 1677–2262 silently dropped on pandas 2.x | **Closed** — `pandas>=3.0.3` pinned + import guards in engine and ingest CLI |
| F-02 | **High** | ATT&CK IDs are prose in `description:`, not validated fields | **Closed** — `attack_metadata.py`, SHA-verified Enterprise 19.2 catalogue, all 285 producers annotated and validated |
| F-03 | Medium | 35-detector taxonomy hard-coded in Python | **Closed** — published as `docs/DETECTOR_POLICY_CONTRACT.md` |
| F-04 | Medium | Explicit Arrow text storage | **Closed** — `_prepare_arrow_text_columns()`; audit's justification corrected (see below) |
| F-05 | Low | Docs and changelog behind the CLI default | **Closed** — v24 consistent; matrix generated and drift-tested |
| F-06 | Low | GeoIP reader errors swallowed as lookup misses | **Closed** — both handlers catch `AddressNotFoundError` |
| F-07 | Info | Public `apply()` untested (not on the production path) | **Closed** — `tests/test_public_apply.py` |

F-01 is also logged in the OpenWolf bug log as `bug-606`.

## Headline results

| Measure | Result |
|---|---|
| Test suite (v24, pandas 3.0.5) | **815 passed, 0 failed**, 8 skipped |
| Line coverage (engine) | **91%** — 12,564 statements, 1,167 missed |
| Hard-coded attacker indicators in engine | **0** |
| Hard-coded numeric thresholds | **3**, all structural bounds |
| YAML signal names hard-coded in engine | **0** (slot indirection verified) |
| Producers carrying a validated ATT&CK annotation | **285 of 285** (140 mapped, 145 explicitly unmapped) |
| Distinct techniques mapped / catalogue size | 54 / 858 (Enterprise 19.2, SHA-pinned) |
| Emitted-but-unweighted signals | 0 (1 dead weight) |
| Sparse-attrs penalty on scalar reads | up to **11,009×** |
| Arrow text storage, measured on the engine | runtime flat; **~10.7% lower peak RSS** |

## Environment

The project floor is now `pandas>=3.0.3`, enforced by `pyproject.toml` and by import guards
in both `chronoSIFT_v2_31.py` and `jsonl_to_parquet_cli_logging.py`. Build the
re-assessment environment with `uv`:

```bash
uv venv --python 3.12 .venv-audit
VIRTUAL_ENV=.venv-audit uv pip install 'duckdb>=1.1' 'geoip2>=4.8' 'numpy>=1.26' 'pandas>=3.0.3' 'pyarrow>=15' 'pytz>=2024.1' 'PyYAML>=6.0' psutil pytest pytest-xdist coverage
```

Re-assessment ran on CPython 3.12.13 / pandas 3.0.5 / numpy 2.5.3 / pyarrow 25.0.1 / duckdb 1.5.5.

### Historical note on F-01

The original audit ran on pandas 2.3.3 — legal under the then-declared `pandas>=2.2` — and
the 2 failures it produced were real, not environmental. Reproducing that state now
requires deliberately installing `'pandas>=2.2,<3'` and removing the import guards; the
guards exist precisely so nobody lands in that state by accident. `results/pytest_full.txt`
preserves the original failing run, `results/pytest_pandas3_reassessment.txt` the green one.

## Scripts

Run from the repository root with the audit venv's interpreter.

### Hard-coded rule detection (question ii)

| Script | What it establishes |
|---|---|
| `scan_literals.py` | AST pass over all 551 string comparisons, split policy-side vs data-side |
| `scan2.py` | Same, filtered to non-benign comparisons grouped by owning method |
| `num_scan.py` | Every numeric threshold comparison not sourced from policy |
| `signal_cross.py` | Cross-references all 434 YAML signal names against engine string literals |
| `registry_test.py` | Mutation tests: what the closed detector registry does and does not permit |

### ATT&CK linkage (question ii)

| Script | What it establishes |
|---|---|
| `attack_audit.py` | Structured vs prose technique references; emission-level coverage (original v23 analysis) |
| `attack_v24.py` | Current state: per-emission `attack_ids`, basis distribution, catalogue pinning |

Outputs `results/attack_ids_in_docs.txt` and `results/attack_ids_in_rules_v23.txt`
support the docs-vs-shipped-rules comparison (96 documented, 47 absent from rules).

### Correctness (question iii)

| Script | What it establishes |
|---|---|
| `align.py` | Signal/weight alignment — unweighted signals, dead weights, dangling temporal inputs |
| `smoke.py` | Engine constructs from the shipped policy and reports its loaded counts (edit the version it loads) |

### Performance (question i)

| Script | What it establishes |
|---|---|
| `e2e.py` | End-to-end `apply()` throughput at 2k / 10k / 40k rows (linearity) |
| `prof.py` | `cProfile` of a 10k-row run, by cumulative and self time |
| `dtype_check.py` | ⚠️ **Superseded** — inspects dtypes before `_prepare_arrow_text_columns()` and benchmarks on pandas 2.x. Kept for provenance; do not cite its ratios. |
| `iat_read.py` | Sparse-attrs read penalty, small payload (fast — start here) |
| `iat_bench_large.py` | Same at 20k payload, incl. writes. **Takes ~9 minutes** — the attached-read case is the point |
| `iat_bench2.py` | Write-only control showing writes are unaffected |

## Raw outputs

`results/pytest_full.txt`, `results/coverage_report.txt`, `results/coverage_run.txt`,
`results/sparse_attrs_benchmark.txt`, `results/pytest_pandas3_reassessment.txt`, plus the
two ATT&CK ID listings.

## Caveats

- Throughput figures use synthetic Plaso-shaped frames, not a real corpus. Treat the
  ratios and the linearity as sound; treat absolute rows/s as indicative only.
- Benchmarks are single-machine, best-of-three.
- Coverage excludes `jsonl_to_parquet_cli_logging.py`, which its test imports
  indirectly, so `coverage` never recorded it.
