"""Storage-only validation against a frozen engine with the SAME v17/v15 policy.

Bounded fixtures, not a full dataset restart. Outputs contain semantic digests
of every derived field plus exact scores, signals and explanations by stable ID.
Missing sentinels are equivalent; empty maps/lists/strings remain distinct.
Run each variant in a fresh process for meaningful peak-RSS comparisons.
"""
import argparse
from dataclasses import replace
from functools import partial
import gc
import hashlib
import importlib.util
import json
import logging
from pathlib import Path
import resource
import shutil
import sys
import time

import numpy as np
import pandas as pd
import context_provenance_replay as common

WT = Path(__file__).resolve().parents[1]
PIPE = WT.parent.parent
BASE = PIPE / "working/20260909T222600Z-chronosift-final-n06f12kj/source"
PREVIOUS = PIPE / "working/20260909-identity-final-pGAZaw"
HISTORY = PIPE / "working/20260909T123739Z-context-repair-bVXktt/windows-complete-auth-tool-history/input"


def normal(value):
    if isinstance(value, dict):
        return {str(k): normal(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, np.ndarray)):
        return [normal(v) for v in value]
    if value is None or value is pd.NA or value is pd.NaT:
        return None
    if isinstance(value, (float, np.floating)) and np.isnan(value):
        return None
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    return value


def digest(value):
    return hashlib.sha256(json.dumps(normal(value), sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def prepare(out):
    before = json.loads((PREVIOUS / "provenance.json").read_text())
    hashes = {}
    for label, source in (("baseline", BASE), ("candidate", WT)):
        dest = out / label; dest.mkdir()
        for name in ("chronoSIFT_v2_31.py", "rules_evidence_calibrated_v17.yaml", "weights_evidence_calibrated_v15.yaml"):
            path = source / name
            if not path.exists(): path = source / "rules" / name
            shutil.copy2(path, dest / name)
            hashes[str(path)] = common.sha(path); hashes[str(dest / name)] = common.sha(dest / name)
    assert common.sha(out / "baseline/chronoSIFT_v2_31.py") == "725ca4451aacc77c1dbf75db1bf8e5291dc71c78e45b1acfb8ed40f3cf0e7d57"
    for name in ("rules_evidence_calibrated_v17.yaml", "weights_evidence_calibrated_v15.yaml"):
        assert common.sha(out / "baseline" / name) == common.sha(out / "candidate" / name)
    for directory in [Path(v) for _, v in before["cases"]] + [HISTORY]:
        for path in directory.rglob("*.parquet"): hashes[str(path)] = common.sha(path)
    for path in before["resources"].values(): hashes[path] = common.sha(path)
    common.save(out / "provenance.json", dict(hashes=hashes, cases=before["cases"], resources=before["resources"],
        history=str(HISTORY), scope="Storage-only v17/v15 comparison; actual YARA/AV/Luhn/GeoIP, neutral profiling, no NSRL; bounded fixtures, not full corpus."))


def load(out, label):
    folder = out / label
    spec = importlib.util.spec_from_file_location("memory_" + label, folder / "chronoSIFT_v2_31.py")
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    p = json.loads((out / "provenance.json").read_text())
    resources = {k: Path(v) for k, v in p["resources"].items()}
    engine = module.ChronoSiftEngine.from_yaml(folder / "rules_evidence_calibrated_v17.yaml",
        folder / "weights_evidence_calibrated_v15.yaml", yara_metadata_path=str(resources["yara"]))
    return p, module, engine, resources


def fingerprints(module, engine, frame, destination):
    frame.attrs = {}
    columns = sorted(set(module._sidecar_materialisation_columns(frame,
        row_id_col="chronosift_row_id", configured_columns=engine._configured_sidecar_output_columns())))
    rows = []
    for values in frame[columns].itertuples(index=False, name=None):
        row = dict(zip(columns, values)); signals = row.pop("chronosift_signals", None) or {}
        explanations = row.pop("chronosift_explain", None) or []
        rid = int(row.pop("chronosift_row_id")); score = float(row.pop("chronosift_score"))
        assert abs(score - engine._score_signals(signals)) < 1e-5, (rid, "signals")
        assert abs(score - min(engine.max_event_score, sum(e.get("score_contribution", 0) for e in explanations))) < 1e-5, (rid, "explanations")
        rows.append((rid, score, digest(signals), digest(explanations), digest(row)))
    result = pd.DataFrame(rows, columns=["id", "score", "signals", "explain", "fields"])
    assert result.id.is_unique and result.id.notna().all()
    result.to_parquet(destination, index=False)
    return columns


def bounded(out, label, case):
    p, module, engine, resources = load(out, label)
    directory = Path(dict(p["cases"])[case]); target = out / label / case; target.mkdir()
    start = time.monotonic(); manifest = common.manifest_for(module, engine, directory, resources)
    raw = module.load_plaso_parquet_dataset(str(directory)); ids = raw.chronosift_row_id.to_numpy(copy=True)
    frame = engine.apply_atomic(raw, apply_profiling=False, **{k: str(v) for k, v in resources.items() if k != "yara"})
    del raw
    frame = engine.apply_contextual(frame, apply_profiling=False, file_hit_manifest=manifest)
    seconds = time.monotonic() - start
    assert np.array_equal(ids, frame.chronosift_row_id.to_numpy())
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # bytes on macOS
    columns = fingerprints(module, engine, frame, target / "fingerprints.parquet")
    common.save(target / "result.json", dict(rows=len(frame), seconds=seconds, peak_rss_bytes=rss, columns=columns))
    print(label, case, len(frame), seconds, rss, flush=True)


def native(out, label):
    p, module, engine, resources = load(out, label); target = out / label / "native-history"; target.mkdir()
    directory = Path(p["history"])
    engine.profiling_policy = replace(engine.profiling_policy, enabled=False)
    engine._apply_non_temporal_contextual_sparse = partial(engine._apply_non_temporal_contextual_sparse,
        retain_zero_weight_lifecycle_signals=False)
    manifest = common.manifest_for(module, engine, directory, resources); start = time.monotonic()
    reports = engine.process_parquet_dataset_partitioned(str(directory), str(target / "sidecar"),
        output_mode="sidecar", materialise_event_columns=True, file_hit_manifest=manifest,
        telemetry_jsonl_path=str(target / "telemetry.jsonl"),
        **{k: str(v) for k, v in resources.items() if k != "yara"})
    seconds = time.monotonic() - start; rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    frame = module.load_plaso_parquet_dataset(str(target / "sidecar"))
    columns = fingerprints(module, engine, frame, target / "fingerprints.parquet")
    common.save(target / "result.json", dict(rows=len(frame), seconds=seconds, peak_rss_bytes=rss, columns=columns, reports=reports))
    print(label, "native-history", len(frame), seconds, rss, flush=True)


def allocations(out, label):
    _, module, engine, _ = load(out, label); results = {}
    # The exact allocation is measured on a modest frame; no 21M-row allocation.
    frame = pd.DataFrame(index=pd.date_range("2024-05-01", periods=100000, freq="s", tz="UTC"))
    gc.collect(); start = time.monotonic()
    frame = module._ensure_object_columns(frame, [f"absent{i}" for i in range(250)])
    results["placeholders"] = dict(rows=len(frame), columns=len(frame.columns),
        value_buffer_bytes=int(frame.memory_usage(index=False, deep=False).sum()), seconds=time.monotonic() - start)
    del frame; gc.collect()
    # Row-local systemd semantics; large unique strings expose eager clipping.
    frame = pd.DataFrame({"message": [f"ordinary log {i} " + "x" * 600 for i in range(100000)],
        "filename": "/tmp/ordinary.log", "timestamp_desc": "mtime"},
        index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * 100000))
    times = []
    for _ in range(3):
        gc.collect(); start = time.monotonic(); signals, explanations = {}, {}
        engine._apply_systemd_service_persistence_sparse(frame, signals, explanations)
        times.append(time.monotonic() - start); assert not signals and not explanations
    # Tracing is a SEPARATE pass, not used for timing or interpreted as RSS.
    import tracemalloc
    gc.collect(); tracemalloc.start(); engine._apply_systemd_service_persistence_sparse(frame, {}, {})
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    results["systemd"] = dict(rows=len(frame), seconds=times, median_seconds=float(np.median(times)),
                              peak_python_allocation_bytes=peak)
    common.save(out / label / "allocations.json", results)
    print(label, results, flush=True)


def compare(out):
    p = json.loads((out / "provenance.json").read_text()); results = []
    for case in [name for name, _ in p["cases"]] + ["native-history"]:
        frames = [pd.read_parquet(out / label / case / "fingerprints.parquet").set_index("id").sort_index()
                  for label in ("baseline", "candidate")]
        assert frames[0].index.equals(frames[1].index), (case, "keys")
        differences = {c: int((frames[0][c] != frames[1][c]).sum()) for c in frames[0]}
        reports = {label: json.loads((out / label / case / "result.json").read_text()) for label in ("baseline", "candidate")}
        assert reports["baseline"]["columns"] == reports["candidate"]["columns"], (case, "columns")
        results.append(dict(case=case, rows=len(frames[0]), differences=differences, variants=reports))
    unchanged = all(common.sha(Path(path)) == value for path, value in p["hashes"].items())
    ok = unchanged and all(not any(item["differences"].values()) for item in results)
    common.save(out / "comparison.json", dict(passed=ok, source_unchanged=unchanged, cases=results))
    assert ok, [(r["case"], r["differences"]) for r in results]
    print("EXACT SEMANTIC PARITY", sum(r["rows"] for r in results), flush=True)


if __name__ == "__main__":
    logging.Formatter.converter = time.gmtime
    parser = argparse.ArgumentParser(); parser.add_argument("mode", choices=["prepare", "bounded", "native", "allocations", "compare"])
    parser.add_argument("--output", required=True, type=Path); parser.add_argument("--label", choices=["baseline", "candidate"])
    parser.add_argument("--case"); args = parser.parse_args()
    if args.mode in ("prepare", "compare"): globals()[args.mode](args.output)
    elif args.mode == "bounded": bounded(args.output, args.label, args.case)
    else: globals()[args.mode](args.output, args.label)
