"""Bounded before/after benchmark; no evidence reads, dependency changes or reruns.

Example (run using an existing interpreter, with bytecode writing disabled):
    python -B benchmarks/benchmark_web_hotpaths.py --reference /path/to/base/ChronoSIFT

The reference checkout is imported read-only. Timings exclude fixture construction
and run without allocation tracing or profiling. Optional allocation measurements
use a separate pass. Outputs, including empty sparse payloads, must match exactly.
"""
import argparse
from copy import deepcopy
from dataclasses import replace
import gc
import hashlib
import importlib.util
import json
import logging
from pathlib import Path
import statistics
import sys
import tempfile
import time
import tracemalloc
import warnings

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(label, **values):
    print(json.dumps({"test": label, **values}, default=str), flush=True)


def diverse_fixture(name, fixture, engine, rows):
    """Synthetic cache-miss stress inputs; never alter source evidence."""
    inputs = fixture(engine, rows)
    frame = inputs[0]
    if name == "classifier":
        frame["chronosift_web_request_target"] = [f"/index.php?id={i}" for i in range(rows)]
    elif name == "referenced_file":
        policy = engine.detector_policy.referenced_file_correlation
        manifest = inputs[3]
        template = manifest["web_identity_map"]["/shell.php"]
        manifest["web_path_map"] = {}
        manifest["web_identity_map"] = {}
        requests = []
        for i in range(rows):
            target = f"/fixture_{i}.php"
            identity = deepcopy(template)
            identity["av_families"].add(f"fixture_family_{i}")
            manifest["web_path_map"][target] = {"av", "luhn"}
            manifest["web_identity_map"][target] = identity
            requests.append(f"GET {target} HTTP/1.1")
        frame[policy.request_field] = requests
    return inputs


def check_policy_variants(engines, fixtures):
    """Exact differential checks, deliberately separate from timed fixtures."""
    import numpy as np
    import pandas as pd

    def equal(results):
        left, right = results["reference"], results["candidate"]
        pd.testing.assert_frame_equal(left[0], right[0], check_exact=True)
        assert left[1] == right[1], "variant signal mismatch"
        assert left[2] == right[2], "variant explanation mismatch"

    count = 0
    for storage in ("python", "pyarrow", "object"):
        for unit in ("s", "ms", "us", "ns"):
            for scope in ("partition", "prior_rows"):
                for lookback in (None, pd.Timedelta("3s")):
                    for statistic in ("median", "mean"):
                        results = {}
                        for version, engine in engines.items():
                            original = engine.detector_policy
                            policy = original.web_request_classification
                            key_fields = ("endpoint", "method") if count % 2 else ("host",)
                            inference = replace(
                                policy.sqli, baseline_scope=scope,
                                baseline_lookback=lookback, baseline_statistic=statistic,
                                baseline_key_fields=key_fields,
                                baseline_require_nonempty_keys=frozenset(key_fields),
                            )
                            policy = replace(policy, sqli=inference, outputs=replace(
                                policy.outputs, web_outcome_field="custom_outcome"))
                            engine.detector_policy = fixtures.policy_with_payload(
                                original, "web_request_classification", policy)
                            try:
                                with pd.option_context("mode.string_storage", "python" if storage == "object" else storage):
                                    frame, signals, explanations = fixtures.classifier_fixture(engine, 48)
                                frame.index = pd.DatetimeIndex([
                                    pd.Timestamp("2024-05-01T00:00:00Z") + pd.Timedelta(seconds=i // 2)
                                    for i in range(48)
                                ]).as_unit(unit)
                                frame["chronosift_web_request_target"] = [
                                    (pd.NA if i % 8 == 0 else "/products?id=1%27%20UNION%20SELECT%20x--"
                                     if i % 3 == 0 else "/index.php") for i in range(48)]
                                frame[policy.outputs.endpoint_field] = [" /Straße " if i % 2 else "N/A" for i in range(48)]
                                frame["chronosift_web_host"] = [" ExAmPle.Test " if i % 3 else "--" for i in range(48)]
                                frame[policy.outputs.method_field] = [" post " if i % 4 else "GET" for i in range(48)]
                                frame[policy.outputs.status_field] = [None if i % 7 == 0 else 404 if i % 5 == 0 else 200 for i in range(48)]
                                frame["chronosift_web_response_bytes"] = [np.nan if i % 11 == 0 else 27000 if i % 3 == 0 else 1000 for i in range(48)]
                                frame[policy.outputs.attack_indicators_field] = ["command_injection" if i % 4 == 0 else "" for i in range(48)]
                                if storage == "object":
                                    for column in frame.select_dtypes(include="string"):
                                        frame[column] = frame[column].astype(object)
                                engine._apply_web_request_classifier_sparse(frame, signals, explanations)
                                results[version] = frame, signals, explanations
                            finally:
                                engine.detector_policy = original
                        equal(results)
                        count += 1
        for reverse in (False, True):
            results = {}
            for version, engine in engines.items():
                original = engine.detector_policy
                policy = original.referenced_file_correlation
                policy = replace(
                    policy, web_outcome_field="custom_outcome",
                    web_feature_fields={role: f"custom_{role}" for role in policy.web_feature_fields},
                    web_branches=tuple(reversed(policy.web_branches)) if reverse else policy.web_branches,
                    web_outcome_merge=replace(policy.web_outcome_merge, ranks={
                        name: i for i, name in enumerate(reversed(tuple(policy.web_outcome_merge.ranks)))
                    }),
                )
                engine.detector_policy = fixtures.policy_with_payload(original, "referenced_file_correlation", policy)
                try:
                    with pd.option_context("mode.string_storage", "python" if storage == "object" else storage):
                        inputs = fixtures.referenced_fixture(engine, 25)
                        inputs[0]["custom_outcome"] = pd.array(["probable_success"] * 25, dtype="string")
                    if storage == "object":
                        for column in inputs[0].select_dtypes(include="string"):
                            inputs[0][column] = inputs[0][column].astype(object)
                    engine._apply_referenced_file_hit_signals_sparse(*inputs)
                    results[version] = inputs
                finally:
                    engine.detector_policy = original
            equal(results)
            count += 1
    emit("policy_variant_equivalence", cases=count, exact_outputs=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--reference-engine", type=Path,
                        help="Optional frozen engine source; --reference still locates its rules")
    parser.add_argument("--mapping-rows", type=int, default=600)
    parser.add_argument("--classifier-rows", type=int, default=4000)
    parser.add_argument("--referenced-rows", type=int, default=1000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--memory", action="store_true")
    parser.add_argument("--diverse", action="store_true",
                        help="Use unique classifier targets and unique referenced identities to stress cache misses")
    args = parser.parse_args()
    if min(args.mapping_rows, args.classifier_rows, args.referenced_rows, args.repeats) < 1:
        parser.error("row counts and repeats must be positive")
    fixtures = load_module("chronosift_benchmark_fixtures", ROOT / "tests/test_v231_performance.py")
    reference_root = args.reference.resolve()
    reference_path = args.reference_engine or reference_root / "chronoSIFT_v2_31.py"
    reference = load_module("chronosift_benchmark_reference", reference_path)
    modules = {"reference": reference, "candidate": fixtures.MODULE}
    roots = {"reference": reference_root, "candidate": ROOT}
    engines = {name: fixtures.load_engine(module, roots[name]) for name, module in modules.items()}
    import numpy as np
    import pandas as pd

    logging.getLogger().setLevel(logging.WARNING)
    warnings.filterwarnings("ignore", category=FutureWarning)
    emit("environment", python=sys.version, pandas=pd.__version__, numpy=np.__version__, diverse=args.diverse,
         sources={name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                  for name, path in {"reference": reference_path, "candidate": ROOT / "chronoSIFT_v2_31.py"}.items()})

    for name, fixture, method_name, rows in (
        ("mapping", fixtures.mapping_fixture, "_apply_web_attack_mapping_sparse", args.mapping_rows),
        ("classifier", fixtures.classifier_fixture, "_apply_web_request_classifier_sparse", args.classifier_rows),
        ("referenced_file", fixtures.referenced_fixture, "_apply_referenced_file_hit_signals_sparse", args.referenced_rows),
    ):
        make_inputs = (lambda engine, rows: diverse_fixture(name, fixture, engine, rows)) if args.diverse else fixture
        results = {}
        timings = {}
        for version, engine in engines.items():
            runs = []
            for _ in range(args.repeats):
                inputs = make_inputs(engine, rows)
                gc.collect()
                start = time.perf_counter()
                getattr(engine, method_name)(*inputs)
                runs.append(time.perf_counter() - start)
                results[version] = inputs
            timings[version] = runs
        left, right = results["reference"], results["candidate"]
        # State contents are compared separately; ignore only its storage alias.
        left[0].attrs = {}
        right[0].attrs = {}
        pd.testing.assert_frame_equal(left[0], right[0], check_exact=True)
        assert left[1] == right[1], name + " signal mismatch"
        assert left[2] == right[2], name + " explanation mismatch"
        medians = {version: statistics.median(runs) for version, runs in timings.items()}
        emit(name, rows=rows, seconds=timings, medians=medians,
             speedup=medians["reference"] / medians["candidate"], exact_outputs=True)
        del results, left, right, inputs
        if args.memory:
            for version, engine in engines.items():
                inputs = make_inputs(engine, rows)
                gc.collect()
                tracemalloc.start()
                try:
                    getattr(engine, method_name)(*inputs)
                    current, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                emit(name + "_allocation_separate_pass", version=version, rows=rows,
                     traced_current_bytes=current, traced_peak_bytes=peak)

    check_policy_variants(engines, fixtures)
    check_mapping_variants(engines, fixtures)

    # Compare complete scored sidecars from the actual partition runner, not
    # just detector internals. All synthetic input and output live in tmpdir.
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="chronosift-performance-equivalence-") as tmp:
        dataset = Path(tmp) / "dataset" / "year=2024" / "month=5"
        dataset.mkdir(parents=True)
        raw_rows = []
        for i in range(12):
            target = "/products?id=1" if i % 3 != 2 else "/products?id=1%27%20UNION%20SELECT%20x--"
            raw_rows.append({
                "datetime": pd.Timestamp("2024-05-01T00:00:00Z"),
                "chronosift_row_id": i * 3 + 100,
                "parser": "text/apache_access",
                "http_request": f"GET {target} HTTP/1.1",
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": 1024 if i % 3 != 2 else 27000,
                "message": "synthetic web request",
            })
        pd.DataFrame(raw_rows).to_parquet(dataset / "part-00000.parquet", index=False)
        for version, engine in engines.items():
            output = Path(tmp) / version
            engine.process_parquet_dataset_partitioned(str(dataset.parents[1]), str(output), output_mode="sidecar")
            frame = modules[version]._duckdb_read_parquet_df(str(output), require_datetime=False)
            outputs[version] = frame.sort_values("chronosift_row_id").reset_index(drop=True)
        pd.testing.assert_frame_equal(outputs["reference"], outputs["candidate"], check_exact=True)
        emit("partitioned_sidecar_equivalence", rows=len(outputs["candidate"]), exact_outputs=True,
             unique_row_ids=outputs["candidate"]["chronosift_row_id"].is_unique)


def check_mapping_variants(engines, fixtures):
    """Exercise prepared predicates, exclusions, multi-output order and aliases."""
    import pandas as pd
    cases = 0
    for storage in ("python", "pyarrow", "object"):
        for mode in ("all", "any"):
            for excluded in (False, True):
                for reverse in (False, True):
                    results = {}
                    for version, engine in engines.items():
                        original = engine.detector_policy
                        p = original.referenced_file_correlation
                        condition = replace(
                            p.mapping_branches[0].conditions, match=mode,
                            indicators_any=frozenset({"command_injection"}),
                            indicator_prefixes_any=("sqli_",), signals_any=frozenset({"fixture_support"}),
                            minimum_signal_value_exclusive=0.5, categories_any=frozenset({"webshell"}),
                            methods_any=frozenset({"GET"}), upload_outcomes_any=frozenset({"uploaded"}),
                            source_ip_scopes_any=frozenset({"public"}),
                        )
                        exclusion = replace(condition, match="any") if excluded else None
                        ids = tuple(p.mapping_outputs)[:3]
                        if reverse:
                            ids = tuple(reversed(ids))
                        branch = replace(p.mapping_branches[0], conditions=condition, exclude=exclusion,
                                         output_ids=ids, evidence=("attack_technique_id", "http_method", "canonical_endpoint",
                                                                  "http_response_code", "attack_indicators", "file_categories",
                                                                  "source_ip", "upload_outcome"))
                        # A second branch observes pre-mapping signals even if
                        # the first branch emits one of its signal prerequisites.
                        follow = replace(branch, branch_id="fixture_follow", exclude=None,
                                         conditions=replace(condition, match="all", indicators_any=frozenset(),
                                                            indicator_prefixes_any=(), categories_any=frozenset(),
                                                            methods_any=frozenset(), upload_outcomes_any=frozenset(),
                                                            source_ip_scopes_any=frozenset(),
                                                            signals_any=frozenset({p.mapping_outputs[ids[0]].emission.name})))
                        p = replace(p, attack_techniques_field="custom_techniques", mapping_branches=(branch, follow))
                        engine.detector_policy = fixtures.policy_with_payload(original, "referenced_file_correlation", p)
                        try:
                            with pd.option_context("mode.string_storage", "python" if storage == "object" else storage):
                                frame, signals, explanations = fixtures.mapping_fixture(engine, 128)
                                frame.attrs.clear()
                                frame["custom_techniques"] = pd.array([pd.NA if i % 2 else "T0009" for i in range(128)], dtype="string")
                            frame[p.attack_indicators_field] = ["|".join(
                                (["command_injection"] if i & 1 else []) + (["sqli_test"] if i & 2 else [])) for i in range(128)]
                            frame[p.web_feature_fields["categories"]] = ["webshell" if i & 8 else "" for i in range(128)]
                            frame[p.method_field] = ["GET" if i & 16 else "POST" for i in range(128)]
                            frame[p.upload_outcome_field] = ["uploaded" if i & 32 else "" for i in range(128)]
                            frame[p.source_ip_field] = ["8.8.8.8" if i & 64 else "10.0.0.1" for i in range(128)]
                            for i in range(128):
                                signals[i]["fixture_support"] = 1.0 if i & 4 else 0.0
                                if i % 11 == 0:
                                    signals[i][p.mapping_outputs[ids[0]].emission.name] = 2.0
                            if storage == "object":
                                for column in frame.select_dtypes(include="string"):
                                    frame[column] = frame[column].astype(object)
                            engine._apply_web_attack_mapping_sparse(frame, signals, explanations)
                            results[version] = frame, signals, explanations
                        finally:
                            engine.detector_policy = original
                    left, right = results["reference"], results["candidate"]
                    pd.testing.assert_frame_equal(left[0], right[0], check_exact=True)
                    assert left[1] == right[1], "mapping variant signal mismatch"
                    assert left[2] == right[2], "mapping variant explanation mismatch"
                    cases += 1
    emit("mapping_variant_equivalence", cases=cases, exact_outputs=True)


if __name__ == "__main__":
    main()
