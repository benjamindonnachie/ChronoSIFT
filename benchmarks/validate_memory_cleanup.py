"""Source-bound verification of the final core-output allocation cleanup.

The earlier frozen comparison checks 861,371 non-partitioned fixture rows and
204,875 native monthly rows. Verify that ONLY the sparse subsetting helper and
monthly driver change afterwards, and that no other engine caller uses that
helper. Re-run the native path, which is the affected path, plus the full suite.
"""
import argparse
import ast
import json
import logging
from pathlib import Path
import shutil
import time

import pandas as pd
import memory_replay as replay


def scope_proof(before, after):
    allowed = {"_subset_sparse_state", "process_parquet_dataset_partitioned"}
    def without_cleanup(path):
        tree = ast.parse(path.read_text())
        engine = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ChronoSiftEngine")
        found = {node.name for node in engine.body if isinstance(node, ast.FunctionDef) and node.name in allowed}
        assert found == allowed
        engine.body = [node for node in engine.body if not isinstance(node, ast.FunctionDef) or node.name not in allowed]
        callers = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute) and node.func.attr == "_subset_sparse_state"]
        assert not callers, ("Unreviewed helper caller", callers)
        return ast.dump(tree, include_attributes=False)
    assert without_cleanup(before) == without_cleanup(after), "Unrelated engine code changed"
    return sorted(allowed)


def prepare(previous, out):
    receipt = json.loads((previous / "comparison.json").read_text())
    assert receipt["passed"] and receipt["source_unchanged"]
    before = previous / "candidate/chronoSIFT_v2_31.py"
    current = replay.WT / "chronoSIFT_v2_31.py"
    changed_functions = scope_proof(before, current)
    p = json.loads((previous / "provenance.json").read_text())
    for path, value in p["hashes"].items():
        if Path(path) != current:
            assert replay.common.sha(path) == value, ("Changed prior input", path)
    p["hashes"][str(current)] = replay.common.sha(current)
    candidate = out / "candidate"; candidate.mkdir(parents=True)
    for source in (current, replay.WT / "rules/rules_evidence_calibrated_v17.yaml",
                   replay.WT / "rules/weights_evidence_calibrated_v15.yaml"):
        target = candidate / source.name; shutil.copy2(source, target)
        p["hashes"][str(source)] = replay.common.sha(source)
        p["hashes"][str(target)] = replay.common.sha(target)
    for path in (previous / "comparison.json", previous / "baseline/native-history/fingerprints.parquet",
                 previous / "candidate/native-history/fingerprints.parquet"):
        p["hashes"][str(path)] = replay.common.sha(path)
    p.update(previous_phase=str(previous), changed_functions=changed_functions,
             unchanged_non_partitioned_paths=True, before_engine_sha256=replay.common.sha(before),
             final_engine_sha256=replay.common.sha(current))
    replay.common.save(out / "provenance.json", p)


def finish(out):
    p = json.loads((out / "provenance.json").read_text()); previous = Path(p["previous_phase"])
    before = pd.read_parquet(previous / "baseline/native-history/fingerprints.parquet").set_index("id").sort_index()
    after = pd.read_parquet(out / "candidate/native-history/fingerprints.parquet").set_index("id").sort_index()
    assert before.index.equals(after.index)
    differences = {column: int((before[column] != after[column]).sum()) for column in before}
    assert not any(differences.values()), differences
    old = json.loads((previous / "baseline/native-history/result.json").read_text())
    new = json.loads((out / "candidate/native-history/result.json").read_text())
    assert old["columns"] == new["columns"]
    regression = json.loads((out / "regression.json").read_text())
    assert regression["successful"] and regression["source_unchanged"]
    for path, value in {**p["hashes"], **regression["sha256"]}.items():
        assert replay.common.sha(path) == value, ("Changed validation source/input", path)
    replay.common.save(out / "validation.json", dict(passed=True, native_rows=len(after), differences=differences,
        tested_rows_in_prior_unchanged_non_partitioned_paths=861371,
        unchanged_non_partitioned_paths=True, tests=regression["tests"], skipped=regression["skipped"],
        final_engine_sha256=p["final_engine_sha256"], resources_and_sources_unchanged=True,
        changed_functions=p["changed_functions"]))
    print("FINAL MEMORY CANDIDATE VALIDATED", len(after), regression["tests"], flush=True)


if __name__ == "__main__":
    logging.Formatter.converter = time.gmtime
    parser = argparse.ArgumentParser(); parser.add_argument("mode", choices=["prepare", "native", "finish"])
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare": prepare(args.previous, args.output)
    elif args.mode == "native": replay.native(args.output, "candidate")
    else: finish(args.output)
