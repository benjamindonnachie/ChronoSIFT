"""Storage-only regressions: stable row keys, missing semantics and bounded work."""
from copy import deepcopy
from dataclasses import replace
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from test_v231_performance import MODULE as M, ROOT, CopyForbidden


def rule(name="MEMORY", field="flag", op="eq", value="yes", evidence=("payload",)):
    return M.Rule(name, "Memory fixture", 1, [], [], [], [M.Condition(field, op, value)],
                  [M.EmitSignal("fixture_signal", 1.0)], list(evidence), "high")


class MemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = M.ChronoSiftEngine.from_yaml(
            ROOT / "rules/rules_evidence_calibrated_v17.yaml",
            ROOT / "rules/weights_evidence_calibrated_v15.yaml")

    def frame(self, count=4):
        return pd.DataFrame({"chronosift_row_id": np.arange(count, dtype=np.int64) * 3 + 7},
                            index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * count))

    def test_missing_columns_have_zero_value_buffers_and_preserve_presence(self):
        original = self.frame(10000)
        frame = M._ensure_object_columns(original, [f"absent{i}" for i in range(250)])
        self.assertEqual(len(frame.columns), 251)
        self.assertEqual(sum(frame[c].memory_usage(index=False) for c in frame if c != "chronosift_row_id"), 0)
        self.assertTrue(frame.absent0.isna().all())
        self.assertEqual(frame.absent0.astype("string").fillna("").tolist(), [""] * len(frame))
        self.assertEqual(frame.chronosift_row_id.tolist(), original.chronosift_row_id.tolist())

    def test_partial_write_promotes_only_target_without_copying_metadata(self):
        frame = M._ensure_object_columns(self.frame(), ["a", "b"])
        state = {"guard": CopyForbidden()}; frame.attrs["chronosift_sparse"] = state
        M._materialise_null_column(frame, "a")
        self.assertIs(frame.attrs["chronosift_sparse"], state)
        with M._detached_sparse_state(frame):
            frame.iloc[2, frame.columns.get_loc("a")] = "value"
            self.assertEqual(frame.a.iloc[2], "value")
            self.assertTrue(frame.a.iloc[[0, 1, 3]].isna().all())
            self.assertTrue(M._is_compact_null(frame.b))

    def test_null_broadcasts_are_readonly_and_share_one_value(self):
        frame = M._ensure_object_columns(self.frame(1000), ["missing"])
        for name in ("missing", "not_present"):
            values = M._column_values_or_none(frame, name)
            self.assertFalse(values.flags.writeable)
            self.assertEqual(values.strides, (0,))
            self.assertTrue(all(value is None for value in values))

    def test_compact_null_parquet_readback(self):
        frame = M._ensure_object_columns(self.frame(), ["missing"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.parquet"
            frame.to_parquet(path)
            result = pd.read_parquet(path)
        self.assertEqual(result.chronosift_row_id.tolist(), frame.chronosift_row_id.tolist())
        self.assertTrue(result.missing.isna().all())

    def test_atomic_missing_conditions_match_dense_null_reference(self):
        for op, value in [("isnull", None), ("notnull", None), ("eq", ""), ("ne", "x"),
                          ("contains", "x"), ("regex", "^$"), ("in", ["x", ""]), ("gt", 3)]:
            with self.subTest(op=op):
                dense = self.frame(); dense["missing"] = pd.Series(None, index=dense.index, dtype=object)
                compact = M._ensure_object_columns(self.frame(), ["missing"])
                with patch.object(self.engine, "rules", [rule(field="missing", op=op, value=value, evidence=("missing",))]):
                    self.assertEqual(self.engine._eval_atomic_rules_sparse(compact),
                                     self.engine._eval_atomic_rules_sparse(dense))

    def test_atomic_last_use_eviction_preserves_shared_and_shortcircuited_conditions(self):
        frame = self.frame(); frame["flag"] = ["yes", "no", "yes", "no"]
        frame["payload"] = [{"nested": [1, 2]}, None, [3, 4], "text"]
        rules = [rule("A"), replace(rule("B"), scope_all=[M.Condition("absent", "eq", "never")]),
                 replace(rule("C"), when_any=[M.Condition("payload", "notnull")])]
        with patch.object(self.engine, "rules", rules):
            self.assertEqual(self.engine._eval_atomic_rules_sparse(frame),
                             self.engine._eval_atomic_rules_sparse_legacy(frame))

    def test_systemd_batches_keep_global_positions_and_exact_evidence(self):
        frame = self.frame(65539)
        frame["message"] = "ordinary"; frame["filename"] = "/tmp/ordinary.txt"
        frame["timestamp_desc"] = "mtime"; frame["hostname"] = "fixture"
        positions = [0, 65535, 65536, 65538]
        frame.iloc[positions, frame.columns.get_loc("message")] = "systemctl enable fixture.service"
        frame.iloc[positions, frame.columns.get_loc("filename")] = "/etc/systemd/system/fixture.service"
        signal = self.engine.detector_policy.systemd_service_persistence.emission.name
        signals = {65536: {signal: 2.0}}; explanations = {65536: [{"prior": True}]}
        expected_signals, expected_explanations = deepcopy(signals), deepcopy(explanations)
        # A single batch is the same row-local algorithm without subdivision.
        self.engine._apply_systemd_service_persistence_batch(frame, expected_signals, expected_explanations, row_offset=0)
        with patch.object(self.engine, "_apply_systemd_service_persistence_batch",
                          wraps=self.engine._apply_systemd_service_persistence_batch) as execute:
            self.engine._apply_systemd_service_persistence_sparse(frame, signals, explanations)
        self.assertEqual([len(call.args[0]) for call in execute.call_args_list], [65536, 3])
        self.assertEqual(signals, expected_signals)
        self.assertEqual(explanations, expected_explanations)
        self.assertEqual(set(signals), set(positions))

    def test_sidecar_release_keeps_all_declared_consumers_and_outputs(self):
        frame = M._ensure_object_columns(self.frame(), self.engine.required_fields | {"unneeded_payload"})
        keep = set(self.engine._temporal_required_columns()) | set(self.engine._configured_sidecar_output_columns())
        present = keep & set(frame.columns)
        removed = self.engine._release_sidecar_stage_inputs(frame, "chronosift_row_id", temporal_only=True)
        self.assertIn("unneeded_payload", removed)
        self.assertTrue(present <= set(frame.columns))
        self.assertIn("chronosift_row_id", frame)

    def test_evidence_planner_protects_aliases_conditions_and_outputs(self):
        rules = [rule(evidence=("payload", "flag", "actor_principal", "alias_canonical", "alias_raw"))]
        with patch.object(self.engine, "rules", rules), patch.object(self.engine, "schema_aliases", {"alias_canonical": ("alias_raw",)}):
            with patch.object(self.engine, "required_fields", self.engine._collect_required_fields()):
                self.assertEqual(self.engine._deferred_atomic_evidence_fields(
                    {"payload", "flag", "actor_principal", "alias_canonical", "alias_raw"}, "chronosift_row_id"), {"payload"})

    def parquet_source(self, directory, duplicate=False):
        path = Path(directory) / "year=2024" / "month=5"; path.mkdir(parents=True)
        frame = self.frame(); frame["payload"] = [["a", "b"], ["c"], None, []]
        frame.index.name = "datetime"
        if duplicate:
            frame.iloc[1, 0] = frame.iloc[0, 0]
        pq.write_table(pa.Table.from_pandas(frame), path / "events.parquet")
        return M._ParquetEvidenceSource(str(Path(directory)), {"payload"}, "chronosift_row_id",
                pd.Timestamp("2024-05-01T00:00:00Z"), pd.Timestamp("2024-05-31T23:59:59Z"))

    def test_deferred_nested_payload_preserves_requested_integer_key_order(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.parquet_source(directory)
            result = source.fetch(pd.Series([16, 7, 13], dtype="int64"), ["payload"])
            eager = M.load_plaso_parquet_dataset(directory).set_index("chronosift_row_id")
            self.assertEqual([M._safe_str(v) for v in result.payload],
                             [M._safe_str(v) for v in eager.loc[[16, 7, 13], "payload"]])
            self.assertEqual((source.batches, source.rows_fetched), (1, 3))

    def test_deferred_reader_rejects_bad_keys_and_unplanned_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.parquet_source(directory)
            for ids in ([7, 7], [999], [7.0], [None], list(range(65537))):
                with self.subTest(ids=str(ids[:3])), self.assertRaises(ValueError):
                    source.fetch(pd.Series(ids), ["payload"])
            with self.assertRaises(ValueError):
                source.fetch(pd.Series([7]), ["unknown"])
        with tempfile.TemporaryDirectory() as directory:
            source = self.parquet_source(directory, duplicate=True)
            with self.assertRaisesRegex(ValueError, "missing, duplicated or mismatched"):
                source.fetch(pd.Series([7]), ["payload"])

    def test_atomic_deferred_is_matched_only_bounded_and_identical(self):
        class Source:
            fields = {"payload"}; row_id_col = "chronosift_row_id"
            def __init__(self): self.sizes = []
            def fetch(self, ids, columns):
                self.sizes.append(len(ids))
                return pd.DataFrame({"payload": [str(i) for i in ids]})
        source = Source(); frame = self.frame(65539); frame["flag"] = "yes"
        frame["payload"] = frame.chronosift_row_id.astype(str)
        with patch.object(self.engine, "rules", [rule()]):
            eager = self.engine._eval_atomic_rules_sparse(frame)
            late = self.engine._eval_atomic_rules_sparse(frame.drop(columns=["payload"]), evidence_source=source)
            self.assertEqual(late, eager); self.assertEqual(source.sizes, [65536, 3])
            frame["flag"] = "no"; source.sizes.clear()
            self.assertEqual(self.engine._eval_atomic_rules_sparse(frame, evidence_source=source), ({}, {}))
            self.assertEqual(source.sizes, [])

    def test_failed_deferred_read_never_falls_back_to_missing_evidence(self):
        class Source:
            fields = {"payload"}; row_id_col = "chronosift_row_id"
            def fetch(self, ids, columns): raise RuntimeError("payload read failed")
        frame = self.frame(); frame["flag"] = "yes"
        with patch.object(self.engine, "rules", [rule()]), patch.object(self.engine, "_eval_atomic_rules_sparse_legacy") as fallback:
            with self.assertRaisesRegex(RuntimeError, "payload read failed"):
                self.engine.apply_atomic(frame, apply_profiling=False, evidence_source=Source())
            fallback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
