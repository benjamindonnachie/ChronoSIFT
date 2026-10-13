"""Core-output projection must not allocate a position map it never consumes."""
import unittest
import json
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import pyarrow.parquet as pq
import numpy as np
import pandas as pd
from test_v231_performance import MODULE as M, CopyForbidden


class CoreMaterialisationTests(unittest.TestCase):
    def test_optional_position_map_preserves_rows_and_shared_sparse_payloads(self):
        frame = pd.DataFrame({"chronosift_row_id": [19, 7, 28, 16, 22], "value": list("abcde")},
            index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * 5))
        signals = {0: {"fixture": 1.0}, 2: {}, 4: {"fixture": 2.0}}
        explanations = {0: [{"rule_id": "FIXTURE", "evidence": {"nested": [1, 2]}}], 2: []}
        state = {"signal_map": signals, "explain_map": explanations, "guard": CopyForbidden()}
        frame.attrs["chronosift_sparse"] = state
        mask = np.array([True, False, True, False, True])
        normal = M.ChronoSiftEngine._subset_sparse_state(frame, signals, explanations, mask)
        core = M.ChronoSiftEngine._subset_sparse_state(frame, signals, explanations, mask,
                                                      build_position_map=False)
        self.assertEqual(normal[3], {0: 0, 2: 1, 4: 2})
        self.assertEqual(core[3], {})
        self.assertIs(frame.attrs["chronosift_sparse"], state)
        with M._detached_sparse_state(core[0]), M._detached_sparse_state(normal[0]):
            pd.testing.assert_frame_equal(core[0], normal[0])
            self.assertEqual(core[0].chronosift_row_id.tolist(), [19, 28, 22])
        self.assertEqual(core[1], normal[1]); self.assertEqual(core[2], normal[2])
        self.assertIs(core[1][0], signals[0]); self.assertIs(core[1][1], signals[2])
        self.assertIs(core[2][0], explanations[0])
        self.assertIs(core[2][1], explanations[2])


    def test_owned_contiguous_core_preserves_values_without_copying_month_data(self):
        frame = pd.DataFrame({"chronosift_row_id": np.arange(20) + 2**53,
                              "value": np.arange(20, dtype=float),
                              "text": pd.array(["İ", None] * 10, dtype="string[pyarrow]")},
                             index=pd.date_range("2024-05-01", periods=20, freq="s", tz="UTC"))
        signals = {i: {"fixture": float(i)} for i in range(20)}
        explanations = {i: [{"row_id": i}] for i in range(20)}
        frame.attrs["chronosift_sparse"] = {"signal_map": signals,
                                             "explain_map": explanations,
                                             "guard": CopyForbidden()}
        mask = np.zeros(20, dtype=bool); mask[3:17] = True
        expected = M.ChronoSiftEngine._subset_sparse_state(frame, signals, explanations,
                                                          mask, columns=list(frame.columns))
        actual = M.ChronoSiftEngine._subset_sparse_state(frame, signals, explanations,
            mask, columns=list(frame.columns), prefer_contiguous_slice=True)
        with M._detached_sparse_state(frame), M._detached_sparse_state(expected[0]), M._detached_sparse_state(actual[0]):
            pd.testing.assert_frame_equal(actual[0], expected[0])
            self.assertTrue(np.shares_memory(frame["value"].to_numpy(copy=False),
                                              actual[0]["value"].to_numpy(copy=False)))
            actual[0].loc[actual[0].index[0], "value"] = -1
            self.assertEqual(frame["value"].iloc[3], 3.0)
        self.assertEqual(actual[1:], expected[1:])
        self.assertIs(actual[1][0], signals[3])
        self.assertIs(actual[2][0], explanations[3])

    def test_contiguous_preference_keeps_irregular_empty_and_column_order_semantics(self):
        frame = pd.DataFrame({"chronosift_row_id": np.arange(20), "value": np.arange(20)},
                             index=pd.date_range("2500-05-01", periods=20, freq="s", tz="UTC", unit="us"))
        for selected in ([0, 5, 8, 18], [], list(range(4, 13))):
            with self.subTest(selected=selected):
                mask = np.zeros(20, dtype=bool); mask[selected] = True
                args = (frame, {i: {"fixture": i} for i in selected}, {}, mask)
                expected = M.ChronoSiftEngine._subset_sparse_state(*args, columns=["value", "chronosift_row_id"])
                actual = M.ChronoSiftEngine._subset_sparse_state(*args, columns=["value", "chronosift_row_id"],
                                                               prefer_contiguous_slice=True)
                with M._detached_sparse_state(expected[0]), M._detached_sparse_state(actual[0]):
                    pd.testing.assert_frame_equal(actual[0], expected[0])
                self.assertEqual(actual[1:], expected[1:])

    def test_native_history_writer_never_deepcopies_sparse_state_across_batches(self):
        core_rows = 65_537
        stamps = pd.DatetimeIndex([pd.Timestamp("2024-04-30T23:59:59Z"),
            *pd.date_range("2024-05-01", periods=core_rows, freq="s", tz="UTC"),
            pd.Timestamp("2024-06-01T00:00:00Z")])
        frame = pd.DataFrame({"chronosift_row_id": np.arange(len(stamps)) + 2**53,
                              "chronosift_score": np.arange(len(stamps), dtype=float) % 51}, index=stamps)
        signals = {i: {"fixture": 1.0 + i % 3} for i in range(len(frame))}
        explanations = {i: [{"rule_id": "fixture", "evidence": {"row": i}}]
                        for i in (0, 1, 65_536, 65_537, 65_538)}
        frame.attrs["chronosift_sparse"] = {"signal_map": signals,
                                             "explain_map": explanations,
                                             "guard": CopyForbidden()}
        engine = object.__new__(M.ChronoSiftEngine)
        engine._deferred_atomic_evidence_fields = lambda *args: set()
        engine._atomic_required_columns = lambda: set(frame.columns)
        engine.apply_atomic = lambda data, **kwargs: data
        engine._release_sidecar_stage_inputs = lambda *args, **kwargs: None
        engine._apply_non_temporal_contextual_sparse = lambda *args, **kwargs: None
        engine._mark_compact_temporal_payload_candidates = lambda *args: None
        telemetry = SimpleNamespace(stage=lambda *args, **kwargs: nullcontext())
        ids, scores = [], []
        with TemporaryDirectory() as temp, patch.object(M, "_duckdb_dataset_columns", return_value=set(frame.columns)), \
             patch.object(M, "load_plaso_parquet_timerange", return_value=frame):
            receipt = engine._prepare_history_month("unused", temp, 2024, 5,
                {"feature_seconds": 86400}, telemetry, row_id_col="chronosift_row_id",
                profile_manifest={}, file_hit_manifest={}, nsrl_cache_df=None,
                retain_zero_weight_lifecycle_signals=False, enrichment={})
            self.assertEqual(receipt["rows"], core_rows)
            self.assertEqual(len(receipt["files"]), 2)
            for file in receipt["files"]:
                for batch in pq.ParquetFile(file).iter_batches(batch_size=65_536):
                    cached = engine._history_batch_to_frame(batch)
                    # Inspect the stored Arrow map/list itself. Arrow's default
                    # pandas conversion represents MAP values as key/value pairs.
                    records = batch.to_pylist()
                    for i, row_id in enumerate(cached.chronosift_row_id):
                        old = int(row_id) - 2**53
                        self.assertEqual(dict(records[i]["chronosift_signals"]), signals[old])
                        evidence = [json.loads(value) for value in (records[i]["chronosift_explain"] or [])]
                        self.assertEqual(evidence, explanations.get(old, []))
                    ids.extend(cached.chronosift_row_id.tolist())
                    scores.extend(cached.chronosift_score.tolist())
            self.assertTrue((Path(temp) / "year=2024/month=05/complete.json").exists())
        self.assertEqual(ids, list(np.arange(1, core_rows + 1) + 2**53))
        self.assertEqual(scores, list(np.arange(1, core_rows + 1, dtype=float) % 51))


if __name__ == "__main__":
    unittest.main()
