"""End-to-end eager/lazy sidecar parity with profiling and month overlap."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
from test_v231_memory import M, ROOT, rule


class DeferredSidecarTests(unittest.TestCase):
    def test_monthly_writer_preserves_payload_scores_and_profile_fields(self):
        frame = pd.DataFrame({"chronosift_row_id": [101, 104, 107, 110, 113, 116],
            "flag": ["yes", "no", "yes"] * 2,
            "payload": ["first", "unused", "third", "fourth", "unused", "sixth"],
            "parser": ["fixture"] * 6, "hostname": ["memory.test"] * 6},
            index=pd.DatetimeIndex(["2024-05-31T23:59:59Z"] * 3 + ["2024-06-01T00:00:00Z"] * 3,
                                   name="datetime"))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); inputs = directory / "input"
            M.write_time_partitioned_parquet(frame, str(inputs), normalise=False)
            results = []
            for label in ("eager", "lazy"):
                engine = M.ChronoSiftEngine.from_yaml(ROOT / "rules/rules_evidence_calibrated_v17.yaml",
                                                    ROOT / "rules/weights_evidence_calibrated_v15.yaml")
                engine.rules = [rule()]; engine.required_fields = engine._collect_required_fields()
                target = directory / label; telemetry = directory / (label + ".jsonl")
                with patch.object(M, "load_plaso_parquet_timerange", wraps=M.load_plaso_parquet_timerange) as reads:
                    if label == "eager":
                        with patch.object(engine, "_deferred_atomic_evidence_fields", return_value=set()), \
                             patch.object(engine, "_release_sidecar_stage_inputs", return_value=[]):
                            engine.process_parquet_dataset_partitioned(str(inputs), str(target), output_mode="sidecar",
                                materialise_event_columns=True, telemetry_jsonl_path=str(telemetry))
                    else:
                        engine.process_parquet_dataset_partitioned(str(inputs), str(target), output_mode="sidecar",
                            materialise_event_columns=True, telemetry_jsonl_path=str(telemetry))
                        self.assertTrue(all("payload" not in call.kwargs["columns"] for call in reads.call_args_list))
                        events = [json.loads(line) for line in telemetry.read_text().splitlines()]
                        loads = [e for e in events if e["event"] == "deferred_evidence"]
                        self.assertEqual(len(loads), 2)
                        self.assertTrue(all(e["fields"] == ["payload"] for e in loads))
                result = M.load_plaso_parquet_dataset(str(target)).set_index("chronosift_row_id").sort_index()
                result.attrs = {}; results.append(result)
            self.assertEqual(results[1].index.tolist(), frame.chronosift_row_id.tolist())
            pd.testing.assert_frame_equal(results[0], results[1])
            for rid, payload in {101: "first", 107: "third", 110: "fourth", 116: "sixth"}.items():
                explanations = results[1].loc[rid, "chronosift_explain"]
                match = next(e for e in explanations if e["rule_id"] == "MEMORY")
                self.assertEqual(match["evidence"]["payload"], payload)


if __name__ == "__main__":
    unittest.main()
