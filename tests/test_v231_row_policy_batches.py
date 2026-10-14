"""Row-local policy batches preserve semantics and bound disposable text arrays."""
from copy import deepcopy
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
from test_v231_performance import MODULE as M, ROOT, CopyForbidden


class RowPolicyBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = M.ChronoSiftEngine.from_yaml(
            str(ROOT / "rules/rules_evidence_calibrated_v27.yaml"),
            str(ROOT / "rules/weights_evidence_calibrated_v23.yaml"),
        )

    @staticmethod
    def frame(n=29):
        commands = [r"copy \\server\admin$\payload.exe",
                    "tar -czf /var/backups/nightly.tgz /srv/data",
                    "vssadmin delete shadows /all", None]
        frame = pd.DataFrame({
            "chronosift_row_id": np.arange(n, dtype=np.int64) + 2**53 + 11,
            "actor_cmd": pd.array([commands[i % 4] for i in range(n)], dtype="string[pyarrow]"),
            "auth_outcome": "success", "auth_protocol": "windows-network",
            "message": pd.array(["  İ Σ Straße  ", None] * (n // 2) + [""] * (n % 2), dtype="string[pyarrow]"),
            "timestamp_desc": ["Creation Time" if i % 2 else "Access Time" for i in range(n)],
        }, index=pd.DatetimeIndex([pd.Timestamp("2500-05-01", tz="UTC")] * n))
        return frame

    def run_policy(self, frame, signals, explanations, executor, detector, batch_rows):
        with patch.object(M, "_ROW_POLICY_BATCH_ROWS", batch_rows):
            getattr(self.engine, executor)(frame, signals, explanations, {}, detector_id=detector)
        return signals, explanations, self.engine._score_signal_map_sparse(len(frame), signals, frame.index)

    def assert_same(self, expected, actual):
        self.assertEqual(expected[:2], actual[:2])
        pd.testing.assert_series_equal(expected[2], actual[2])

    def test_direct_rules_preserve_dependencies_and_global_sparse_positions(self):
        frame = self.frame()
        original = frame.copy()
        signals = {i: {"fixture": 0.25} for i in (1, 6, 7, 14, 21, 28)}
        explanations = {i: [{"rule_id": "fixture", "evidence": {"nested": [i]}}] for i in signals}
        args = ("_apply_ordered_row_rules_sparse", "direct_attack_semantics")
        expected = self.run_policy(frame, deepcopy(signals), deepcopy(explanations), *args, 10**9)
        actual = self.run_policy(frame, deepcopy(signals), deepcopy(explanations), *args, 7)
        self.assert_same(expected, actual)
        for i in range(0, len(frame), 4):
            self.assertEqual(actual[0][i]["smb_admin_share"], 1.0)
            self.assertEqual(actual[0][i]["external_remote_service"], 1.0)
        pd.testing.assert_frame_equal(frame, original)

    def test_adjustments_preserve_zeros_explanations_and_scores(self):
        n = 29
        commands = ["nslookup example.test", "tasklist /svc",
                    "tar -czf /var/backups/nightly.tgz /srv/data"]
        initial = [
            {"remote_system_discovery": 1., "exec_network_tool": 1., "suspicious_execution": .75},
            {"exec_shell_spawn": 1., "system_owner_user_discovery": 1., "suspicious_execution": 1.},
            {"lolbin_linux": 1., "exec_archive_tool": 1., "suspicious_execution": 1.},
        ]
        frame = self.frame(n)
        frame["actor_cmd"] = [commands[i % 3] for i in range(n)]
        frame["message"] = ""
        signals = {i: deepcopy(initial[i % 3]) for i in range(n)}
        args = ("_apply_ordered_signal_adjustments_sparse", "contextual_signal_adjustments")
        expected = self.run_policy(frame, deepcopy(signals), {}, *args, 10**9)
        actual = self.run_policy(frame, deepcopy(signals), {}, *args, 7)
        self.assert_same(expected, actual)
        self.assertEqual(actual[0][0]["remote_system_discovery"], 1.)
        self.assertEqual(actual[0][1]["exec_shell_spawn"], 0.)
        self.assertEqual(actual[0][2]["exec_archive_tool"], expected[0][2]["exec_archive_tool"])
        self.assertTrue(actual[1])

    def test_text_resolution_is_bounded_without_deepcopying_sparse_attrs(self):
        frame = self.frame()
        expected_ids = frame.chronosift_row_id.tolist()
        signals, explanations = {}, {}
        state = {"signal_map": signals, "explain_map": explanations, "guard": CopyForbidden()}
        frame.attrs["chronosift_sparse"] = state
        observed = []
        original = self.engine._resolve_row_policy_inputs

        def observe(batch, inputs, cache):
            self.assertNotIn("chronosift_sparse", batch.attrs)
            self.assertTrue(np.shares_memory(frame.chronosift_row_id.to_numpy(), batch.chronosift_row_id.to_numpy()))
            observed.append(batch.chronosift_row_id.tolist())
            return original(batch, inputs, cache)

        with patch.object(self.engine, "_resolve_row_policy_inputs", side_effect=observe):
            self.run_policy(frame, signals, explanations, "_apply_ordered_row_rules_sparse", "direct_attack_semantics", 7)
        self.assertEqual([len(x) for x in observed], [7, 7, 7, 7, 1])
        self.assertEqual([v for batch in observed for v in batch], expected_ids)
        self.assertIs(frame.attrs["chronosift_sparse"], state)
        self.assertIn(28, signals)

    def test_sparse_attrs_are_restored_on_failure_and_empty_frame(self):
        frame = self.frame()
        state = {"guard": CopyForbidden()}
        frame.attrs["chronosift_sparse"] = state
        with patch.object(self.engine, "_resolve_row_policy_inputs", side_effect=RuntimeError("fixture failure")):
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                self.run_policy(frame, {}, {}, "_apply_ordered_row_rules_sparse", "direct_attack_semantics", 7)
        self.assertIs(frame.attrs["chronosift_sparse"], state)
        with M._detached_sparse_state(frame):
            empty = frame.iloc[:0]
        empty.attrs["chronosift_sparse"] = state
        with patch.object(self.engine, "_resolve_row_policy_inputs") as resolve:
            self.run_policy(empty, {}, {}, "_apply_ordered_row_rules_sparse", "direct_attack_semantics", 7)
        resolve.assert_not_called()
        self.assertIs(empty.attrs["chronosift_sparse"], state)

    def test_default_boundary_has_exact_tail_ids_signals_and_explanations(self):
        n = 65_537
        frame = pd.DataFrame({"chronosift_row_id": np.arange(n, dtype=np.int64) + 2**53 + 1,
                              "actor_cmd": pd.array([None] * n, dtype="string[pyarrow]"),
                              "auth_outcome": "success", "auth_protocol": "windows-network"},
                             index=pd.DatetimeIndex([pd.Timestamp("2024-05-01", tz="UTC")] * n))
        frame.iloc[[0, n - 1], frame.columns.get_loc("actor_cmd")] = r"copy \\server\admin$\payload.exe"
        args = ("_apply_ordered_row_rules_sparse", "direct_attack_semantics")
        expected = self.run_policy(frame, {}, {}, *args, 10**9)
        with patch.object(self.engine, "_resolve_row_policy_inputs", wraps=self.engine._resolve_row_policy_inputs) as resolve:
            actual = self.run_policy(frame, {}, {}, *args, 65_536)
        self.assertEqual([len(call.args[0]) for call in resolve.call_args_list], [65_536, 1])
        self.assert_same(expected, actual)
        self.assertEqual(actual[0][n - 1]["external_remote_service"], 1.)

    def test_partial_executor_updates_and_sparse_attrs_survive_failure(self):
        frame = self.frame()
        signals, explanations = {}, {}
        state = {"signal_map": signals, "explain_map": explanations, "guard": CopyForbidden()}
        frame.attrs["chronosift_sparse"] = state
        calls = []

        def execute(batch, batch_signals, batch_explanations, cache, *, detector_id):
            calls.append(len(batch))
            batch_signals[0] = {"fixture": float(len(calls))}
            batch_explanations[0] = [{"rule_id": "fixture"}]
            if len(calls) == 2:
                raise RuntimeError("fixture after mutation")

        with patch.object(M, "_ROW_POLICY_BATCH_ROWS", 7):
            with self.assertRaisesRegex(RuntimeError, "fixture after mutation"):
                self.engine._apply_row_local_policy_in_batches(frame, signals, explanations,
                    executor=execute, detector_id="fixture")
        self.assertEqual(calls, [7, 7])
        self.assertEqual(signals, {0: {"fixture": 1.}, 7: {"fixture": 2.}})
        self.assertEqual(explanations, {0: [{"rule_id": "fixture"}], 7: [{"rule_id": "fixture"}]})
        self.assertIs(frame.attrs["chronosift_sparse"], state)


if __name__ == "__main__":
    unittest.main()
