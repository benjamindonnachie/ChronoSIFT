"""Focused runtime regressions for typed temporal detector policies."""

from copy import deepcopy
import importlib.util
import pathlib
import sys
import unittest

import pandas as pd
import yaml


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "chronoSIFT_v2_31.py"
SPEC = importlib.util.spec_from_file_location(
    "chronosift_v2_31_temporal_detector_policy", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ChronoSiftEngine = MODULE.ChronoSiftEngine
RULES_PATH = PROJECT_ROOT / "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = PROJECT_ROOT / "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"


def _load_yaml(path):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


BASE_RULES = _load_yaml(RULES_PATH)
BASE_WEIGHTS = _load_yaml(WEIGHTS_PATH)
BASE_YARA_PATH = str(
    (
        PROJECT_ROOT
        / BASE_RULES["detector_policy"]["detectors"]["yara_classification"][
            "metadata"
        ]["path"]
    ).resolve()
)


class ChronoSiftV231TemporalDetectorPolicyTest(unittest.TestCase):
    def setUp(self):
        self.engine = ChronoSiftEngine.from_yaml(
            str(RULES_PATH),
            str(WEIGHTS_PATH),
        )

    @staticmethod
    def _engine(rules):
        return ChronoSiftEngine(
            deepcopy(rules),
            deepcopy(BASE_WEIGHTS),
            yara_metadata_path=BASE_YARA_PATH,
        )

    def _apply(self, timestamps, rows, signal_map):
        frame = pd.DataFrame(rows, index=pd.DatetimeIndex(timestamps))
        explain_map = {row_i: [] for row_i in signal_map}
        self.engine._apply_deadbox_temporal_composites_sparse(
            frame,
            signal_map,
            explain_map,
        )
        return signal_map, explain_map

    @staticmethod
    def _explain(explain_map, row_i, rule_id):
        return next(
            item for item in explain_map.get(row_i, [])
            if item["rule_id"] == rule_id
        )

    def test_generic_temporal_rules_emit_only_on_declared_anchor_rows(self):
        start = pd.Timestamp("2024-06-16T08:00:00Z")

        cooccur_frame = pd.DataFrame(
            {"actor_principal": ["alice", "alice", "alice"]},
            index=pd.DatetimeIndex(
                [
                    start,
                    start + pd.Timedelta(minutes=1),
                    start + pd.Timedelta(minutes=2),
                ]
            ),
        )
        cooccur_signals = {
            0: {"transfer_execution": 1.0},
            1: {"boundary_crossing": 1.0},
            2: {"service_stop": 1.0},
        }
        cooccur_explain = {0: [], 1: [], 2: []}
        self.engine._apply_temporal_rules_sparse(
            cooccur_frame,
            cooccur_signals,
            cooccur_explain,
        )
        self.assertEqual(cooccur_signals[1]["cross_border_transfer"], 1.0)
        self.assertNotIn("cross_border_transfer", cooccur_signals[0])
        self.assertNotIn("cross_border_transfer", cooccur_signals[2])

        sequence_frame = pd.DataFrame(
            {"actor_principal": ["alice"] * 5},
            index=pd.date_range(start, periods=5, freq="min"),
        )
        sequence_signals = {
            0: {"auth_remote_failure": 1.0},
            1: {"auth_remote_failure": 1.0},
            2: {"auth_remote_failure": 1.0},
            3: {"auth_remote_success": 1.0},
            4: {"service_stop": 1.0},
        }
        sequence_explain = {row_i: [] for row_i in range(5)}
        self.engine._apply_temporal_rules_sparse(
            sequence_frame,
            sequence_signals,
            sequence_explain,
        )
        self.assertEqual(sequence_signals[3]["fail_then_success_user"], 1.0)
        self.assertNotIn("fail_then_success_user", sequence_signals[4])

    def test_generic_temporal_emit_on_is_required_and_mode_specific(self):
        rules = deepcopy(BASE_RULES)
        del rules["temporal_rules"][0]["emit_on"]
        with self.assertRaisesRegex(
            ValueError,
            r"temporal_rules\[0\]: missing required key\(s\): emit_on",
        ):
            self.engine._parse_temporal_rules(rules["temporal_rules"])

        mode_cases = (
            (0, "current_input", "sequence_completion, sequence_start"),
            (10, "sequence_completion", "current_input, window_start"),
            (
                14,
                "current_input",
                "condition_match, reference_observation",
            ),
        )
        for index, configured, expected in mode_cases:
            with self.subTest(index=index):
                rules = deepcopy(BASE_RULES)
                rules["temporal_rules"][index]["emit_on"] = configured
                with self.assertRaisesRegex(
                    ValueError,
                    rf"temporal_rules\[{index}\]\.emit_on: expected one of {expected}",
                ):
                    self.engine._parse_temporal_rules(rules["temporal_rules"])

    def test_generic_temporal_emit_anchors_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        rules["temporal_rules"][0]["emit_on"] = "sequence_start"
        rules["temporal_rules"][10]["emit_on"] = "window_start"
        rules["temporal_rules"][14]["emit_on"] = "reference_observation"
        engine = self._engine(rules)
        start = pd.Timestamp("2024-06-16T08:00:00Z")

        sequence_frame = pd.DataFrame(
            {"actor_principal": ["alice"] * 4},
            index=pd.date_range(start, periods=4, freq="min"),
        )
        sequence_signals = {
            0: {"auth_remote_failure": 1.0},
            1: {"auth_remote_failure": 1.0},
            2: {"auth_remote_failure": 1.0},
            3: {"auth_remote_success": 1.0},
        }
        engine._apply_temporal_rules_sparse(
            sequence_frame,
            sequence_signals,
            {row_i: [] for row_i in range(4)},
        )
        self.assertEqual(sequence_signals[0]["fail_then_success_user"], 1.0)
        self.assertNotIn("fail_then_success_user", sequence_signals[3])

        cooccur_frame = pd.DataFrame(
            {"actor_principal": ["alice", "alice"]},
            index=pd.date_range(start, periods=2, freq="min"),
        )
        cooccur_signals = {
            0: {"transfer_execution": 1.0},
            1: {"boundary_crossing": 1.0},
        }
        engine._apply_temporal_rules_sparse(
            cooccur_frame, cooccur_signals, {0: [], 1: []}
        )
        self.assertEqual(cooccur_signals[0]["cross_border_transfer"], 1.0)
        self.assertNotIn("cross_border_transfer", cooccur_signals[1])

        condition_frame = pd.DataFrame(
            {
                "src_ip": ["203.0.113.10", "203.0.113.10"],
                "actor_principal": ["alice", "bob"],
            },
            index=pd.date_range(start, periods=2, freq="min"),
        )
        condition_signals = {}
        engine._apply_temporal_rules_sparse(
            condition_frame, condition_signals, {}
        )
        self.assertEqual(
            condition_signals[0]["auth_pivot_accounts_from_same_src"], 1.0
        )
        self.assertNotIn(1, condition_signals)

    def test_generic_temporal_lookback_lower_bound_is_strict_and_authoritative(self):
        rules = deepcopy(BASE_RULES)
        del rules["temporal_rules"][0]["lookback_lower_bound"]
        with self.assertRaisesRegex(
            ValueError,
            r"temporal_rules\[0\]: missing required key\(s\): lookback_lower_bound",
        ):
            self.engine._parse_temporal_rules(rules["temporal_rules"])

        rules = deepcopy(BASE_RULES)
        rules["temporal_rules"][0]["lookback_lower_bound"] = "closed"
        with self.assertRaisesRegex(
            ValueError,
            r"temporal_rules\[0\]\.lookback_lower_bound: expected one of exclusive, inclusive",
        ):
            self.engine._parse_temporal_rules(rules["temporal_rules"])

        start = pd.Timestamp("2024-06-16T09:00:00Z")
        frame = pd.DataFrame(
            {"actor_principal": ["alice", "alice"]},
            index=pd.DatetimeIndex([start, start + pd.Timedelta(hours=6)]),
        )
        inclusive_signals = {
            0: {"transfer_execution": 1.0},
            1: {"boundary_crossing": 1.0},
        }
        self.engine._apply_temporal_rules_sparse(
            frame, inclusive_signals, {0: [], 1: []}
        )
        self.assertEqual(
            inclusive_signals[1]["cross_border_transfer"], 1.0
        )

        rules = deepcopy(BASE_RULES)
        rules["temporal_rules"][10]["lookback_lower_bound"] = "exclusive"
        rules["temporal_rules"][0]["lookback_lower_bound"] = "exclusive"
        rules["temporal_rules"][14]["lookback_lower_bound"] = "exclusive"
        exclusive_engine = self._engine(rules)
        exclusive_signals = {
            0: {"transfer_execution": 1.0},
            1: {"boundary_crossing": 1.0},
        }
        exclusive_engine._apply_temporal_rules_sparse(
            frame, exclusive_signals, {0: [], 1: []}
        )
        self.assertNotIn("cross_border_transfer", exclusive_signals[1])

        sequence_frame = pd.DataFrame(
            {"actor_principal": ["alice"] * 4},
            index=pd.DatetimeIndex(
                [
                    start,
                    start + pd.Timedelta(minutes=1),
                    start + pd.Timedelta(minutes=2),
                    start + pd.Timedelta(hours=6),
                ]
            ),
        )
        sequence_input = {
            0: {"auth_remote_failure": 1.0},
            1: {"auth_remote_failure": 1.0},
            2: {"auth_remote_failure": 1.0},
            3: {"auth_remote_success": 1.0},
        }
        inclusive_sequence = deepcopy(sequence_input)
        self.engine._apply_temporal_rules_sparse(
            sequence_frame,
            inclusive_sequence,
            {row_i: [] for row_i in range(4)},
        )
        self.assertEqual(
            inclusive_sequence[3]["fail_then_success_user"], 1.0
        )
        exclusive_sequence = deepcopy(sequence_input)
        exclusive_engine._apply_temporal_rules_sparse(
            sequence_frame,
            exclusive_sequence,
            {row_i: [] for row_i in range(4)},
        )
        self.assertNotIn("fail_then_success_user", exclusive_sequence[3])

        condition_frame = pd.DataFrame(
            {
                "src_ip": ["203.0.113.10", "203.0.113.10"],
                "actor_principal": ["alice", "bob"],
            },
            index=pd.DatetimeIndex([start, start + pd.Timedelta(hours=6)]),
        )
        inclusive_condition = {}
        self.engine._apply_temporal_rules_sparse(
            condition_frame, inclusive_condition, {}
        )
        self.assertEqual(
            inclusive_condition[1]["auth_pivot_accounts_from_same_src"], 1.0
        )
        exclusive_condition = {}
        exclusive_engine._apply_temporal_rules_sparse(
            condition_frame, exclusive_condition, {}
        )
        self.assertNotIn(1, exclusive_condition)

    def test_generic_condition_state_policy_is_strict_and_authoritative(self):
        condition_index = 14
        required_keys = (
            "empty_value_behavior",
            "first_observation_behavior",
            "reference_selection",
        )
        for key in required_keys:
            with self.subTest(missing=key):
                rules = deepcopy(BASE_RULES)
                del rules["temporal_rules"][condition_index]["condition"][key]
                with self.assertRaisesRegex(
                    ValueError,
                    rf"temporal_rules\[{condition_index}\]\.condition: missing required key\(s\): {key}",
                ):
                    self.engine._parse_temporal_rules(rules["temporal_rules"])

        invalid_cases = (
            ("empty_value_behavior", "skip", "ignore, observe"),
            ("first_observation_behavior", "ignore", "emit, suppress"),
            (
                "reference_selection",
                "rolling_window",
                "previous_observation, window_start",
            ),
        )
        for key, value, expected in invalid_cases:
            with self.subTest(invalid=key):
                rules = deepcopy(BASE_RULES)
                rules["temporal_rules"][condition_index]["condition"][key] = value
                with self.assertRaisesRegex(
                    ValueError,
                    rf"temporal_rules\[{condition_index}\]\.condition\.{key}: expected one of {expected}",
                ):
                    self.engine._parse_temporal_rules(rules["temporal_rules"])

        start = pd.Timestamp("2024-06-16T10:00:00Z")

        def apply_condition(engine, values):
            frame = pd.DataFrame(
                {
                    "src_ip": ["203.0.113.10"] * len(values),
                    "actor_principal": values,
                },
                index=pd.date_range(start, periods=len(values), freq="min"),
            )
            signal_map = {}
            engine._apply_temporal_rules_sparse(frame, signal_map, {})
            return signal_map

        ignored_empty = apply_condition(self.engine, ["alice", "", "bob"])
        self.assertNotIn(1, ignored_empty)
        self.assertEqual(
            ignored_empty[2]["auth_pivot_accounts_from_same_src"], 1.0
        )

        rules = deepcopy(BASE_RULES)
        condition = rules["temporal_rules"][condition_index]["condition"]
        condition["empty_value_behavior"] = "observe"
        observed_empty = apply_condition(
            self._engine(rules), ["alice", "", "bob"]
        )
        self.assertEqual(
            observed_empty[1]["auth_pivot_accounts_from_same_src"], 1.0
        )
        self.assertEqual(
            observed_empty[2]["auth_pivot_accounts_from_same_src"], 1.0
        )

        rules = deepcopy(BASE_RULES)
        condition = rules["temporal_rules"][condition_index]["condition"]
        condition["first_observation_behavior"] = "emit"
        first_emitted = apply_condition(self._engine(rules), ["alice"])
        self.assertEqual(
            first_emitted[0]["auth_pivot_accounts_from_same_src"], 1.0
        )

        rules = deepcopy(BASE_RULES)
        condition = rules["temporal_rules"][condition_index]["condition"]
        condition["reference_selection"] = "window_start"
        window_start = apply_condition(
            self._engine(rules), ["alice", "bob", "alice"]
        )
        self.assertEqual(
            window_start[1]["auth_pivot_accounts_from_same_src"], 1.0
        )
        self.assertNotIn(2, window_start)

        rules = deepcopy(BASE_RULES)
        condition = rules["temporal_rules"][condition_index]["condition"]
        condition["kind"] = "first_seen_value"
        condition["first_observation_behavior"] = "emit"
        condition["reference_selection"] = "rolling_window"
        rolling = apply_condition(
            self._engine(rules), ["alice", "bob", "alice"]
        )
        self.assertIn(0, rolling)
        self.assertIn(1, rolling)
        self.assertNotIn(2, rolling)

        condition["reference_selection"] = "previous_observation"
        previous = apply_condition(
            self._engine(rules), ["alice", "bob", "alice"]
        )
        self.assertIn(0, previous)
        self.assertIn(1, previous)
        self.assertIn(2, previous)

    def test_generic_temporal_signal_minimum_is_required_and_authoritative(self):
        rules = deepcopy(BASE_RULES)
        del rules["temporal_rules"][0]["minimum_signal_value_exclusive"]
        with self.assertRaisesRegex(
            ValueError,
            r"temporal_rules\[0\]: missing required key\(s\): minimum_signal_value_exclusive",
        ):
            self.engine._parse_temporal_rules(rules["temporal_rules"])

        rules = deepcopy(BASE_RULES)
        rules["temporal_rules"][0]["minimum_signal_value_exclusive"] = -0.1
        with self.assertRaisesRegex(ValueError, r"expected a non-negative"):
            self.engine._parse_temporal_rules(rules["temporal_rules"])

        rules = deepcopy(BASE_RULES)
        cross_border = next(
            rule
            for rule in rules["temporal_rules"]
            if rule["id"] == "CROSS_BORDER_TRANSFER"
        )
        cross_border["minimum_signal_value_exclusive"] = 1
        engine = self._engine(rules)
        start = pd.Timestamp("2024-06-16T09:00:00Z")
        frame = pd.DataFrame(
            {"actor_principal": ["alice", "alice"]},
            index=pd.date_range(start, periods=2, freq="min"),
        )

        below = {
            0: {"transfer_execution": 1.0},
            1: {"boundary_crossing": 2.0},
        }
        engine._apply_temporal_rules_sparse(frame, below, {0: [], 1: []})
        self.assertNotIn("cross_border_transfer", below[1])

        above = {
            0: {"transfer_execution": 2.0},
            1: {"boundary_crossing": 2.0},
        }
        engine._apply_temporal_rules_sparse(frame, above, {0: [], 1: []})
        self.assertEqual(above[1]["cross_border_transfer"], 1.0)

    def test_ransomware_prior_support_window_is_closed(self):
        start = pd.Timestamp("2024-06-16T10:00:00Z")
        window = pd.Timedelta(self.engine.detector_policy.ransomware_impact.lookback)

        signal_map, explain_map = self._apply(
            [start, start + window],
            [{"hostname": "victim1"}, {"hostname": "victim1"}],
            {
                0: {"defender_disabled": 1.0},
                1: {"mass_file_modification": 1.0},
            },
        )

        self.assertEqual(signal_map[1]["ransomware_impact"], 1.0)
        explanation = self._explain(explain_map, 1, "RANSOMWARE_IMPACT")
        self.assertEqual(explanation["evidence_type"], "contextual")
        self.assertEqual(
            set(explanation["evidence"]),
            {
                "hostname",
                "source_signals",
                "support_timestamp",
                "ransom_note_timestamp",
            },
        )
        self.assertEqual(explanation["evidence"]["hostname"], "victim1")
        self.assertEqual(
            explanation["evidence"]["source_signals"],
            "mass_file_modification",
        )
        self.assertEqual(
            explanation["evidence"]["support_timestamp"],
            start.isoformat(),
        )
        self.assertEqual(explanation["evidence"]["ransom_note_timestamp"], "")

        outside_signals, _ = self._apply(
            [start, start + window + pd.Timedelta(microseconds=1)],
            [{"hostname": "victim1"}, {"hostname": "victim1"}],
            {
                0: {"defender_disabled": 1.0},
                1: {"mass_file_modification": 1.0},
            },
        )
        self.assertNotIn("ransomware_impact", outside_signals[1])

    def test_ransomware_future_note_boundary_and_prior_support_precedence(self):
        start = pd.Timestamp("2024-06-16T12:00:00Z")
        window = pd.Timedelta(self.engine.detector_policy.ransomware_impact.lookback)

        note_signals, note_explain = self._apply(
            [start, start + window],
            [
                {"hostname": "victim1", "filename": "/tmp/encrypted.bin"},
                {"hostname": "victim1", "filename": "/tmp/README_DECRYPT.txt"},
            ],
            {0: {"ransomware_extension_burst": 1.0}},
        )
        self.assertEqual(note_signals[0]["ransomware_impact"], 1.0)
        note_item = self._explain(note_explain, 0, "RANSOMWARE_IMPACT")
        self.assertEqual(note_item["evidence"]["support_timestamp"], "")
        self.assertEqual(
            note_item["evidence"]["ransom_note_timestamp"],
            (start + window).isoformat(),
        )

        outside_signals, _ = self._apply(
            [start, start + window + pd.Timedelta(microseconds=1)],
            [
                {"hostname": "victim1", "filename": "/tmp/encrypted.bin"},
                {"hostname": "victim1", "filename": "/tmp/README_DECRYPT.txt"},
            ],
            {0: {"ransomware_extension_burst": 1.0}},
        )
        self.assertNotIn("ransomware_impact", outside_signals[0])

        support_ts = start - pd.Timedelta(minutes=5)
        precedence_signals, precedence_explain = self._apply(
            [support_ts, start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1"},
                {"hostname": "victim1", "filename": "/tmp/encrypted.bin"},
                {"hostname": "victim1", "filename": "/tmp/README_DECRYPT.txt"},
            ],
            {
                0: {"inhibit_system_recovery": 1.0},
                1: {"mass_file_modification": 1.0},
            },
        )
        self.assertEqual(precedence_signals[1]["ransomware_impact"], 1.0)
        precedence_item = self._explain(
            precedence_explain, 1, "RANSOMWARE_IMPACT"
        )
        self.assertEqual(
            precedence_item["evidence"]["support_timestamp"],
            support_ts.isoformat(),
        )
        self.assertEqual(
            precedence_item["evidence"]["ransom_note_timestamp"],
            "",
        )

    def test_automated_exfiltration_counts_rows_once_and_requires_support(self):
        timestamps = pd.date_range(
            "2024-06-16T14:00:00Z", periods=2, freq="min"
        )
        rows = [{"hostname": "victim1"}, {"hostname": "victim1"}]

        no_support, _ = self._apply(
            timestamps,
            rows,
            {
                0: {"data_transfer_tool_exec": 1.0},
                1: {"transfer_execution": 1.0},
            },
        )
        self.assertNotIn("automated_exfiltration", no_support[0])
        self.assertNotIn("automated_exfiltration", no_support[1])

        all_counted_on_one_row = {
            "transfer_execution": 1.0,
            "data_transfer_tool_exec": 1.0,
            "staging_then_transfer": 1.0,
            "large_http_transfer": 1.0,
            "sensitive_file_access": 1.0,
        }
        with_support, explain_map = self._apply(
            timestamps,
            rows,
            {
                0: all_counted_on_one_row,
                1: {"transfer_execution": 1.0},
            },
        )
        self.assertNotIn("automated_exfiltration", with_support[0])
        self.assertEqual(with_support[1]["automated_exfiltration"], 1.0)
        item = self._explain(explain_map, 1, "AUTOMATED_EXFILTRATION")
        self.assertEqual(item["evidence"]["count_in_window"], 2)
        self.assertEqual(item["evidence"]["window_seconds"], 30 * 60)

    def test_automated_exfiltration_emit_roles_exclude_unrelated_rows(self):
        start = pd.Timestamp("2024-06-16T15:00:00Z")
        timestamps = pd.date_range(start, periods=4, freq="min")
        rows = [{"hostname": "victim1"}] * 4
        signal_map, _ = self._apply(
            timestamps,
            rows,
            {
                0: {
                    "sensitive_file_access": 1.0,
                    "transfer_execution": 1.0,
                },
                1: {"transfer_execution": 1.0},
                2: {"service_stop": 1.0},
                3: {"suspicious_execution": 1.0},
            },
        )

        self.assertEqual(signal_map[1]["automated_exfiltration"], 1.0)
        self.assertNotIn("automated_exfiltration", signal_map[2])
        self.assertEqual(signal_map[3]["automated_exfiltration"], 1.0)

    def test_counted_window_emit_roles_are_yaml_authoritative_and_strict(self):
        rules = deepcopy(BASE_RULES)
        config = rules["detector_policy"]["detectors"]["automated_exfiltration"]
        config["count"]["any_signals"] = ["usb_device_connected"]
        config["support"]["window_any_signals"] = ["service_stop"]
        config["support"]["current_any_signals"] = ["account_access_removal"]
        config["emit_on"] = ["window_support"]
        engine = self._engine(rules)
        start = pd.Timestamp("2024-06-16T16:00:00Z")
        frame = pd.DataFrame(
            {"hostname": ["victim1", "victim1", "victim1"]},
            index=pd.date_range(start, periods=3, freq="min"),
        )
        signal_map = {
            0: {"usb_device_connected": 1.0},
            1: {"usb_device_connected": 1.0},
            2: {"service_stop": 1.0},
        }
        explain_map = {0: [], 1: [], 2: []}
        engine._apply_counted_signal_window_policies_sparse(
            frame,
            signal_map,
            explain_map,
        )
        self.assertNotIn("automated_exfiltration", signal_map[1])
        self.assertEqual(signal_map[2]["automated_exfiltration"], 1.0)

        parser = MODULE._parse_counted_signal_window_policy
        path = "detector_policy.detectors.automated_exfiltration"
        invalid_cases = (
            ("legacy scalar", "qualifying_row", r"emit_on: expected a non-empty list"),
            (
                "unknown role",
                ["arbitrary_row"],
                r"emit_on\[0\]: expected one of counted, current_support, window_support",
            ),
            (
                "duplicate role",
                ["counted", "counted"],
                r"emit_on\[1\]: duplicate value 'counted'",
            ),
        )
        for label, emit_on, error in invalid_cases:
            with self.subTest(label=label):
                raw = deepcopy(
                    BASE_RULES["detector_policy"]["detectors"][
                        "automated_exfiltration"
                    ]
                )
                raw["emit_on"] = emit_on
                with self.assertRaisesRegex(ValueError, error):
                    parser(raw, path)

    def test_counted_window_signal_minimum_is_required_and_authoritative(self):
        parser = MODULE._parse_counted_signal_window_policy
        path = "detector_policy.detectors.automated_exfiltration"
        raw = deepcopy(
            BASE_RULES["detector_policy"]["detectors"]["automated_exfiltration"]
        )
        del raw["minimum_signal_value_exclusive"]
        with self.assertRaisesRegex(
            ValueError, r"missing required key\(s\): minimum_signal_value_exclusive"
        ):
            parser(raw, path)

        rules = deepcopy(BASE_RULES)
        config = rules["detector_policy"]["detectors"]["automated_exfiltration"]
        config["minimum_signal_value_exclusive"] = 1
        engine = self._engine(rules)
        frame = pd.DataFrame(
            {"hostname": ["victim1"] * 3},
            index=pd.date_range("2024-06-16T17:00:00Z", periods=3, freq="min"),
        )
        signal_map = {
            0: {"transfer_execution": 1.0, "sensitive_file_access": 2.0},
            1: {"transfer_execution": 2.0},
            2: {"transfer_execution": 2.0},
        }
        engine._apply_counted_signal_window_policies_sparse(
            frame,
            signal_map,
            {0: [], 1: [], 2: []},
        )
        self.assertNotIn("automated_exfiltration", signal_map[1])
        self.assertEqual(signal_map[2]["automated_exfiltration"], 1.0)

    def test_credential_labelled_and_unlabelled_follow_on_ordering(self):
        start = pd.Timestamp("2024-06-16T16:00:00Z")

        labelled, labelled_explain = self._apply(
            [start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1", "filename": "/tmp/lsass.dmp"},
                {"hostname": "victim1", "filename": "/tmp/lsass.dmp"},
            ],
            {
                0: {"credential_dumping": 1.0},
                1: {"archive_created": 1.0},
            },
        )
        self.assertEqual(labelled[0]["credential_dump_collection"], 1.0)
        item = self._explain(
            labelled_explain, 0, "CREDENTIAL_DUMP_COLLECTION"
        )
        self.assertEqual(item["evidence"]["source_timestamp"], start.isoformat())

        before_source, _ = self._apply(
            [start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1", "filename": "/tmp/lsass.dmp"},
                {"hostname": "victim1", "filename": "/tmp/lsass.dmp"},
            ],
            {
                0: {"archive_created": 1.0},
                1: {"credential_dumping": 1.0},
            },
        )
        self.assertNotIn("credential_dump_collection", before_source[1])

        unrelated, _ = self._apply(
            [start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1", "filename": "/tmp/lsass.dmp"},
                {"hostname": "victim1", "filename": "/tmp/archive.zip"},
            ],
            {
                0: {"credential_dumping": 1.0},
                1: {"archive_created": 1.0},
            },
        )
        self.assertNotIn("credential_dump_collection", unrelated[0])

        unlabelled, _ = self._apply(
            [start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1", "filename": "/tmp/tool.exe"},
                {"hostname": "victim1", "filename": "/tmp/archive.zip"},
            ],
            {
                0: {"av_offensive_tool": 1.0},
                1: {"archive_created": 1.0},
            },
        )
        self.assertEqual(unlabelled[0]["credential_dump_collection"], 1.0)

    def test_password_store_rejects_unrelated_label_and_accepts_copy_stage(self):
        start = pd.Timestamp("2024-06-16T18:00:00Z")
        login_data = (
            "C:/Users/alice/AppData/Local/Google/Chrome/"
            "User Data/Default/Login Data"
        )

        unrelated, _ = self._apply(
            [start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1", "filename": login_data},
                {"hostname": "victim1", "filename": "/tmp/archive1.tar.gz"},
            ],
            {
                0: {"password_store_access": 1.0},
                1: {"transfer_execution": 1.0},
            },
        )
        self.assertNotIn("password_store_exfil_chain", unrelated[0])

        copy_command = (
            'copy "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\'
            'User Data\\Default\\Login Data" C:\\Temp\\login-data.db'
        )
        copied, copied_explain = self._apply(
            [start, start + pd.Timedelta(minutes=5)],
            [
                {"hostname": "victim1", "filename": login_data},
                {
                    "hostname": "victim1",
                    "command_line": copy_command,
                    "message": copy_command,
                },
            ],
            {0: {"password_store_access": 1.0}},
        )
        self.assertEqual(copied[0]["password_store_exfil_chain"], 1.0)
        item = self._explain(
            copied_explain, 0, "PASSWORD_STORE_EXFIL_CHAIN"
        )
        self.assertEqual(item["evidence"]["source_timestamp"], start.isoformat())
        self.assertEqual(item["evidence"]["window_seconds"], 60 * 60)


if __name__ == "__main__":
    unittest.main()
