"""Residual strict-authority regressions for reusable policy expressions."""

from copy import deepcopy
import importlib.util
import pathlib
import sys
import tempfile
import unittest

import pandas as pd
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "chronoSIFT_v2_31.py"
RULES_PATH = (
    ROOT
    / "rules"
    / "rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
)
WEIGHTS_PATH = (
    ROOT
    / "rules"
    / "weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"
)

SPEC = importlib.util.spec_from_file_location(
    "chronosift_v231_residual_config_authority", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _load_yaml(path):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


BASE_RULES = _load_yaml(RULES_PATH)
BASE_WEIGHTS = _load_yaml(WEIGHTS_PATH)
BASE_YARA_PATH = str(
    (
        ROOT
        / BASE_RULES["detector_policy"]["detectors"]["yara_classification"][
            "metadata"
        ]["path"]
    ).resolve()
)


class ChronoSiftV231ResidualConfigAuthorityTest(unittest.TestCase):
    @staticmethod
    def _engine(rules):
        return MODULE.ChronoSiftEngine(
            deepcopy(rules),
            deepcopy(BASE_WEIGHTS),
            yara_metadata_path=BASE_YARA_PATH,
        )

    @staticmethod
    def _walk_predicates(predicate):
        yield predicate
        for child in predicate.children:
            yield from ChronoSiftV231ResidualConfigAuthorityTest._walk_predicates(
                child
            )

    def test_from_yaml_rejects_duplicate_mapping_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = pathlib.Path(tmpdir)
            duplicate_rules_path = tmpdir_path / "duplicate-rules.yaml"
            duplicate_rules_path.write_text(
                "profiling: {}\nprofiling: {}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                r"(?s)rules configuration YAML .*duplicate key 'profiling'",
            ):
                MODULE.ChronoSiftEngine.from_yaml(
                    duplicate_rules_path,
                    WEIGHTS_PATH,
                )

            duplicate_weights_path = tmpdir_path / "duplicate-weights.yaml"
            duplicate_weights_path.write_text(
                "max_event_score: 50\nweights:\n  example: 1\n  example: 2\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                r"(?s)weights configuration YAML .*duplicate key 'example'",
            ):
                MODULE.ChronoSiftEngine.from_yaml(
                    RULES_PATH,
                    duplicate_weights_path,
                )

    def test_ordered_row_signal_predicate_threshold_is_strict_and_authoritative(self):
        with self.assertRaisesRegex(
            ValueError, r"missing required key\(s\): minimum_value_exclusive"
        ):
            MODULE._parse_row_predicate(
                {"op": "signal_any_positive", "signals": ["service_stop"]},
                "predicate",
                {},
            )
        with self.assertRaisesRegex(ValueError, r"expected a non-negative"):
            MODULE._parse_row_predicate(
                {
                    "op": "signal_any_positive",
                    "signals": ["service_stop"],
                    "minimum_value_exclusive": -0.1,
                },
                "predicate",
                {},
            )

        rules = deepcopy(BASE_RULES)
        detector = rules["detector_policy"]["detectors"][
            "direct_attack_semantics"
        ]
        signal_node = next(
            rule["when"]
            for rule in detector["ordered_rules"]
            if rule["id"] == "application_protocol_transfer_signal"
        )
        self.assertEqual(signal_node["op"], "signal_any_positive")
        signal_node["minimum_value_exclusive"] = 1
        engine = self._engine(rules)
        policy = engine.detector_policy.definition(
            "direct_attack_semantics"
        ).payload
        predicate = next(
            predicate
            for rule in policy.rules
            for predicate in self._walk_predicates(rule.predicate)
            if predicate.operator == "signal_any_positive"
            and predicate.minimum_value_exclusive == 1
        )
        mask = engine._evaluate_row_policy_predicate(
            predicate,
            {},
            {
                0: {next(iter(predicate.signals)): 1.0},
                1: {next(iter(predicate.signals)): 2.0},
            },
            2,
        )
        self.assertEqual(mask.tolist(), [False, True])

    def test_lifecycle_derived_fact_composition_is_yaml_authoritative(self):
        baseline = self._engine(BASE_RULES)
        rules = deepcopy(BASE_RULES)
        lifecycle = rules["detector_policy"]["detectors"]["file_lifecycle"]
        lifecycle["classification"]["derived_predicates"]["database_dump"] = {
            "all": [
                "database_dump_extension",
                "database_dump_basename",
                "database_dump_message",
            ],
            "any": [],
            "none": [],
        }
        strict = self._engine(rules)
        frame = pd.DataFrame(
            {"filename": ["/tmp/plain.sql"], "timestamp_desc": ["Creation Time"]},
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )

        baseline_signals = {}
        baseline._apply_file_lifecycle_signals_sparse(
            frame.copy(), baseline_signals, {}
        )
        self.assertEqual(
            baseline_signals[0]["database_dump_candidate"], 1.0
        )

        strict_signals = {}
        strict._apply_file_lifecycle_signals_sparse(
            frame.copy(), strict_signals, {}
        )
        self.assertNotIn("database_dump_candidate", strict_signals.get(0, {}))

        missing = deepcopy(BASE_RULES)
        del missing["detector_policy"]["detectors"]["file_lifecycle"][
            "classification"
        ]["derived_predicates"]
        with self.assertRaisesRegex(
            ValueError, r"missing required key\(s\): derived_predicates"
        ):
            self._engine(missing)

        unknown = deepcopy(BASE_RULES)
        unknown["detector_policy"]["detectors"]["file_lifecycle"][
            "classification"
        ]["derived_predicates"]["database_dump"]["any"] = ["hidden_fact"]
        with self.assertRaisesRegex(ValueError, r"unknown base fact"):
            self._engine(unknown)

    def test_artifact_follow_on_qualification_is_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        credential = rules["detector_policy"]["detectors"][
            "credential_dump_collection"
        ]
        credential["follow_on_qualification"] = {
            "any": [
                {"all": ["copy_command", "copy_text_support"]},
            ]
        }
        engine = self._engine(rules)
        frame = pd.DataFrame(
            {
                "filename": ["/tmp/lsass.dmp", "/tmp/lsass.dmp.zip"],
                "message": ["", ""],
                "hostname": ["victim1", "victim1"],
            },
            index=pd.date_range("2024-06-16T11:00:00Z", periods=2, freq="min"),
        )
        signal_map = {
            0: {"credential_dumping": 1.0},
            1: {"archive_created": 1.0},
        }
        engine._apply_artifact_follow_on_policies_sparse(frame, signal_map, {})
        self.assertNotIn("credential_dump_collection", signal_map[0])

        missing = deepcopy(BASE_RULES)
        del missing["detector_policy"]["detectors"][
            "credential_dump_collection"
        ]["follow_on_qualification"]
        with self.assertRaisesRegex(
            ValueError, r"missing required key\(s\): follow_on_qualification"
        ):
            self._engine(missing)

        unknown = deepcopy(BASE_RULES)
        unknown["detector_policy"]["detectors"]["credential_dump_collection"][
            "follow_on_qualification"
        ]["any"][0]["all"] = ["hidden_fact"]
        with self.assertRaisesRegex(ValueError, r"unknown fact"):
            self._engine(unknown)

    def test_detector_merge_is_an_engine_invariant_not_a_config_key(self):
        detectors = BASE_RULES["detector_policy"]["detectors"]
        self.assertTrue(all("merge" not in detector for detector in detectors.values()))

        rules = deepcopy(BASE_RULES)
        rules["detector_policy"]["detectors"]["masquerading"]["merge"] = "max"
        with self.assertRaisesRegex(
            ValueError,
            r"detector_policy\.detectors\.masquerading: unknown key\(s\): merge",
        ):
            self._engine(rules)

    def test_smb_network_logon_inference_preserves_explicit_share_pipe_precedence(self):
        engine = self._engine(BASE_RULES)
        frame = pd.DataFrame(
            [
                {
                    "event_identifier": "5145",
                    "share_name": r"\\server\users",
                    "relative_target_name": r"\PIPE\svcctl",
                    "auth_outcome": "success",
                    "auth_protocol": "windows-network",
                    "logon_type": "3",
                    "authentication_package": "ntlm",
                    "workstation_name": "client1",
                },
                {
                    "auth_outcome": "success",
                    "auth_protocol": "windows-network",
                    "logon_type": "3",
                    "authentication_package": "ntlm",
                    "workstation_name": "client2",
                },
                {
                    "event_identifier": "5145",
                    "share_name": r"\\server\IPC$",
                    "relative_target_name": r"\PIPE\svcctl",
                    "auth_outcome": "success",
                    "auth_protocol": "windows-network",
                    "logon_type": "3",
                    "authentication_package": "ntlm",
                    "workstation_name": "client3",
                },
            ],
            index=pd.date_range("2024-06-16T12:00:00Z", periods=3, freq="min"),
        )
        signal_map = {}
        explain_map = {}
        engine._apply_ordered_row_rules_sparse(
            frame,
            signal_map,
            explain_map,
            None,
            detector_id="direct_attack_semantics",
        )

        self.assertEqual(signal_map[0], {"external_remote_service": 1.0})
        self.assertEqual(signal_map[1]["smb_admin_share"], 1.0)
        self.assertEqual(signal_map[1]["external_remote_service"], 1.0)
        self.assertEqual(signal_map[2]["smb_admin_share"], 1.0)
        self.assertEqual(signal_map[2]["external_remote_service"], 1.0)
        self.assertNotIn(
            "smb_network_logon_inference",
            {item["detector_rule_id"] for item in explain_map[0]},
        )
        self.assertIn(
            "smb_network_logon_inference",
            {item["detector_rule_id"] for item in explain_map[1]},
        )
        self.assertNotIn(
            "smb_network_logon_inference",
            {item["detector_rule_id"] for item in explain_map[2]},
        )

    def test_ordered_rules_retain_every_matching_rule_explanation(self):
        engine = self._engine(BASE_RULES)
        frame = pd.DataFrame(
            [{
                "actor_cmd": "procdump lsass.dmp",
                "filename": "/tmp/lsass.dmp",
                "timestamp_desc": "Creation Time",
            }],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T13:00:00Z")]),
        )
        signal_map = {}
        explain_map = {}
        for _ in range(2):
            engine._apply_ordered_row_rules_sparse(
                frame,
                signal_map,
                explain_map,
                None,
                detector_id="direct_attack_semantics",
            )

        self.assertEqual(signal_map[0]["credential_dumping"], 1.0)
        credential_items = [
            item for item in explain_map[0]
            if "credential_dumping" in item["signals"]
        ]
        self.assertEqual(
            {item["detector_rule_id"] for item in credential_items},
            {"credential_dump_command", "credential_dump_artifact"},
        )
        self.assertEqual(len(credential_items), 2)

    def test_temporal_row_evidence_fields_are_config_authoritative(self):
        rules = deepcopy(BASE_RULES)
        for detector_id in (
            "ransomware_impact",
            "automated_exfiltration",
            "credential_dump_collection",
        ):
            rules["detector_policy"]["detectors"][detector_id]["evidence"][
                "hostname"
            ]["field"] = "asset_name"
        engine = self._engine(rules)
        self.assertIn("asset_name", engine.required_fields)

        ransomware_frame = pd.DataFrame(
            {"asset_name": ["asset-r", "asset-r"]},
            index=pd.date_range("2024-06-16T14:00:00Z", periods=2, freq="min"),
        )
        ransomware_signals = {
            0: {"defender_disabled": 1.0},
            1: {"mass_file_modification": 1.0},
        }
        ransomware_explain = {}
        engine._apply_ransomware_impact_policy_sparse(
            ransomware_frame, ransomware_signals, ransomware_explain
        )
        self.assertEqual(
            ransomware_explain[1][0]["evidence"]["hostname"], "asset-r"
        )

        counted_frame = pd.DataFrame(
            {"asset_name": ["asset-c", "asset-c"]},
            index=pd.date_range("2024-06-16T15:00:00Z", periods=2, freq="min"),
        )
        counted_signals = {
            0: {"transfer_execution": 1.0, "sensitive_file_access": 1.0},
            1: {"transfer_execution": 1.0, "suspicious_execution": 1.0},
        }
        counted_explain = {}
        engine._apply_counted_signal_window_policies_sparse(
            counted_frame, counted_signals, counted_explain
        )
        self.assertEqual(
            counted_explain[1][0]["evidence"]["hostname"], "asset-c"
        )

        follow_frame = pd.DataFrame(
            {
                "asset_name": ["asset-f", "asset-f"],
                "filename": ["/tmp/lsass.dmp", "/tmp/lsass.dmp.zip"],
                "message": ["", ""],
            },
            index=pd.date_range("2024-06-16T16:00:00Z", periods=2, freq="min"),
        )
        follow_signals = {
            0: {"credential_dumping": 1.0},
            1: {"archive_created": 1.0},
        }
        follow_explain = {}
        engine._apply_artifact_follow_on_policies_sparse(
            follow_frame, follow_signals, follow_explain
        )
        self.assertEqual(
            follow_explain[0][0]["evidence"]["hostname"], "asset-f"
        )


if __name__ == "__main__":
    unittest.main()
