"""Versioned candidate policy: honest labels, retained weak evidence, strict inputs."""
from pathlib import Path
import logging
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
import pyarrow.dataset as arrow_dataset
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import chronoSIFT_v2_31 as module
import run_chronosift_sidecar_cli as cli

RULES = ROOT / "rules/rules_evidence_calibrated_v11.yaml"
WEIGHTS = ROOT / "rules/weights_evidence_calibrated_v10.yaml"

# Synthetic rules test policy boundaries; no third-party detection content.
METADATA = """rule TEST_WEBSHELL_Weak
{
  meta:
    score = 70
    quality = 85
  condition:
    false
}
rule TEST_WEBSHELL_Strong
{
  meta:
    score = 75
    quality = 85
  condition:
    false
}
"""


def timeline(rows):
    frame = pd.DataFrame(rows)
    frame.index = pd.date_range("2024-06-05T23:00:00Z", periods=len(rows), freq="s")
    frame["chronosift_row_id"] = range(len(rows))
    return frame


class EvidenceCalibrationTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(logging.getLogger().setLevel, logging.getLogger().level)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.metadata = Path(self.temp.name) / "fixture.yar"
        self.metadata.write_text(METADATA, encoding="utf-8")
        self.engine = module.ChronoSiftEngine.from_yaml(
            RULES, WEIGHTS, yara_metadata_path=str(self.metadata)
        )

    def test_candidate_defaults_and_neutral_taxonomy(self):
        args = cli.build_arg_parser().parse_args(["input", "output"])
        self.assertEqual(Path(args.rules_yaml).name, "rules_evidence_calibrated_v24.yaml")
        self.assertEqual(Path(args.weights_yaml).name, "weights_evidence_calibrated_v21.yaml")
        self.assertIsNone(args.overlap)
        self.assertEqual(self.engine.max_event_score, 50)
        for signal in ("mitre_t1190", "mitre_t1505_003", "mitre_t1105",
                       "mitre_t1213_006", "web_confirmed_webshell_access",
                       "web_external_sensitive_transfer"):
            self.assertEqual(self.engine.weights[signal], 0)
        for obsolete in ("defacement_candidate", "mass_file_modification", "ransomware_impact"):
            self.assertNotIn(obsolete, self.engine.weights)

    def test_cli_candidate_end_to_end_preserves_tied_timestamp_row_ids(self):
        frame = timeline([
            {"parser": "filestat", "filename": "/var/www/html/Uploader.php",
             "timestamp_desc": "Creation Time", "yara_match": '["TEST_WEBSHELL_Strong"]'},
            {"parser": "text/apache_access", "http_request": "GET /Uploader.php HTTP/1.1",
             "http_response_code": 200},
        ])
        frame.index = pd.DatetimeIndex([pd.Timestamp("2024-06-05T23:00:00.000000123Z")] * 2,
                                       name="datetime")
        dataset = Path(self.temp.name)/"cli-input"
        partition = dataset/"year=2024"/"month=6"
        partition.mkdir(parents=True)
        frame.to_parquet(partition/"part.parquet")
        output = Path(self.temp.name)/"cli-output"
        result = subprocess.run(
            [sys.executable, "-B", "-W", "ignore", str(ROOT/"run_chronosift_sidecar_cli.py"),
             str(dataset), str(output), "--yara-metadata-path", str(self.metadata),
             "--log-level", "ERROR"], cwd=self.temp.name, capture_output=True, text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Read keys directly: pandas 3 cannot reconstruct every stored Arrow
        # nested-map dtype from pandas metadata, even though Parquet is valid.
        ids = arrow_dataset.dataset(output, format="parquet", partitioning="hive").to_table(
            columns=["chronosift_row_id"]
        )["chronosift_row_id"].to_pylist()
        self.assertEqual(sorted(ids), [0, 1])
        self.assertEqual(len(ids), len(set(ids)))

    def test_priority_revision_changes_only_download_and_shell_activity_weights(self):
        previous = yaml.safe_load((ROOT / "rules/weights_evidence_calibrated_v9.yaml").read_text())
        current = yaml.safe_load(WEIGHTS.read_text())
        expected = dict(previous["weights"])
        expected.update(web_sensitive_file_download=20, webshell_activity=15)
        self.assertEqual(current, {**previous, "weights": expected})
        score = self.engine._score_signals
        # A shell-related request receives more priority, while an ordinary
        # exploitation hint without temporal support does not gain points.
        self.assertEqual(score({"web_exploitation_hint": 1, "exploit_public_facing_app": 1}), 9)
        self.assertEqual(score({"web_exploitation_hint": 1, "exploit_public_facing_app": 1,
                                "webshell_activity": 1}), 24)
        self.assertEqual(score({"web_sqli_attempt": 1}), 4)
        self.assertEqual(score({"yara_webshell": 1}), 4)

    def test_missing_metadata_fails_before_dataset_processing(self):
        output = Path(self.temp.name) / "must-not-exist"
        args = ["chronosift", "absent-input", str(output), "--rules-yaml", str(RULES),
                "--weights-yaml", str(WEIGHTS), "--yara-metadata-path",
                str(Path(self.temp.name) / "missing.yar")]
        with patch.object(sys, "argv", args), patch.object(
            module.ChronoSiftEngine, "process_parquet_dataset_partitioned"
        ) as process:
            with self.assertRaisesRegex(FileNotFoundError, "metadata file does not exist"):
                cli.main()
            process.assert_not_called()
        self.assertFalse(output.exists())

    def test_quality_gate_not_relaxed_and_unknown_stays_unqualified(self):
        policy = self.engine.detector_policy.yara_classification
        self.assertEqual((policy.referenced_file_gate.minimum_score,
                          policy.referenced_file_gate.minimum_quality), (75, 70))
        index = self.engine.yara_metadata_index
        for name in ("TEST_WEBSHELL_Weak", "TEST_WEBSHELL_Unindexed"):
            self.assertEqual(module._web_relevant_yara_rule_evidence(name, index, policy), [])
        self.assertEqual(len(module._web_relevant_yara_rule_evidence(
            "TEST_WEBSHELL_Strong", index, policy)), 1)

    def test_empty_metadata_fails_before_processing(self):
        self.metadata.write_text("// no rule definitions\n", encoding="utf-8")
        args = ["chronosift", "absent-input", str(Path(self.temp.name) / "output"),
                "--rules-yaml", str(RULES), "--weights-yaml", str(WEIGHTS),
                "--yara-metadata-path", str(self.metadata)]
        with patch.object(sys, "argv", args), patch.object(
            module.ChronoSiftEngine, "process_parquet_dataset_partitioned"
        ) as process:
            with self.assertRaisesRegex(ValueError, "No YARA rule metadata parsed"):
                cli.main()
            process.assert_not_called()

    def test_mass_modification_is_retained_without_ransomware_promotion(self):
        frame = timeline([{"parser": "text/apt_history", "command_line": "apt install php",
                           "message": "apt install php"}] + [
            {"parser": "filestat", "filename": f"/var/www/html/file{i}.php",
             "timestamp_desc": "Metadata Modification Time"} for i in range(26)
        ] + [{"parser": "filestat", "filename": "/var/www/html/README.txt",
              "timestamp_desc": "Last Access Time"}])
        output = self.engine.apply_contextual(self.engine.apply_atomic(frame))
        signals = [s or {} for s in output["chronosift_signals"]]
        self.assertTrue(any(s.get("file_modification_burst") for s in signals))
        self.assertTrue(any(s.get("web_content_modification") for s in signals))
        self.assertFalse(any(s.get("ransomware_activity_candidate") for s in signals))
        self.assertEqual(list(output.chronosift_row_id), list(range(len(frame))))

    def test_note_name_and_generic_execution_cannot_promote_mass_only(self):
        frame = timeline([{"filename": "/usr/share/Restore.wav"},
                          {"filename": "/home/user/file.txt"},
                          {"filename": "/home/user/README"}])
        signals = {0: {"suspicious_execution": 1}, 1: {"file_modification_burst": 1}}
        self.engine._apply_ransomware_impact_policy_sparse(frame, signals, {})
        self.assertNotIn("ransomware_activity_candidate", signals[1])

    def test_ransomware_specific_evidence_with_recovery_inhibition_retained(self):
        frame = timeline([{"filename": "/tmp/command"}, {"filename": "/home/user/a.locked"}])
        for source in ("ransomware_extension_burst", "yara_ransomware", "av_ransomware"):
            with self.subTest(source=source):
                signals = {0: {"inhibit_system_recovery": 1}, 1: {source: 1}}
                explanations = {}
                self.engine._apply_ransomware_impact_policy_sparse(frame, signals, explanations)
                self.assertEqual(signals[1]["ransomware_activity_candidate"], 1)
                self.assertIn("not established", explanations[1][0]["description"])

    def test_ransomware_candidate_note_description_does_not_claim_creation(self):
        frame = timeline([{"filename": "/home/user/a.locked"},
                          {"filename": "/home/user/README", "timestamp_desc": "Access Time"}])
        signals, explanations = {0: {"ransomware_extension_burst": 1}}, {}
        self.engine._apply_ransomware_impact_policy_sparse(frame, signals, explanations)
        self.assertEqual(signals[0]["ransomware_activity_candidate"], 1)
        self.assertIn("content and creation are not established", explanations[0][0]["description"])

    def test_score_order_and_real_defacement_feature_retention(self):
        score = self.engine._score_signals
        setup = score({"yara_webshell": 1, "yara_hit_strength": .2,
                       "web_content_modification": 1, "file_modification_burst": 1})
        shell = score({"yara_webshell": 1, "yara_hit_strength": .7/3,
                       "web_executable_file_created": 1, "webshell_artifact": 1})
        transfer = score({"large_http_transfer": 1, "referenced_file_luhn_hit": .5,
                          "web_sensitive_file_download": 1, "automated_exfiltration": 1})
        self.assertAlmostEqual(setup, 12.6)
        self.assertAlmostEqual(transfer, 29.5)
        self.assertGreater(shell, setup)
        self.assertGreater(transfer, setup)
        self.assertGreater(score({"web_content_modification": 1}), 0)
        self.assertEqual(score({"yara_webshell": 100}), 50)

    def test_strong_identity_web_access_and_successful_sensitive_download(self):
        rows = [
            {"parser": "filestat", "filename": "/var/www/html/Uploader.php",
             "timestamp_desc": "Creation Time", "yara_match": '["TEST_WEBSHELL_Strong"]'},
            {"parser": "filestat", "filename": "/var/www/html/MySQL Web Shell.php",
             "timestamp_desc": "Creation Time", "yara_match": '["TEST_WEBSHELL_Weak"]'},
            {"parser": "filestat", "filename": "/var/www/html/dump.sql",
             "timestamp_desc": "Creation Time", "luhn_hit": True},
        ]
        for path, status in (("/Uploader.php", 200), ("/MySQL%20Web%20Shell.php", 200),
                             ("/dump.sql", 200), ("/dump.sql", 404)):
            rows.append({"parser": "text/apache_access", "http_request": f"GET {path} HTTP/1.1",
                         "http_response_code": status, "http_response_bytes": 15000000,
                         "ip_address": "123.7.220.100", "message": f"GET {path} HTTP/1.1"})
        frame = timeline(rows)
        dataset = Path(self.temp.name) / "dataset"
        partition = dataset / "year=2024" / "month=6"
        partition.mkdir(parents=True)
        frame.to_parquet(partition / "part.parquet")
        manifest = module.build_global_referenced_file_hit_manifest(
            str(dataset), yara_metadata_index=self.engine.yara_metadata_index,
            yara_metadata_path=str(self.metadata),
            clamav_classifier_policy=self.engine.detector_policy.clamav_classification,
            yara_classifier_policy=self.engine.detector_policy.yara_classification,
            referenced_file_policy=self.engine.detector_policy.referenced_file_correlation,
        )
        self.assertIn("/Uploader.php", manifest["web_identity_map"])
        self.assertNotIn("/uploader.php", manifest["web_identity_map"])
        self.assertNotIn("/MySQL Web Shell.php", manifest["web_identity_map"])
        output = self.engine.apply_contextual(self.engine.apply_atomic(frame), file_hit_manifest=manifest)
        signals = [s or {} for s in output.chronosift_signals]
        self.assertEqual(signals[3].get("web_confirmed_webshell_access"), 1)
        self.assertEqual(signals[3].get("web_malicious_file_access"), 1)
        self.assertNotIn("web_confirmed_webshell_access", signals[4])
        self.assertEqual(signals[5].get("web_sensitive_file_download"), 1)
        self.assertNotIn("web_sensitive_file_download", signals[6])


if __name__ == "__main__":
    unittest.main()
