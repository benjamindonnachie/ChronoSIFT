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

    def _run_referenced_hit_propagation(self, hit_rows, target_rows):
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
        self.engine._apply_referenced_file_hit_signals_sparse(df, signal_map, explain_map)
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
