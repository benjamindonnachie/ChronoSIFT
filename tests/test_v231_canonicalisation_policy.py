"""Focused tests for the mandatory canonicalisation and normalisation policy."""

import copy
import pathlib
import unittest
from unittest import mock

import pandas as pd
import yaml

import chronoSIFT_v2_31 as module


ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = ROOT / "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"


def _documents():
    with RULES_PATH.open("r", encoding="utf-8") as handle:
        rules = yaml.safe_load(handle)
    with WEIGHTS_PATH.open("r", encoding="utf-8") as handle:
        weights = yaml.safe_load(handle)
    return rules, weights


class CanonicalisationPolicyTest(unittest.TestCase):
    def _engine(self, mutate=None):
        rules, weights = _documents()
        if mutate is not None:
            mutate(rules)
        return module.ChronoSiftEngine(copy.deepcopy(rules), copy.deepcopy(weights))

    def test_windows_event_classification_comes_from_config(self):
        def mutate(rules):
            outcomes = rules["canonicalisation"]["windows_authentication"]["classifications"]["outcomes"]
            outcomes[0] = {"event_ids": ["9001"], "value": "configured-success"}

        engine = self._engine(mutate)
        frame = pd.DataFrame([{
            "parser": "winevtx",
            "xml_string": (
                "<Event><System><EventID>9001</EventID></System><EventData>"
                "<Data Name='LogonType'>10</Data>"
                "<Data Name='IpAddress'>192.0.2.10</Data>"
                "</EventData></Event>"
            ),
        }])
        out = engine._extract_windows_auth_fields(frame)
        self.assertEqual(out.loc[0, "auth_outcome"], "configured-success")
        self.assertEqual(out.loc[0, "auth_protocol"], "rdp")

    def test_windows_protocol_truth_table_and_precedence_come_from_config(self):
        def mutate(rules):
            classifications = rules["canonicalisation"]["windows_authentication"][
                "classifications"
            ]
            classifications["protocol_branch_mode"] = "last_match"
            classifications["remote_direction_condition"] = "classified_protocol"
            classifications["protocols"] = [
                {
                    "event_ids": ["9001"],
                    "logon_types": ["10"],
                    "match": "any",
                    "require_client_address": False,
                    "value": "configured-any",
                },
                {
                    "event_ids": ["9001"],
                    "logon_types": ["10"],
                    "match": "all",
                    "require_client_address": False,
                    "value": "configured-all",
                },
            ]

        engine = self._engine(mutate)

        def extract(event_id, logon_type):
            return engine._extract_windows_auth_fields(pd.DataFrame([{
                "parser": "winevtx",
                "xml_string": (
                    f"<Event><System><EventID>{event_id}</EventID></System>"
                    "<EventData>"
                    f"<Data Name='LogonType'>{logon_type}</Data>"
                    "<Data Name='IpAddress'>192.0.2.10</Data>"
                    "</EventData></Event>"
                ),
            }])).iloc[0]

        both = extract("9001", "10")
        self.assertEqual(both["auth_protocol"], "configured-all")
        self.assertEqual(both["auth_direction"], "remote")

        event_only = extract("9001", "11")
        self.assertEqual(event_only["auth_protocol"], "configured-any")

        unclassified = extract("9002", "11")
        self.assertTrue(pd.isna(unclassified["auth_protocol"]))
        self.assertTrue(pd.isna(unclassified["auth_direction"]))

    def test_authentication_output_merge_is_yaml_authoritative(self):
        windows_frame = pd.DataFrame([{
            "parser": "winevtx",
            "xml_string": (
                "<Event><System><EventID>4624</EventID></System><EventData>"
                "<Data Name='LogonType'>10</Data>"
                "<Data Name='IpAddress'>192.0.2.10</Data>"
                "</EventData></Event>"
            ),
            "auth_outcome": "curated-outcome",
            "auth_protocol": "curated-protocol",
        }])
        ssh_frame = pd.DataFrame([{
            "parser": "syslog",
            "message": (
                "sshd[42]: Accepted publickey for alice from 192.0.2.20"
            ),
            "auth_outcome": "curated-outcome",
            "auth_protocol": "curated-protocol",
        }])

        preserving = self._engine()
        windows_preserved = preserving._extract_windows_auth_fields(
            windows_frame.copy()
        )
        ssh_preserved = preserving._extract_ssh_auth_fields(ssh_frame.copy())
        self.assertEqual(
            windows_preserved.loc[0, "auth_outcome"], "curated-outcome"
        )
        self.assertEqual(
            windows_preserved.loc[0, "auth_protocol"], "curated-protocol"
        )
        self.assertEqual(ssh_preserved.loc[0, "auth_outcome"], "curated-outcome")
        self.assertEqual(ssh_preserved.loc[0, "auth_protocol"], "curated-protocol")

        def prefer_extracted(rules):
            canonical = rules["canonicalisation"]
            canonical["windows_authentication"]["output_merge"] = (
                "prefer_extracted"
            )
            canonical["ssh_authentication"]["output_merge"] = (
                "prefer_extracted"
            )

        replacing = self._engine(prefer_extracted)
        windows_replaced = replacing._extract_windows_auth_fields(
            windows_frame.copy()
        )
        ssh_replaced = replacing._extract_ssh_auth_fields(ssh_frame.copy())
        self.assertEqual(windows_replaced.loc[0, "auth_outcome"], "success")
        self.assertEqual(windows_replaced.loc[0, "auth_protocol"], "rdp")
        self.assertEqual(ssh_replaced.loc[0, "auth_outcome"], "success")
        self.assertEqual(ssh_replaced.loc[0, "auth_protocol"], "ssh")

    def test_ssh_pattern_and_semantic_values_come_from_config(self):
        def mutate(rules):
            ssh = rules["canonicalisation"]["ssh_authentication"]
            ssh["patterns"][0]["regex"] = (
                r"(?i)\bgranted\s+([a-z0-9_-]+)\s+for\s+"
                r"([A-Za-z0-9._$@-]+)\s+from\s+([0-9A-Fa-f:.]+)"
            )
            ssh["values"]["protocol"] = "configured-ssh"

        engine = self._engine(mutate)
        frame = pd.DataFrame([{
            "parser": "syslog",
            "message": "sshd[42]: Granted publickey for alice from 192.0.2.20",
        }])
        out = engine._extract_ssh_auth_fields(frame)
        self.assertEqual(out.loc[0, "ssh_actor_user_auth"], "alice")
        self.assertEqual(out.loc[0, "auth_protocol"], "configured-ssh")

    def test_generic_pam_session_is_not_promoted_to_ssh(self):
        engine = self._engine()
        frame = pd.DataFrame([{
            "parser": "syslog",
            "message": (
                "sudo: pam_unix(sudo:session): session opened for user root "
                "by alice"
            ),
        }])
        out = engine._extract_ssh_auth_fields(frame)
        self.assertTrue(pd.isna(out.loc[0, "auth_outcome"]))
        self.assertTrue(pd.isna(out.loc[0, "auth_protocol"]))

        sshd = frame.copy()
        sshd.loc[0, "message"] = "sshd[42]: session opened for user root"
        sshd_out = engine._extract_ssh_auth_fields(sshd)
        self.assertEqual(sshd_out.loc[0, "auth_outcome"], "success")
        self.assertEqual(sshd_out.loc[0, "auth_protocol"], "ssh")

    def test_ssh_optional_capture_and_placeholder_fill_are_safe(self):
        def mutate(rules):
            accepted = rules["canonicalisation"]["ssh_authentication"]["patterns"][0]
            accepted["regex"] = (
                r"(?i)\baccepted(?:\s+([a-z0-9_-]+))?\s+for\s+"
                r"([A-Za-z0-9._$@-]+)\s+from\s+([0-9A-Fa-f:.]+)"
            )

        engine = self._engine(mutate)
        frame = pd.DataFrame([{
            "parser": "syslog",
            "message": "sshd[42]: Accepted for alice from 192.0.2.21",
            "src_ip": "-",
            "auth_protocol": "-",
        }])
        out = engine._extract_ssh_auth_fields(frame)
        self.assertEqual(out.loc[0, "src_ip"], "192.0.2.21")
        self.assertEqual(out.loc[0, "auth_protocol"], "ssh")
        self.assertTrue(pd.isna(out.loc[0, "ssh_auth_method"]))

    def test_pivot_precedence_and_prefix_come_from_config(self):
        def mutate(rules):
            pivot = rules["canonicalisation"]["pivot_destination"]
            pivot["precedence"] = [
                {"role": "hostname", "prefix": "configured-host:"},
                {"role": "ip", "prefix": "configured-ip:"},
                {"role": "fqdn", "prefix": "configured-fqdn:"},
            ]

        engine = self._engine(mutate)
        frame = pd.DataFrame([{
            "auth_protocol": "ssh",
            "destination_ip": "192.0.2.30",
            "destination_hostname": "Server-A",
        }])
        out = engine._derive_pivot_destination_fields(frame)
        self.assertEqual(out.loc[0, "pivot_dest_key"], "configured-host:server-a")

    def test_ip_recovery_fields_come_from_config(self):
        def mutate(rules):
            sources = rules["canonicalisation"]["ip_recovery"]["sources"]
            direct_text = next(
                source
                for source in sources
                if source["kind"] == "text_fields" and not source["require_context"]
            )
            direct_text["fields"] = ["configured_network_text"]

        engine = self._engine(mutate)
        frame = pd.DataFrame([{
            "parser": "custom",
            "configured_network_text": "sftp://192.0.2.40/archive",
        }])
        out = engine._recover_ip_address(frame)
        self.assertEqual(out.loc[0, "ip_address"], "192.0.2.40")

    def test_ip_source_subset_and_excluded_networks_come_from_config(self):
        def mutate(rules):
            canonical = rules["canonicalisation"]
            canonical["excluded_networks"] = ["0.0.0.0/32", "::/128"]
            canonical["ip_recovery"]["sources"] = [{
                "kind": "text_fields",
                "fields": ["configured_network_text"],
                "require_context": False,
            }]

        engine = self._engine(mutate)
        out = engine._recover_ip_address(pd.DataFrame([{
            "configured_network_text": "http://127.0.0.1/archive",
        }]))
        self.assertEqual(out.loc[0, "ip_address"], "127.0.0.1")

    def test_configured_ip_output_reaches_projection_and_geoip(self):
        def mutate(rules):
            rules["canonicalisation"]["ip_recovery"]["output_field"] = (
                "configured_ip"
            )

        engine = self._engine(mutate)
        self.assertIn("configured_ip", engine.required_fields)

        geo_frame = pd.DataFrame({
            "configured_ip": ["192.0.2.41"],
            "geo_country": ["Configured Country"],
        })
        with mock.patch.object(
            module,
            "build_geoip_enrichment_table",
            return_value=geo_frame,
        ) as geoip:
            out = engine.apply_atomic(
                pd.DataFrame(
                    [{
                        "parser": "custom",
                        "message": "sftp://192.0.2.41/archive",
                    }],
                    index=pd.DatetimeIndex([
                        pd.Timestamp("2024-06-16T10:00:00Z")
                    ]),
                ),
                geoip_city_db="configured-city.mmdb",
                geoip_asn_db="configured-asn.mmdb",
                apply_profiling=False,
                enforce_required_fields=False,
            )

        self.assertEqual(out.iloc[0]["configured_ip"], "192.0.2.41")
        self.assertEqual(out.iloc[0]["geo_country"], "Configured Country")
        self.assertEqual(geoip.call_args.kwargs["ip_field"], "configured_ip")

    def test_invalid_canonicalisation_regex_fails_at_startup(self):
        rules, weights = _documents()
        rules["canonicalisation"]["ssh_authentication"]["patterns"][0]["regex"] = "("
        with self.assertRaisesRegex(ValueError, "invalid regular expression"):
            module.ChronoSiftEngine(rules, weights)

    def test_invalid_windows_protocol_match_mode_fails_at_startup(self):
        rules, weights = _documents()
        rules["canonicalisation"]["windows_authentication"]["classifications"][
            "protocols"
        ][0]["match"] = "opaque"
        with self.assertRaisesRegex(ValueError, r"protocols\[0\]\.match"):
            module.ChronoSiftEngine(rules, weights)

    def test_authentication_output_merge_schema_is_strict(self):
        for policy_name in ("windows_authentication", "ssh_authentication"):
            with self.subTest(policy=policy_name, case="missing"):
                rules, weights = _documents()
                rules["canonicalisation"][policy_name].pop("output_merge")
                with self.assertRaisesRegex(
                    ValueError, r"missing required key\(s\): output_merge"
                ):
                    module.ChronoSiftEngine(rules, weights)

            with self.subTest(policy=policy_name, case="invalid"):
                rules, weights = _documents()
                rules["canonicalisation"][policy_name]["output_merge"] = (
                    "opaque"
                )
                with self.assertRaisesRegex(
                    ValueError, r"output_merge: expected one of"
                ):
                    module.ChronoSiftEngine(rules, weights)

    def test_unknown_normalisation_method_fails_at_startup(self):
        rules, weights = _documents()
        rules["normalisation"][0]["method"] = "engine_fallback"
        with self.assertRaisesRegex(ValueError, "expected one of"):
            module.ChronoSiftEngine(rules, weights)

    def test_file_extension_normalisation_does_not_hide_a_length_policy(self):
        self.assertEqual(
            module.normalise_file_extension("sample.verylongextension"),
            ".verylongextension",
        )
        engine = self._engine()
        out = engine._apply_normalisation(
            pd.DataFrame([{"filename": "sample.verylongextension"}])
        )
        self.assertEqual(out.loc[0, "file_ext"], ".verylongextension")


if __name__ == "__main__":
    unittest.main()
