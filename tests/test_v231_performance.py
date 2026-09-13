"""Output and operation-count regressions for large-window execution.

Do not assert wall-clock timings in unit tests. Benchmark fixtures are deliberately
small, have duplicate timestamps, and retain the persistent integer row key.
"""
from dataclasses import replace
from copy import deepcopy
import ipaddress
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "chronosift_v231_performance", ROOT / "chronoSIFT_v2_31.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def load_engine(module=MODULE, root=ROOT):
    return module.ChronoSiftEngine.from_yaml(
        str(root / "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"),
        str(root / "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"),
    )


def mapping_fixture(engine, n, attached=True):
    p = engine.detector_policy.referenced_file_correlation
    fields = {
        p.attack_indicators_field: ["command_injection"] * n,
        p.web_feature_fields["categories"]: [""] * n,
        p.source_ip_field: ["192.0.2.5"] * n,
        p.method_field: ["GET"] * n,
        p.endpoint_field: ["/index.php"] * n,
        p.status_field: [200] * n,
        p.upload_outcome_field: [""] * n,
        "chronosift_row_id": np.arange(n, dtype=np.int64) * 3 + 100,
    }
    for col in dict.fromkeys(("chronosift_attack_techniques", p.attack_techniques_field)):
        fields[col] = pd.array(["T0000"] * n, dtype="string")
    frame = pd.DataFrame(fields, index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * n))
    signals = {i: {"fixture_signal": 1.0} for i in range(n)}
    explanations = {i: [{
        "rule_id": "FIXTURE", "signals": ["fixture_signal"],
        "evidence": {"source": "synthetic", "tokens": ["one", "two"]},
    }] for i in range(n)}
    if attached:
        frame.attrs["chronosift_sparse"] = {
            "signal_map": signals, "explain_map": explanations,
        }
    return frame, signals, explanations


def classifier_fixture(engine, n):
    p = engine.detector_policy.web_request_classification.outputs
    fields = {
        p.method_field: ["GET"] * n,
        "chronosift_web_request_target": ["/index.php"] * n,
        p.endpoint_field: ["/index.php"] * n,
        "chronosift_web_host": ["example.test"] * n,
        p.status_field: [200] * n,
        "chronosift_web_response_bytes": [1024 + i % 3 for i in range(n)],
        p.source_ip_field: ["192.0.2.5"] * n,
        "chronosift_web_user_agent": ["fixture"] * n,
        p.attack_indicators_field: [""] * n,
        "chronosift_web_upload_name": [""] * n,
        p.upload_names_field: [""] * n,
        p.upload_outcome_field: [""] * n,
        "chronosift_row_id": np.arange(n, dtype=np.int64) * 3 + 100,
    }
    for col in dict.fromkeys(("chronosift_web_outcome", p.web_outcome_field)):
        fields[col] = pd.array([""] * n, dtype="string")
    return pd.DataFrame(fields, index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * n)), {}, {}


def policy_with_payload(policy, detector_id, payload):
    return replace(policy, detectors=tuple(
        replace(definition, payload=payload)
        if definition.detector_id == detector_id else definition
        for definition in policy.detectors
    ))


def referenced_fixture(engine, n):
    p = engine.detector_policy.referenced_file_correlation
    identity = MODULE._empty_file_identity()
    identity["hit_types"].update(("av", "luhn"))
    identity["av_categories"].add("webshell")
    identity["av_families"].add("fixture_family")
    manifest = {
        "schema_version": MODULE.REFERENCED_FILE_HIT_MANIFEST_SCHEMA_VERSION,
        "clamav_policy_digest": engine.detector_policy.clamav_classification.policy_digest,
        "yara_policy_digest": engine.detector_policy.yara_classification.policy_digest,
        "correlation_policy_digest": p.policy_digest,
        "source_digest": "synthetic-performance-fixture",
        "hit_map": {"/var/www/html/shell.php": {"av", "luhn"}},
        "web_path_map": {"/shell.php": {"av", "luhn"}},
        "web_identity_map": {"/shell.php": identity},
        "web_basename_map": {"shell.php": {"av", "luhn"}},
        "web_basename_identity_map": {"shell.php": identity},
        "hash_hit_map": {"A" * 64: {"av", "luhn"}},
        "hash_identity_map": {"A" * 64: identity},
    }
    fields = {
        p.current_path_field: ["/var/log/apache2/access.log"] * n,
        p.message_field: ["synthetic request"] * n,
        p.parser_field: ["text/apache_access"] * n,
        p.request_field: [
            ("POST /upload HTTP/1.1" if i % 5 == 1 else
             "GET /missing HTTP/1.1" if i % 5 == 3 else "GET /shell.php HTTP/1.1")
            for i in range(n)
        ],
        p.response_code_field: [404 if i % 5 == 2 else 200 for i in range(n)],
        p.response_bytes_field: [24000] * n,
        p.upload_names_field: ["shell.php" if i % 5 == 1 else "" for i in range(n)],
        p.upload_hashes_field: ["A" * 64 if i % 5 == 1 else "" for i in range(n)],
        p.upload_outcome_field: [""] * n,
        "chronosift_row_id": np.arange(n, dtype=np.int64) * 3 + 100,
    }
    for role in ("hit_types", "categories", "rules", "families"):
        for col in dict.fromkeys((f"chronosift_web_file_{role}", p.web_feature_fields[role])):
            fields[col] = pd.array([pd.NA] * n, dtype="string")
    for col in dict.fromkeys(("chronosift_web_outcome", p.web_outcome_field)):
        fields[col] = pd.array(["attempt" if i % 2 else pd.NA for i in range(n)], dtype="string")
    frame = pd.DataFrame(fields, index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * n))
    return frame, {}, {}, manifest


class CopyForbidden:
    def __deepcopy__(self, memo):
        raise AssertionError("Sparse partition metadata must not be deep-copied")


class LargeWindowPerformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_engine()

    def test_identity_snapshots_match_raw_normalisation_and_own_mutable_outputs(self):
        raw = {
            "hit_types": [" yara ", "null", "av"],
            "av_signatures": " test-signature ",
            "av_categories": ["webshell"],
            "av_families": [" fixture "],
            "yara_rules": [" Rule "],
            "yara_rule_metadata": [{"rule": " Rule ", "category": " webshell ", "score": "4", "quality": "3"}],
        }
        expected = MODULE._normalise_file_identity(raw)
        original = deepcopy(raw)
        cache = MODULE._FileIdentityCache(max_entries=2)
        targets = [MODULE._empty_file_identity() for _ in range(3)]
        with patch.object(MODULE, "_normalise_file_identity", wraps=MODULE._normalise_file_identity) as normalise:
            for target in targets:
                cache.merge_into(target, raw)
                self.assertEqual(target, expected)
            self.assertEqual(normalise.call_count, 1)
        snapshot = cache._entries[id(raw)][1]
        self.assertTrue(all(isinstance(values, frozenset) for values in snapshot.sets))
        self.assertIsInstance(snapshot.metadata, tuple)
        targets[0]["hit_types"].add("fixture-new")
        targets[0]["yara_rule_metadata"]["Rule"]["score"] = 999
        self.assertEqual(targets[1], expected)
        self.assertEqual(targets[2], expected)
        self.assertEqual(raw, original)
        combined = MODULE._empty_file_identity()
        MODULE._merge_normalised_file_identity(combined, targets[1])
        combined["yara_rule_metadata"]["Rule"]["score"] = 888
        self.assertEqual(targets[1], expected)

    def test_identity_cache_bounds_and_uncached_inputs_preserve_results(self):
        cache = MODULE._FileIdentityCache(max_entries=2)
        sources = [{"yara_rules": [f"rule{i}"]} for i in range(4)]
        sources += [{"yara_rules": ["x" * 16385]}, {"yara_rules": [str(i) for i in range(257)]}, None, "not-a-dict"]
        for source in sources:
            target = MODULE._empty_file_identity()
            cache.merge_into(target, source)
            self.assertEqual(target, MODULE._normalise_file_identity(source))
        self.assertEqual(len(cache._entries), 2)
        for source in sources[4:6]:
            fresh = MODULE._FileIdentityCache()
            fresh.merge_into(MODULE._empty_file_identity(), source)
            self.assertEqual(len(fresh._entries), 0)

    def test_referenced_identity_reuse_preserves_explanation_ownership(self):
        original = self.engine.detector_policy
        correlation = original.referenced_file_correlation
        correlation = replace(correlation, web_branches=tuple(
            replace(branch, evidence=tuple(dict.fromkeys((*branch.evidence, "yara_rule_metadata"))))
            for branch in correlation.web_branches
        ))
        with patch.object(self.engine, "detector_policy", policy_with_payload(original, "referenced_file_correlation", correlation)):
            frame, signals, explanations, manifest = referenced_fixture(self.engine, 20)
            identity = manifest["web_identity_map"]["/shell.php"]
            identity["yara_rules"].add("Rule")
            identity["yara_rule_metadata"]["Rule"] = {"category": "webshell", "score": 5, "quality": 3}
            before = deepcopy(manifest)
            with patch.object(MODULE, "_normalise_file_identity", wraps=MODULE._normalise_file_identity) as normalise:
                self.engine._apply_referenced_file_hit_signals_sparse(frame, signals, explanations, manifest)
                self.assertEqual(normalise.call_count, 1)
            metadata = [item["evidence"]["yara_rule_metadata"] for items in explanations.values() for item in items
                        if item.get("evidence", {}).get("yara_rule_metadata")]
            self.assertGreater(len(metadata), 2)
            self.assertEqual(len({id(value) for value in metadata}), len(metadata))
            metadata[0]["Rule"]["score"] = 999
            self.assertTrue(all(value["Rule"]["score"] == 5 for value in metadata[1:]))
            self.assertEqual(manifest, before)
            # A later invocation must observe manifest changes, not reuse old snapshots.
            identity["yara_rule_metadata"]["Rule"]["score"] = 6
            next_explanations = {}
            self.engine._apply_referenced_file_hit_signals_sparse(frame, {}, next_explanations, manifest)
            self.assertTrue(all(item["evidence"]["yara_rule_metadata"]["Rule"]["score"] == 6
                                for items in next_explanations.values() for item in items
                                if item.get("evidence", {}).get("yara_rule_metadata")))

    def test_sqli_lookup_is_exact_bounded_and_policy_local(self):
        policy = self.engine.detector_policy.web_request_classification.indicators
        target = "/products?id=1%27%20UNION%20SELECT%20x--"
        expected = MODULE._http_sqli_indicators(target, policy)
        self.assertTrue(expected)
        with patch.object(MODULE, "_http_sqli_indicators", wraps=MODULE._http_sqli_indicators) as detect:
            lookup = MODULE._make_sqli_indicator_lookup(policy)
            self.assertEqual(lookup(target), expected)
            self.assertEqual(lookup(target), expected)
            self.assertEqual(detect.call_count, 1)
            lookup(target + " ")
            self.assertEqual(detect.call_count, 2)  # no lossy target-key folding
            other = MODULE._make_sqli_indicator_lookup(replace(policy, sqli_patterns=()))
            self.assertEqual(other(target), ())
            self.assertEqual(detect.call_count, 3)
            oversized = target + "x" * 4096
            self.assertEqual(lookup(oversized), lookup(oversized))
            self.assertEqual(detect.call_count, 5)
        with patch.object(MODULE, "_http_sqli_indicators", return_value=()) as detect:
            lookup = MODULE._make_sqli_indicator_lookup(policy)
            for i in range(8193):
                lookup(f"/{i}")
            lookup("/0")  # first key must have been evicted
            self.assertEqual(detect.call_count, 8194)

    def test_prepared_mapping_conditions_preserve_all_groups_and_empty_semantics(self):
        for present in range(128):
            for mode in ("all", "any"):
                condition = MODULE.WebMappingConditionPolicy(
                    match=mode,
                    indicators_any=frozenset({"ioc"}) if present & 1 else frozenset(),
                    indicator_prefixes_any=("prefix_",) if present & 2 else (),
                    signals_any=frozenset({"signal"}) if present & 4 else frozenset(),
                    minimum_signal_value_exclusive=0.5 if present & 4 else None,
                    categories_any=frozenset({"webshell"}) if present & 8 else frozenset(),
                    methods_any=frozenset({"GET"}) if present & 16 else frozenset(),
                    upload_outcomes_any=frozenset({"attempt"}) if present & 32 else frozenset(),
                    source_ip_scopes_any=frozenset({"public"}) if present & 64 else frozenset(),
                )
                matches = MODULE._prepare_web_mapping_condition(condition)
                for truth in range(128):
                    indicators = ({"ioc"} if truth & 1 else set()) | ({"prefix_x"} if truth & 2 else set())
                    groups = [bool(truth & (1 << bit)) for bit in range(7) if present & (1 << bit)]
                    expected = all(groups) if mode == "all" else any(groups)
                    actual = matches(indicators, {"webshell"} if truth & 8 else set(),
                                     "GET" if truth & 16 else "POST", "attempt" if truth & 32 else "observed",
                                     "public" if truth & 64 else "", {"signal": 1.0 if truth & 4 else 0.0})
                    self.assertEqual(actual, expected, (present, mode, truth))
        condition = replace(condition, match="all", indicators_any=frozenset({"absent"}))
        with self.assertRaises(ValueError):
            MODULE._prepare_web_mapping_condition(condition)(set(), set(), "POST", "", "", {"signal": "invalid"})

    def test_null_fast_path_matches_previous_scalar_and_container_semantics(self):
        def previous(value):
            if value is None:
                return True
            if isinstance(value, (dict, list)):
                return False
            try:
                if bool(pd.isna(value)):
                    return True
            except Exception:
                pass
            if isinstance(value, str):
                text = value.strip()
                if not text or text.lower() in MODULE.PLACEHOLDER_STRINGS:
                    return True
            return False

        values = [None, pd.NA, pd.NaT, np.nan, 0, 0.0, False, {}, [], (),
                  [None], {"a": None}, np.array([1]), np.array([1, 2]),
                  np.array([np.nan]), b"", b"null", "", " \t", " NA ",
                  "--", "NULL", "none", "0", "unknown", " Straße ",
                  np.str_("n/a"), np.str_("text")]
        for value in values:
            with self.subTest(value=repr(value)):
                self.assertEqual(MODULE._is_null(value), previous(value))
        with patch.object(pd, "isna", side_effect=AssertionError("string dispatched to pandas")):
            self.assertEqual(MODULE._safe_str("normal text"), "normal text")
            self.assertEqual(MODULE._safe_str(" NULL "), "")

    def test_ip_cache_is_bounded_and_preserves_address_semantics(self):
        def expected(value):
            value = MODULE._safe_str(value).strip()
            try:
                ip = ipaddress.ip_address(value)
            except Exception:
                return None
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                return None
            return "private" if ip.is_private else "public" if ip.is_global else None

        values = [None, pd.NA, [], {}, "", "null", " 8.8.8.8 ", "192.0.2.5",
                  "10.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0",
                  "100.64.0.1", "::", "::1", "fe80::1%en0", "2001:4860:4860::8888",
                  "bad", "x" * 10000]
        MODULE._ip_scope_from_text.cache_clear()
        for value in values:
            self.assertEqual(MODULE._ip_scope(value), expected(value))
        with patch.object(MODULE.ipaddress, "ip_address", wraps=ipaddress.ip_address) as parse:
            for _ in range(20):
                self.assertEqual(MODULE._ip_scope(" 8.8.8.8 "), "public")
            self.assertEqual(parse.call_count, 0)
        for i in range(8300):
            MODULE._ip_scope(f"invalid-{i}")
        self.assertEqual(MODULE._ip_scope_from_text.cache_info().currsize, 8192)
        MODULE._ip_scope_from_text.cache_clear()

    def test_referenced_writes_are_batched_with_aliases_and_ordered_outcomes(self):
        original = self.engine.detector_policy
        correlation = original.referenced_file_correlation
        payload = replace(correlation, web_outcome_field="custom_outcome",
                          web_feature_fields={role: f"custom_{role}" for role in correlation.web_feature_fields})
        for storage in ("python", "pyarrow"):
            with self.subTest(storage=storage), pd.option_context("mode.string_storage", storage), patch.object(
                self.engine, "detector_policy", policy_with_payload(original, "referenced_file_correlation", payload)
            ):
                frame, signals, explanations, manifest = referenced_fixture(self.engine, 10)
                before_manifest = deepcopy(manifest)
                # Unknown/custom prior values and unequal aliases must each
                # take the configured merge path, not be copied from canonical.
                frame["custom_outcome"] = pd.array(["fixture_prior"] * 10, dtype="string")
                existing = {col: frame[col].tolist() for col in ("chronosift_web_outcome", "custom_outcome")}
                sparse = {"signal_map": signals, "explain_map": explanations, "guard": CopyForbidden()}
                frame.attrs["chronosift_sparse"] = sparse
                merge_calls = []
                merge_class = type(payload.web_outcome_merge)
                old_merge = merge_class.merge
                def record_merge(policy, prior, new):
                    result = old_merge(policy, prior, new)
                    merge_calls.append((prior, new, result))
                    return result
                with patch.object(pd.DataFrame, "_get_value", side_effect=AssertionError("scalar read")), patch.object(
                    pd.DataFrame, "_set_value", side_effect=AssertionError("scalar write")
                ), patch.object(merge_class, "merge", record_merge):
                    self.engine._apply_referenced_file_hit_signals_sparse(frame, signals, explanations, manifest)
                self.assertIs(frame.attrs.pop("chronosift_sparse"), sparse)
                self.assertEqual(manifest, before_manifest)
                self.assertTrue(merge_calls)
                for role in correlation.web_feature_fields:
                    pd.testing.assert_series_equal(frame[f"custom_{role}"], frame[f"chronosift_web_file_{role}"], check_names=False)
                for col in existing:
                    for row_i in (3, 8):
                        if pd.isna(existing[col][row_i]):
                            self.assertTrue(pd.isna(frame[col].iloc[row_i]))
                        else:
                            self.assertEqual(frame[col].iloc[row_i], existing[col][row_i])
                    self.assertEqual(frame[col].array.dtype.storage, storage)
                self.assertEqual(frame.index.nunique(), 1)
                self.assertTrue(frame["chronosift_row_id"].is_unique)

    def test_benign_classifier_does_not_build_unused_evidence(self):
        frame, signals, explanations = classifier_fixture(self.engine, 12)
        outputs = self.engine.detector_policy.web_request_classification.outputs
        frame[outputs.source_ip_field] = ["unused-actor-evidence"] * 12
        frame["chronosift_web_user_agent"] = ["unused-user-agent-evidence"] * 12
        with patch.object(MODULE, "_safe_str", wraps=MODULE._safe_str) as convert:
            self.engine._apply_web_request_classifier_sparse(frame, signals, explanations)
        converted = [call.args[0] for call in convert.call_args_list if isinstance(call.args[0], str)]
        self.assertNotIn("unused-actor-evidence", converted)
        self.assertNotIn("unused-user-agent-evidence", converted)
        self.assertEqual(signals, {i: {} for i in range(12)})
        self.assertEqual(explanations, {i: [] for i in range(12)})

    def test_detachment_is_reentrant_and_restores_identity_on_error(self):
        frame, signals, explanations = mapping_fixture(self.engine, 3)
        attrs = frame.attrs
        sparse = attrs["chronosift_sparse"]
        provenance = {"dataset": "fixture"}
        attrs["chronosift_metadata"] = provenance
        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            with MODULE._detached_sparse_state(frame):
                self.assertNotIn("chronosift_sparse", frame.attrs)
                with MODULE._detached_sparse_state(frame):
                    frame["new_column"] = [1, 2, 3]
                    signals[0]["added"] = 1.0
                self.assertNotIn("chronosift_sparse", frame.attrs)
                raise RuntimeError("fixture failure")
        self.assertIs(frame.attrs, attrs)
        self.assertIs(frame.attrs["chronosift_sparse"], sparse)
        self.assertIs(frame.attrs["chronosift_metadata"], provenance)
        self.assertEqual(sparse["signal_map"][0]["added"], 1.0)
        self.assertEqual(frame["new_column"].tolist(), [1, 2, 3])
        bare = pd.DataFrame({"value": [1]})
        with MODULE._detached_sparse_state(bare):
            pass
        self.assertEqual(bare.attrs, {})

    def test_mapping_never_copies_sparse_state_or_reads_scalar_iat(self):
        frame, signals, explanations = mapping_fixture(self.engine, 20)
        sparse = frame.attrs["chronosift_sparse"]
        sparse["guard"] = CopyForbidden()
        with patch.object(pd.DataFrame, "_get_value", side_effect=AssertionError("scalar read")):
            self.engine._apply_web_attack_mapping_sparse(frame, signals, explanations)
        self.assertIs(frame.attrs["chronosift_sparse"], sparse)
        frame.attrs.pop("chronosift_sparse")
        self.assertEqual(frame["chronosift_attack_techniques"].tolist(), ["T0000|T1190"] * 20)
        self.assertEqual(frame["chronosift_row_id"].tolist(), list(range(100, 160, 3)))
        self.assertEqual(frame.index.nunique(), 1)
        self.assertTrue(all(sig["mitre_t1190"] == 1 for sig in signals.values()))

    def test_mapping_restores_sparse_state_when_detector_raises(self):
        frame, signals, explanations = mapping_fixture(self.engine, 2)
        sparse = frame.attrs["chronosift_sparse"]
        sparse["guard"] = CopyForbidden()
        with patch.object(MODULE, "_ip_scope", side_effect=RuntimeError("fixture failure")):
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                self.engine._apply_web_attack_mapping_sparse(frame, signals, explanations)
        self.assertIs(frame.attrs["chronosift_sparse"], sparse)

    def test_mapping_aliases_and_unmatched_null_values_are_preserved(self):
        policy = self.engine.detector_policy
        correlation = replace(policy.referenced_file_correlation, attack_techniques_field="custom_techniques")
        with patch.object(self.engine, "detector_policy", policy_with_payload(policy, "referenced_file_correlation", correlation)):
            frame, signals, explanations = mapping_fixture(self.engine, 3)
            frame.attrs.pop("chronosift_sparse")
            frame["custom_techniques"] = pd.array([pd.NA, "T0002", "T0003"], dtype="string")
            frame[correlation.attack_indicators_field] = ["command_injection", "", "command_injection"]
            frame["chronosift_attack_techniques"] = pd.array([pd.NA, pd.NA, "T1190"], dtype="string")
            self.engine._apply_web_attack_mapping_sparse(frame, signals, explanations)
        self.assertEqual(frame["custom_techniques"].tolist(), ["T1190", "T0002", "T0003|T1190"])
        self.assertEqual(frame["chronosift_attack_techniques"].iloc[0], "T1190")
        self.assertTrue(pd.isna(frame["chronosift_attack_techniques"].iloc[1]))
        self.assertEqual(frame["chronosift_attack_techniques"].iloc[2], "T1190")
        self.assertEqual(str(frame["custom_techniques"].dtype), "string")
        self.assertNotIn("mitre_t1190", signals[1])

    def test_public_contextual_api_does_not_copy_state_and_retains_provenance(self):
        for materialise in (False, True):
            with self.subTest(materialise=materialise):
                frame = pd.DataFrame(
                    {"parser": ["fixture"], "message": ["ordinary event"], "chronosift_row_id": [31]},
                    index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"]),
                )
                atomic = self.engine.apply_atomic(frame, apply_profiling=False, enforce_required_fields=False)
                sparse = atomic.attrs["chronosift_sparse"]
                sparse["guard"] = CopyForbidden()
                atomic.attrs["chronosift_metadata"] = {"dataset": "fixture"}
                result = self.engine.apply_contextual(atomic, apply_temporal=True, materialise_event_columns=materialise)
                self.assertIs(result, atomic)
                if not materialise:
                    self.assertIs(result.attrs["chronosift_sparse"], sparse)
                    self.assertEqual(result.attrs["chronosift_metadata"], {"dataset": "fixture"})
                else:
                    # Existing materialisation contract deliberately removes attrs.
                    self.assertEqual(result.attrs, {})

    def test_static_baseline_is_reduced_once_per_group(self):
        for statistic in ("median", "mean"):
            with self.subTest(statistic=statistic):
                policy = self.engine.detector_policy
                web = replace(policy.web_request_classification, sqli=replace(
                    policy.web_request_classification.sqli, baseline_statistic=statistic,
                ))
                frame, signals, explanations = classifier_fixture(self.engine, 30)
                frame["chronosift_web_host"] = ["a.test", "b.test"] * 15
                frame.attrs["chronosift_sparse"] = {"guard": CopyForbidden()}
                with patch.object(self.engine, "detector_policy", policy_with_payload(policy, "web_request_classification", web)):
                    with patch.object(MODULE.np, statistic, wraps=getattr(np, statistic)) as reduction:
                        self.engine._apply_web_request_classifier_sparse(frame, signals, explanations)
                self.assertEqual(reduction.call_count, 2)
                # Do not silently change {} / [] to missing values in output.
                self.assertEqual(signals, {i: {} for i in range(30)})
                self.assertEqual(explanations, {i: [] for i in range(30)})

    def test_public_contextual_failure_restores_original_sparse_object(self):
        frame, _, _ = mapping_fixture(self.engine, 2)
        sparse = frame.attrs["chronosift_sparse"]
        with patch.object(self.engine, "_apply_non_temporal_contextual_sparse", side_effect=RuntimeError("fixture failure")):
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                self.engine.apply_contextual(frame)
        self.assertIs(frame.attrs["chronosift_sparse"], sparse)

    def test_temporal_candidate_merge_preserves_positions_without_state_copy(self):
        frame, signals, explanations = mapping_fixture(self.engine, 4)
        sparse = frame.attrs["chronosift_sparse"]
        sparse["guard"] = CopyForbidden()
        candidate, candidate_signals, candidate_explanations, old_to_new = (
            self.engine._subset_sparse_state(frame, signals, explanations, np.array([True, False, True, False]))
        )
        candidate_signals.pop(0)
        candidate_signals[1]["added"] = 1.0
        field = self.engine.detector_policy.impossible_travel.output_fields["distance_km"]
        candidate[field] = [1.5, 2.5]
        result = self.engine._merge_sparse_contextual_updates(
            frame, signals, explanations, candidate, old_to_new,
        )
        self.assertIs(result, frame)
        self.assertIs(result.attrs["chronosift_sparse"], sparse)
        self.assertNotIn(0, signals)
        self.assertEqual(signals[2]["added"], 1.0)
        self.assertEqual(old_to_new, {0: 0, 2: 1})
        result.attrs.pop("chronosift_sparse")
        self.assertEqual(result["chronosift_row_id"].tolist(), [100, 103, 106, 109])
        self.assertEqual(result[field].iloc[[0, 2]].tolist(), [1.5, 2.5])
        self.assertTrue(result[field].iloc[[1, 3]].isna().all())

    def test_row_dependent_baselines_keep_exact_sample_semantics(self):
        for scope in ("partition", "prior_rows"):
            for lookback in (None, pd.Timedelta(seconds=1)):
                for statistic in ("median", "mean"):
                    for unit in ("s", "ms", "us", "ns"):
                        with self.subTest(scope=scope, lookback=lookback, statistic=statistic, unit=unit):
                            self._assert_baselines(scope, lookback, statistic, unit)

    def _assert_baselines(self, scope, lookback, statistic, unit):
        policy = self.engine.detector_policy
        inference = replace(
            policy.web_request_classification.sqli,
            baseline_scope=scope, baseline_lookback=lookback,
            baseline_statistic=statistic, baseline_sample_indicators="any",
        )
        web = replace(policy.web_request_classification, sqli=inference)
        frame, signals, explanations = classifier_fixture(self.engine, 6)
        offsets = [0, 1, 1, 2, 5, 6]
        frame.index = pd.DatetimeIndex(pd.Timestamp("2024-05-01T00:00:00Z") + pd.to_timedelta(offsets, unit="s")).as_unit(unit)
        values = [100, 100, 10000, 5000, 200, 100000]
        frame["chronosift_web_response_bytes"] = values
        frame["chronosift_web_request_target"] = ["/index.php?id=1 UNION SELECT x FROM y--"] * 6
        with patch.object(self.engine, "detector_policy", policy_with_payload(policy, "web_request_classification", web)):
            self.engine._apply_web_request_classifier_sparse(frame, signals, explanations)
        for row in range(6):
            samples = [value for sample, value in enumerate(values)
                       if (scope != "prior_rows" or sample < row)
                       and (lookback is None or abs(offsets[row] - offsets[sample]) <= 1)]
            expected_stat = float(getattr(np, statistic)(np.asarray(samples, dtype=np.float64))) if len(samples) >= inference.baseline_min_samples else None
            evidence = next(item["evidence"] for item in explanations[row] if item["rule_id"] == "WEB_SQLI_ATTEMPT")
            self.assertEqual(evidence["baseline_sample_count"], len(samples))
            self.assertEqual(evidence["baseline_response_statistic"], expected_stat)
            threshold = float(inference.absolute_large_response_bytes) if expected_stat is None else max(
                inference.response_minimum_bytes, expected_stat * inference.response_ratio,
                expected_stat + inference.response_delta_bytes,
            )
            self.assertEqual(evidence["response_anomaly_threshold"], round(threshold, 3))

    def test_no_baseline_and_empty_inputs_remain_valid(self):
        for n in (0, 1, 4):
            for missing_key in (False, True):
                with self.subTest(n=n, missing_key=missing_key):
                    frame, signals, explanations = classifier_fixture(self.engine, n)
                    if missing_key:
                        frame[self.engine.detector_policy.web_request_classification.outputs.endpoint_field] = ""
                    with patch.object(MODULE.np, "median", wraps=np.median) as reduction:
                        self.engine._apply_web_request_classifier_sparse(frame, signals, explanations)
                    self.assertEqual(reduction.call_count, 0 if n < 2 or missing_key else 1)

    def test_classifier_batches_outcome_aliases_and_preserves_non_http_rows(self):
        for storage in ("python", "pyarrow"):
            with self.subTest(storage=storage):
                policy = self.engine.detector_policy
                web = policy.web_request_classification
                web = replace(web, outputs=replace(web.outputs, web_outcome_field="custom_outcome"))
                with patch.object(self.engine, "detector_policy", policy_with_payload(policy, "web_request_classification", web)):
                    frame, signals, explanations = classifier_fixture(self.engine, 4)
                    for col in ("chronosift_web_outcome", "custom_outcome"):
                        frame[col] = pd.array(["", pd.NA, "", ""], dtype=pd.StringDtype(storage=storage))
                    frame["chronosift_web_request_target"] = ["/index.php", "", "/index.php", "/index.php"]
                    with patch.object(pd.DataFrame, "_set_value", side_effect=AssertionError("scalar write")):
                        self.engine._apply_web_request_classifier_sparse(frame, signals, explanations)
                for col in ("chronosift_web_outcome", "custom_outcome"):
                    self.assertEqual(frame[col].iloc[[0, 2, 3]].tolist(), ["observed"] * 3)
                    self.assertTrue(pd.isna(frame[col].iloc[1]))
                    self.assertEqual(frame[col].dtype.storage, storage)
                self.assertNotIn(1, signals)


if __name__ == "__main__":
    unittest.main()
