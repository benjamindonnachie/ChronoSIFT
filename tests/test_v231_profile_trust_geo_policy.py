"""Focused contracts for geo continuity, profiling, trust, and strict config."""

from copy import deepcopy
import importlib.util
import pathlib
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import pandas as pd
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "chronoSIFT_v2_31.py"
SPEC = importlib.util.spec_from_file_location(
    "chronosift_v2_31_profile_trust_geo", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RULES_PATH = ROOT / "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = ROOT / "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"


def _load_yaml(path):
    with pathlib.Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _replace_scalar(value, old, new):
    if isinstance(value, dict):
        for key, item in value.items():
            value[key] = _replace_scalar(item, old, new)
        return value
    if isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = _replace_scalar(item, old, new)
        return value
    return new if value == old else value


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


class ChronoSiftV231ProfileTrustGeoPolicyTest(unittest.TestCase):
    def _engine(self, rules=None, weights=None):
        return MODULE.ChronoSiftEngine(
            deepcopy(BASE_RULES if rules is None else rules),
            deepcopy(BASE_WEIGHTS if weights is None else weights),
            yara_metadata_path=BASE_YARA_PATH,
        )

    @staticmethod
    def _detector(rules, detector_id):
        return rules["detector_policy"]["detectors"][detector_id]

    def test_canonical_geo_policies_are_typed_and_complete(self):
        engine = self._engine()
        self.assertEqual(len(engine.detector_policy.detectors), 35)
        self.assertEqual(
            engine.geoip_enrichment_policy.output_fields,
            {
                "city_geoname_id": "geo_city_geoname_id",
                "city_name": "geo_city_name",
                "country_iso": "geo_country_iso",
                "latitude": "geo_latitude",
                "longitude": "geo_longitude",
                "asn": "geo_asn",
            },
        )
        geo = engine.detector_policy.geographic_continuity
        self.assertEqual(geo.key_fields, ("actor_principal",))
        self.assertEqual(geo.success_signals, frozenset({"auth_remote_success"}))
        self.assertIsNone(geo.history_lookback)
        self.assertEqual(geo.novelty_reference, "all_seen")
        self.assertTrue(geo.mark_first_observation)
        self.assertFalse(geo.emit_first_observation)
        self.assertEqual(geo.boundary_reference, "previous_observation")
        self.assertEqual(
            set(geo.emissions_by_semantic),
            {"new_country", "new_asn", "new_city", "boundary_crossing"},
        )
        travel = engine.detector_policy.impossible_travel
        self.assertEqual(travel.velocity_kmh_threshold, 900.0)
        self.assertEqual(travel.reference_selection, "retained_reference")
        self.assertEqual(
            travel.rejected_observation_update, "retain_reference"
        )
        self.assertEqual(
            travel.qualifying_comparison_update, "update_reference"
        )
        self.assertEqual(
            (
                travel.minimum_distance_comparison,
                travel.minimum_time_comparison,
                travel.velocity_comparison,
            ),
            (
                "greater_than_or_equal",
                "greater_than_or_equal",
                "greater_than_or_equal",
            ),
        )
        ip_scope = engine.detector_policy.ip_scope_continuity
        self.assertEqual(
            ip_scope.lookback, pd.Timedelta("24h").to_pytimedelta()
        )
        self.assertEqual(ip_scope.reference_selection, "retained_reference")
        self.assertEqual(ip_scope.state_update, "every_valid_observation")
        self.assertEqual(ip_scope.lookback_window_bounds, "closed")
        self.assertEqual(ip_scope.branch_mode, "all_matches")

    def test_geoip_output_fields_are_config_authoritative_end_to_end(self):
        rules = deepcopy(BASE_RULES)
        output_fields = {
            "city_geoname_id": "policy_geo_city_id",
            "city_name": "policy_geo_city",
            "country_iso": "policy_geo_country",
            "latitude": "policy_geo_latitude",
            "longitude": "policy_geo_longitude",
            "asn": "policy_geo_asn",
        }
        rules["geoip_enrichment"]["outputs"] = output_fields
        geographic = self._detector(rules, "geographic_continuity")["inputs"]
        geographic.update(
            {
                "country_field": output_fields["country_iso"],
                "asn_field": output_fields["asn"],
                "city_field": output_fields["city_name"],
            }
        )
        travel = self._detector(rules, "impossible_travel")["inputs"]
        travel.update(
            {
                "latitude_field": output_fields["latitude"],
                "longitude_field": output_fields["longitude"],
                "country_field": output_fields["country_iso"],
            }
        )
        engine = self._engine(rules)

        locations = {
            "8.8.8.8": (2643743, "London", "GB", 51.5074, -0.1278),
            "1.1.1.1": (2950159, "Berlin", "DE", 52.5200, 13.4050),
        }
        asns = {"8.8.8.8": 15169, "1.1.1.1": 13335}

        class CityReader:
            def city(self, ip_value):
                geoname_id, name, country, latitude, longitude = locations[ip_value]
                return SimpleNamespace(
                    city=SimpleNamespace(geoname_id=geoname_id, name=name),
                    country=SimpleNamespace(iso_code=country),
                    location=SimpleNamespace(
                        latitude=latitude,
                        longitude=longitude,
                    ),
                )

            def close(self):
                pass

        class ASNReader:
            def asn(self, ip_value):
                return SimpleNamespace(autonomous_system_number=asns[ip_value])

            def close(self):
                pass

        frame = pd.DataFrame(
            {
                "actor_principal": ["alice", "alice"],
                "ip_address": ["8.8.8.8", "1.1.1.1"],
            },
            index=pd.date_range("2024-06-16T10:00:00Z", periods=2, freq="30min"),
        )
        with mock.patch.object(
            MODULE.geoip2_database,
            "Reader",
            side_effect=[CityReader(), ASNReader()],
        ):
            out = engine.apply_atomic(
                frame,
                geoip_city_db="configured-city.mmdb",
                geoip_asn_db="configured-asn.mmdb",
                apply_profiling=False,
                enforce_required_fields=False,
            )

        self.assertEqual(out.iloc[0][output_fields["city_name"]], "London")
        self.assertEqual(out.iloc[1][output_fields["country_iso"]], "DE")
        self.assertEqual(out.iloc[1][output_fields["asn"]], 13335)
        self.assertNotIn("geo_city_name", out.columns)
        self.assertNotIn("geo_country_iso", out.columns)
        self.assertNotIn("geo_asn", out.columns)
        self.assertTrue(
            set(output_fields.values()).issubset(
                engine._configured_sidecar_output_columns()
            )
        )
        self.assertTrue(
            {
                output_fields["city_name"],
                output_fields["country_iso"],
                output_fields["latitude"],
                output_fields["longitude"],
                output_fields["asn"],
            }.issubset(engine.required_fields)
        )

        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        engine._apply_geo_continuity_sparse(out, signal_map, explain_map)
        engine._apply_impossible_travel_sparse(out, signal_map, explain_map)
        self.assertEqual(signal_map[1]["new_country"], 1.0)
        self.assertEqual(signal_map[1]["boundary_crossing"], 1.0)
        self.assertEqual(signal_map[1]["impossible_travel"], 1.0)

    def test_geo_policies_coalesce_ordered_ip_fields_per_row(self):
        engine = self._engine()
        frame = pd.DataFrame(
            {
                "actor_principal": ["alice", "alice"],
                "src_ip": ["", pd.NA],
                "ip_address": ["8.8.8.8", "10.0.0.5"],
                "geo_country_iso": ["GB", "DE"],
                "geo_asn": ["AS1", "AS2"],
                "geo_city_name": ["London", "Berlin"],
                "geo_latitude": [51.5074, 52.5200],
                "geo_longitude": [-0.1278, 13.4050],
            },
            index=pd.date_range(
                "2024-06-16T10:00:00Z", periods=2, freq="5min"
            ),
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}

        engine._apply_geo_continuity_sparse(frame, signal_map, explain_map)
        engine._apply_impossible_travel_sparse(frame, signal_map, explain_map)
        engine._apply_private_ip_continuity_sparse(
            frame, signal_map, explain_map
        )

        boundary = next(
            item
            for item in explain_map[1]
            if item["rule_id"] == "BOUNDARY_CROSSING"
        )
        self.assertEqual(boundary["evidence"]["from_ip"], "8.8.8.8")
        self.assertEqual(boundary["evidence"]["to_ip"], "10.0.0.5")
        self.assertEqual(frame.iloc[1]["travel_from_ip"], "8.8.8.8")
        self.assertEqual(signal_map[1]["user_public_to_private_ip"], 1.0)

    def test_impossible_travel_retains_rejected_reference_across_partitions(self):
        engine = self._engine()
        carried_state = {}

        def observe(timestamp, country, latitude, longitude, ip_address):
            frame = pd.DataFrame(
                [
                    {
                        "actor_principal": "alice",
                        "geo_country_iso": country,
                        "geo_latitude": latitude,
                        "geo_longitude": longitude,
                        "src_ip": ip_address,
                    }
                ],
                index=pd.DatetimeIndex([pd.Timestamp(timestamp)]),
            )
            signal_map = {0: {"auth_remote_success": 1.0}}
            explain_map = {}
            engine._apply_impossible_travel_sparse(
                frame,
                signal_map,
                explain_map,
                carried_last=carried_state,
            )
            return frame, signal_map, explain_map

        observe(
            "2024-06-16T10:00:00Z",
            "GB",
            51.5074,
            -0.1278,
            "203.0.113.1",
        )
        _, rejected_signals, rejected_explain = observe(
            "2024-06-16T10:00:30Z",
            "JP",
            35.6762,
            139.6503,
            "203.0.113.2",
        )
        detected_frame, detected_signals, detected_explain = observe(
            "2024-06-16T10:01:30Z",
            "JP",
            35.6762,
            139.6503,
            "203.0.113.2",
        )

        self.assertNotIn("impossible_travel", rejected_signals[0])
        self.assertEqual(rejected_explain, {})
        self.assertEqual(detected_signals[0]["impossible_travel"], 1.0)
        self.assertEqual(
            detected_explain[0][0]["evidence"]["from_country"], "GB"
        )
        self.assertEqual(detected_frame.iloc[0]["travel_from_ip"], "203.0.113.1")
        self.assertEqual(
            carried_state[("alice",)]["retained_reference"]["country"],
            "JP",
        )

    def test_impossible_travel_state_mutations_are_yaml_authoritative(self):
        def run_sequence(rules, observations):
            engine = self._engine(rules)
            carried_state = {}
            outputs = []
            for timestamp, country, latitude, longitude in observations:
                frame = pd.DataFrame(
                    [
                        {
                            "actor_principal": "alice",
                            "geo_country_iso": country,
                            "geo_latitude": latitude,
                            "geo_longitude": longitude,
                            "src_ip": f"203.0.113.{len(outputs) + 1}",
                        }
                    ],
                    index=pd.DatetimeIndex([pd.Timestamp(timestamp)]),
                )
                signal_map = {0: {"auth_remote_success": 1.0}}
                engine._apply_impossible_travel_sparse(
                    frame,
                    signal_map,
                    {},
                    carried_last=carried_state,
                )
                outputs.append(signal_map[0])
            return outputs

        rejected_sequence = (
            ("2024-06-16T10:00:00Z", "GB", 51.5074, -0.1278),
            ("2024-06-16T10:00:30Z", "JP", 35.6762, 139.6503),
            ("2024-06-16T10:01:30Z", "JP", 35.6762, 139.6503),
        )
        for state_key, configured_value in (
            ("rejected_observation_update", "update_reference"),
            ("reference_selection", "previous_observation"),
        ):
            with self.subTest(state_key=state_key):
                rules = deepcopy(BASE_RULES)
                self._detector(rules, "impossible_travel")["state"][
                    state_key
                ] = configured_value
                outputs = run_sequence(rules, rejected_sequence)
                self.assertNotIn("impossible_travel", outputs[2])

        qualifying_sequence = (
            ("2024-06-16T10:00:00Z", "GB", 51.5074, -0.1278),
            ("2024-06-16T22:00:00Z", "JP", 35.6762, 139.6503),
            ("2024-06-16T22:01:00Z", "GB", 51.5074, -0.1278),
        )
        baseline_outputs = run_sequence(BASE_RULES, qualifying_sequence)
        self.assertEqual(baseline_outputs[2]["impossible_travel"], 1.0)

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "impossible_travel")["state"][
            "qualifying_comparison_update"
        ] = "retain_reference"
        configured_outputs = run_sequence(rules, qualifying_sequence)
        self.assertNotIn("impossible_travel", configured_outputs[2])

    def test_impossible_travel_threshold_comparisons_are_yaml_authoritative(self):
        london = (51.5074, -0.1278)
        tokyo = (35.6762, 139.6503)
        distance_km = MODULE._haversine_km(*london, *tokyo)
        dt_seconds = 3600.0
        velocity_kmh = (distance_km / dt_seconds) * 3600.0

        def detected(rules):
            engine = self._engine(rules)
            frame = pd.DataFrame(
                [
                    {
                        "actor_principal": "alice",
                        "geo_country_iso": "GB",
                        "geo_latitude": london[0],
                        "geo_longitude": london[1],
                        "src_ip": "203.0.113.1",
                    },
                    {
                        "actor_principal": "alice",
                        "geo_country_iso": "JP",
                        "geo_latitude": tokyo[0],
                        "geo_longitude": tokyo[1],
                        "src_ip": "203.0.113.2",
                    },
                ],
                index=pd.DatetimeIndex(
                    [
                        pd.Timestamp("2024-06-16T10:00:00Z"),
                        pd.Timestamp("2024-06-16T11:00:00Z"),
                    ]
                ),
            )
            signal_map = {
                0: {"auth_remote_success": 1.0},
                1: {"auth_remote_success": 1.0},
            }
            engine._apply_impossible_travel_sparse(frame, signal_map, {})
            return "impossible_travel" in signal_map[1]

        baseline_rules = deepcopy(BASE_RULES)
        thresholds = self._detector(
            baseline_rules, "impossible_travel"
        )["thresholds"]
        thresholds.update(
            {
                "minimum_distance_km": distance_km,
                "minimum_time_seconds": dt_seconds,
                "velocity_kmh": velocity_kmh,
            }
        )
        self.assertTrue(detected(baseline_rules))

        for comparison_key in (
            "minimum_distance_comparison",
            "minimum_time_comparison",
            "velocity_comparison",
        ):
            with self.subTest(comparison_key=comparison_key):
                rules = deepcopy(baseline_rules)
                self._detector(rules, "impossible_travel")["thresholds"][
                    comparison_key
                ] = "greater_than"
                self.assertFalse(detected(rules))

    def test_ip_scope_all_matching_transitions_and_branch_mode_are_authoritative(self):
        def run(rules):
            engine = self._engine(rules)
            frame = pd.DataFrame(
                {
                    "actor_principal": ["alice", "alice"],
                    "src_ip": ["10.0.0.5", "10.0.1.8"],
                },
                index=pd.DatetimeIndex(
                    [
                        pd.Timestamp("2024-06-16T10:00:00Z"),
                        pd.Timestamp("2024-06-16T10:05:00Z"),
                    ]
                ),
            )
            signal_map = {}
            explain_map = {}
            engine._apply_private_ip_continuity_sparse(
                frame, signal_map, explain_map
            )
            return signal_map, explain_map

        signal_map, explain_map = run(BASE_RULES)
        self.assertEqual(signal_map[1]["user_changed_private_ip"], 1.0)
        self.assertEqual(signal_map[1]["user_crossed_private_subnet"], 1.0)
        self.assertEqual(
            [item["rule_id"] for item in explain_map[1]],
            ["USER_CHANGED_PRIVATE_IP", "USER_CROSSED_PRIVATE_SUBNET"],
        )

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "ip_scope_continuity")[
            "branch_mode"
        ] = "first_match"
        configured_signals, configured_explain = run(rules)
        self.assertEqual(
            configured_signals[1]["user_changed_private_ip"], 1.0
        )
        self.assertNotIn(
            "user_crossed_private_subnet", configured_signals[1]
        )
        self.assertEqual(
            [item["rule_id"] for item in configured_explain[1]],
            ["USER_CHANGED_PRIVATE_IP"],
        )

    def test_ip_scope_lookback_bounds_are_yaml_authoritative(self):
        def changed(rules):
            engine = self._engine(rules)
            frame = pd.DataFrame(
                {
                    "actor_principal": ["alice", "alice"],
                    "src_ip": ["10.0.0.5", "10.0.0.8"],
                },
                index=pd.DatetimeIndex(
                    [
                        pd.Timestamp("2024-06-16T10:00:00Z"),
                        pd.Timestamp("2024-06-17T10:00:00Z"),
                    ]
                ),
            )
            signal_map = {}
            engine._apply_private_ip_continuity_sparse(frame, signal_map, {})
            return "user_changed_private_ip" in signal_map.get(1, {})

        self.assertTrue(changed(BASE_RULES))
        rules = deepcopy(BASE_RULES)
        self._detector(rules, "ip_scope_continuity")["lookback"][
            "window_bounds"
        ] = "open"
        self.assertFalse(changed(rules))

    def test_ip_scope_history_state_is_yaml_authoritative_across_partitions(self):
        observations = (
            ("2024-06-16T10:00:00Z", "10.0.0.5"),
            ("2024-06-17T11:00:00Z", "8.8.8.8"),
            ("2024-06-17T11:01:00Z", "10.0.0.8"),
        )

        def run(rules):
            engine = self._engine(rules)
            carried_state = {}
            outputs = []
            for timestamp, ip_address in observations:
                frame = pd.DataFrame(
                    {
                        "actor_principal": ["alice"],
                        "src_ip": [ip_address],
                    },
                    index=pd.DatetimeIndex([pd.Timestamp(timestamp)]),
                )
                signal_map = {}
                engine._apply_private_ip_continuity_sparse(
                    frame,
                    signal_map,
                    {},
                    carried_last=carried_state,
                )
                outputs.append(signal_map.get(0, {}))
            return outputs, carried_state

        baseline_outputs, baseline_state = run(BASE_RULES)
        self.assertEqual(
            baseline_outputs[2]["user_public_to_private_ip"], 1.0
        )
        self.assertEqual(
            baseline_state[("alice",)]["retained_reference"]["ip"],
            "10.0.0.8",
        )

        rules = deepcopy(BASE_RULES)
        history = self._detector(rules, "ip_scope_continuity")["history"]
        history["state_update"] = "after_in_window_comparison"
        retained_outputs, retained_state = run(rules)
        self.assertNotIn("user_public_to_private_ip", retained_outputs[2])
        self.assertEqual(
            retained_state[("alice",)]["retained_reference"]["ip"],
            "10.0.0.5",
        )

        history["reference_selection"] = "previous_observation"
        previous_outputs, _ = run(rules)
        self.assertEqual(
            previous_outputs[2]["user_public_to_private_ip"], 1.0
        )

    def test_geoip_output_schema_and_consumer_bindings_are_strict(self):
        rules = deepcopy(BASE_RULES)
        rules["geoip_enrichment"]["outputs"]["city_name"] = "geo_country_iso"
        with self.assertRaisesRegex(
            ValueError,
            r"geoip_enrichment\.outputs.*must be distinct",
        ):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        rules["geoip_enrichment"]["outputs"]["unexpected"] = "geo_unexpected"
        with self.assertRaisesRegex(
            ValueError,
            r"geoip_enrichment\.outputs.*unknown key.*unexpected",
        ):
            self._engine(rules)

        mismatch_cases = (
            ("geographic_continuity", "country_field", "country_iso"),
            ("geographic_continuity", "asn_field", "asn"),
            ("geographic_continuity", "city_field", "city_name"),
            ("impossible_travel", "latitude_field", "latitude"),
            ("impossible_travel", "longitude_field", "longitude"),
            ("impossible_travel", "country_field", "country_iso"),
        )
        for detector_id, input_name, output_role in mismatch_cases:
            with self.subTest(detector_id=detector_id, input_name=input_name):
                rules = deepcopy(BASE_RULES)
                self._detector(rules, detector_id)["inputs"][input_name] = (
                    f"mismatched_{input_name}"
                )
                with self.assertRaisesRegex(
                    ValueError,
                    rf"{detector_id}\.inputs\.{input_name}.*"
                    rf"geoip_enrichment\.outputs\.{output_role}",
                ):
                    self._engine(rules)

    def test_geographic_emission_and_output_metadata_are_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        geo = self._detector(rules, "geographic_continuity")
        geo["output_fields"]["new_country"] = "policy_geo_new_country"
        geo["emissions"]["new_country"].update(
            {
                "name": "policy_new_country",
                "value": 0.75,
                "rule_id": "POLICY_NEW_COUNTRY",
                "description": "Configured geography metadata reached runtime",
                "confidence": "low",
            }
        )
        _replace_scalar(rules, "new_country", "policy_new_country")
        weights["weights"]["policy_new_country"] = 4
        engine = self._engine(rules, weights)

        frame = pd.DataFrame(
            [
                {
                    "actor_principal": "alice",
                    "geo_country_iso": "GB",
                    "geo_asn": "AS1",
                    "geo_city_name": "London",
                    "src_ip": "203.0.113.1",
                },
                {
                    "actor_principal": "alice",
                    "geo_country_iso": "DE",
                    "geo_asn": "AS2",
                    "geo_city_name": "Berlin",
                    "src_ip": "203.0.113.2",
                },
            ],
            index=pd.date_range("2024-06-16T10:00:00Z", periods=2, freq="h"),
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        engine._apply_geo_continuity_sparse(frame, signal_map, explain_map)

        self.assertTrue(bool(frame.iloc[1]["policy_geo_new_country"]))
        self.assertEqual(signal_map[1]["policy_new_country"], 0.75)
        explanation = next(
            item
            for item in explain_map[1]
            if item["rule_id"] == "POLICY_NEW_COUNTRY"
        )
        self.assertEqual(
            explanation["description"],
            "Configured geography metadata reached runtime",
        )
        self.assertEqual(explanation["confidence"], "low")

    def test_geographic_history_decisions_are_yaml_authoritative(self):
        def frame(countries, *, spacing="1h"):
            count = len(countries)
            return pd.DataFrame(
                {
                    "actor_principal": ["alice"] * count,
                    "geo_country_iso": countries,
                    "geo_asn": ["AS1"] * count,
                    "geo_city_name": ["London"] * count,
                    "src_ip": [f"203.0.113.{index + 1}" for index in range(count)],
                },
                index=pd.date_range(
                    "2024-06-16T10:00:00Z", periods=count, freq=spacing
                ),
            )

        rules = deepcopy(BASE_RULES)
        history = self._detector(rules, "geographic_continuity")["history"]
        history["novelty_reference"] = "previous_observation"
        engine = self._engine(rules)
        data = frame(["GB", "DE", "GB"])
        signal_map = {
            index: {"auth_remote_success": 1.0} for index in range(len(data))
        }
        explain_map = {index: [] for index in range(len(data))}
        engine._apply_geo_continuity_sparse(data, signal_map, explain_map)
        self.assertEqual(signal_map[2]["new_country"], 1.0)

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "geographic_continuity")["history"][
            "emit_first_observation"
        ] = True
        engine = self._engine(rules)
        data = frame(["GB"])
        signal_map = {0: {"auth_remote_success": 1.0}}
        explain_map = {0: []}
        engine._apply_geo_continuity_sparse(data, signal_map, explain_map)
        self.assertEqual(signal_map[0]["new_country"], 1.0)

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "geographic_continuity")["history"][
            "retention"
        ] = "1h"
        engine = self._engine(rules)
        data = frame(["GB", "GB"], spacing="2h")
        signal_map = {
            index: {"auth_remote_success": 1.0} for index in range(len(data))
        }
        explain_map = {index: [] for index in range(len(data))}
        engine._apply_geo_continuity_sparse(data, signal_map, explain_map)
        self.assertTrue(bool(data.iloc[1]["geo_new_country"]))
        self.assertNotIn("new_country", signal_map[1])

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "geographic_continuity")["history"][
            "boundary_reference"
        ] = "any_prior_distinct"
        engine = self._engine(rules)
        data = frame(["GB", "DE", "DE"])
        signal_map = {
            index: {"auth_remote_success": 1.0} for index in range(len(data))
        }
        explain_map = {index: [] for index in range(len(data))}
        engine._apply_geo_continuity_sparse(data, signal_map, explain_map)
        self.assertEqual(signal_map[2]["boundary_crossing"], 1.0)

    def test_geo_policy_disablement_suppresses_each_executor(self):
        for detector_id in (
            "geographic_continuity",
            "impossible_travel",
            "ip_scope_continuity",
        ):
            with self.subTest(detector_id=detector_id):
                rules = deepcopy(BASE_RULES)
                self._detector(rules, detector_id)["enabled"] = False
                engine = self._engine(rules)
                self.assertFalse(
                    engine.detector_policy.definition(detector_id).payload.enabled
                )

    def test_candidate_merge_uses_configured_geo_output_fields(self):
        rules = deepcopy(BASE_RULES)
        self._detector(rules, "geographic_continuity")["output_fields"][
            "new_country"
        ] = "policy_candidate_geo_country"
        self._detector(rules, "impossible_travel")["output_fields"][
            "distance_km"
        ] = "policy_candidate_distance"
        engine = self._engine(rules)
        self.assertIn(
            "policy_candidate_geo_country",
            engine._configured_sidecar_output_columns(),
        )
        self.assertIn(
            "policy_candidate_distance",
            engine._configured_sidecar_output_columns(),
        )
        full = pd.DataFrame(
            {"value": [1, 2]},
            index=pd.date_range("2024-06-16T10:00:00Z", periods=2, freq="h"),
        )
        candidate = pd.DataFrame(
            {
                "policy_candidate_geo_country": [True],
                "policy_candidate_distance": [250.0],
            },
            index=full.index[1:],
        )
        candidate.attrs["chronosift_sparse"] = {
            "signal_map": {0: {"new_country": 1.0}},
            "explain_map": {0: []},
        }
        signal_map = {}
        explain_map = {}
        merged = engine._merge_sparse_contextual_updates(
            full,
            signal_map,
            explain_map,
            candidate,
            {1: 0},
        )
        self.assertTrue(bool(merged.iloc[1]["policy_candidate_geo_country"]))
        self.assertEqual(merged.iloc[1]["policy_candidate_distance"], 250.0)
        self.assertEqual(signal_map[1]["new_country"], 1.0)

    def test_malformed_geo_policies_report_precise_paths(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        del self._detector(rules, "geographic_continuity")["inputs"][
            "country_field"
        ]
        cases.append((rules, r"geographic_continuity\.inputs.*country_field"))

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "geographic_continuity")["history"][
            "novelty_reference"
        ] = "opaque_baseline"
        cases.append(
            (rules, r"geographic_continuity\.history\.novelty_reference")
        )

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "impossible_travel")["thresholds"][
            "velocity_kmh"
        ] = 0
        cases.append((rules, r"impossible_travel\.thresholds\.velocity_kmh"))

        rules = deepcopy(BASE_RULES)
        del self._detector(rules, "impossible_travel")["state"]
        cases.append((rules, r"impossible_travel.*missing required key.*state"))

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "impossible_travel")["state"][
            "rejected_observation_update"
        ] = "always_advance"
        cases.append(
            (
                rules,
                r"impossible_travel\.state\.rejected_observation_update",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "impossible_travel")["thresholds"][
            "minimum_time_comparison"
        ] = "approximately"
        cases.append(
            (
                rules,
                r"impossible_travel\.thresholds\.minimum_time_comparison",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "ip_scope_continuity")["transition_rules"][0][
            "emission"
        ] = "missing_semantic"
        cases.append((rules, r"ip_scope_continuity\.transition_rules\[0\]\.emission"))

        rules = deepcopy(BASE_RULES)
        del self._detector(rules, "ip_scope_continuity")["history"]
        cases.append(
            (rules, r"ip_scope_continuity.*missing required key.*history")
        )

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "ip_scope_continuity")["history"][
            "state_update"
        ] = "sometimes"
        cases.append((rules, r"ip_scope_continuity\.history\.state_update"))

        rules = deepcopy(BASE_RULES)
        del self._detector(rules, "ip_scope_continuity")["lookback"][
            "window_bounds"
        ]
        cases.append(
            (
                rules,
                r"ip_scope_continuity\.lookback.*missing required key.*window_bounds",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._detector(rules, "ip_scope_continuity")["branch_mode"] = (
            "unordered"
        )
        cases.append((rules, r"ip_scope_continuity\.branch_mode"))

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["nsrl_exclusion_combine"] = (
            "opaque_mode"
        )
        cases.append((rules, r"profiling\.hour_of_week\.nsrl_exclusion_combine"))

        for rules_doc, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    self._engine(rules_doc)

    def test_profile_nsrl_exclusion_composition_is_yaml_authoritative(self):
        frame = pd.DataFrame(
            {
                "parser": ["mft"],
                "filename": ["ordinary.bin"],
                "nsrl_is_os_component": [False],
                "nsrl_application_type": ["Operating System"],
            },
            index=pd.DatetimeIndex(
                [pd.Timestamp("2024-06-16T09:00:00Z")]
            ),
        )

        any_policy = self._engine().profiling_policy
        self.assertTrue(
            MODULE._select_profile_events(frame, any_policy).empty
        )

        preferred_rules = deepcopy(BASE_RULES)
        preferred_rules["profiling"]["hour_of_week"][
            "nsrl_exclusion_combine"
        ] = "component_field_preferred"
        preferred_policy = self._engine(preferred_rules).profiling_policy
        self.assertEqual(
            len(MODULE._select_profile_events(frame, preferred_policy)),
            1,
        )

    def test_profiling_fields_signals_and_explanation_are_config_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        profile = rules["profiling"]["hour_of_week"]
        profile.update(
            {
                "min_profile_events": 1,
                "parser_field": "policy_parser",
                "filename_field": "policy_filename",
                "nsrl_is_os_component_field": "policy_nsrl_os",
                "nsrl_application_type_field": "policy_nsrl_type",
                "include_parser_regex": "profile",
                "hour_of_week_field": "policy_hour_of_week",
                "rarity_signal": "policy_hour_rarity",
                "quiet_signal": "policy_quiet_time",
                "rarity_score_field": "chronosift_policy_hour_score",
                "quiet_signal_value": 2.5,
                "emit_hour_rarity_signal": True,
                "emit_quiet_time_signal": True,
            }
        )
        profile["rarity_explanation"].update(
            {
                "rule_id": "POLICY_HOUR_RARITY",
                "description": "Configured profile explanation",
                "confidence": "high",
            }
        )
        profile["quiet_explanation"].update(
            {
                "rule_id": "POLICY_QUIET_TIME",
                "description": "Configured quiet-time explanation",
                "confidence": "medium",
            }
        )
        ineligible = rules["engine_config"]["temporal_signal_policy"][
            "ineligible_signals"
        ]
        ineligible.extend(["policy_hour_rarity", "policy_quiet_time"])
        weights["weights"]["policy_hour_rarity"] = 4
        weights["weights"]["policy_quiet_time"] = 3
        engine = self._engine(rules, weights)

        frame = pd.DataFrame(
            {
                "policy_parser": ["profile", "profile"],
                "policy_filename": ["a", "b"],
            },
            index=pd.date_range("2024-06-16T10:00:00Z", periods=2, freq="h"),
        )
        profiled = engine._apply_hour_of_week_profiling(
            frame,
            profile_manifest={
                "profile": {154: 0.5, 155: 0.25},
                "quiet_hours": [154],
                "selection_mode": "test",
                "source_event_count": 2,
                "selected_event_count": 2,
            },
        )
        self.assertIn("policy_hour_of_week", profiled.columns)
        self.assertIn("policy_hour_rarity", profiled.columns)
        signal_map = {}
        explain_map = {}
        engine._inject_profile_base_signals_sparse(
            profiled, signal_map, explain_map
        )
        self.assertEqual(
            signal_map,
            {
                0: {
                    "policy_hour_rarity": 0.5,
                    "policy_quiet_time": 2.5,
                },
                1: {"policy_hour_rarity": 0.25},
            },
        )
        self.assertEqual(
            engine._score_signal_map_sparse(2, signal_map).tolist(),
            [9.5, 1.0],
        )
        explanation = MODULE._hour_rarity_explain_item(engine.profiling_policy)
        self.assertEqual(explanation["rule_id"], "POLICY_HOUR_RARITY")
        self.assertEqual(explanation["description"], "Configured profile explanation")
        self.assertEqual(explanation["confidence"], "high")
        self.assertEqual(explanation["signals"], ["policy_hour_rarity"])
        self.assertEqual(
            [item["rule_id"] for item in explain_map[0]],
            ["POLICY_HOUR_RARITY", "POLICY_QUIET_TIME"],
        )

        engine._materialise_sparse_event_columns(
            profiled, signal_map, explain_map
        )
        self.assertEqual(
            profiled["chronosift_policy_hour_score"].tolist(),
            [2.0, 1.0],
        )
        self.assertEqual(
            sum(
                item["rule_id"] == "POLICY_HOUR_RARITY"
                for item in profiled.iloc[0]["chronosift_explain"]
            ),
            1,
        )

    def test_profile_signal_merge_and_disablement_are_literal(self):
        rules = deepcopy(BASE_RULES)
        profile = rules["profiling"]["hour_of_week"]
        profile.update(
            {
                "rarity_signal_merge": "sum",
                "quiet_signal_value": 2,
                "quiet_signal_merge": "sum",
                "emit_hour_rarity_signal": True,
                "emit_quiet_time_signal": True,
            }
        )
        rules["engine_config"]["temporal_signal_policy"][
            "ineligible_signals"
        ].extend(["hour_rarity", "quiet_time_event"])
        weights = deepcopy(BASE_WEIGHTS)
        weights["weights"]["hour_rarity"] = 5
        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            {"hour_rarity": [0.4], "hour_of_week": [10]},
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-17T10:00:00Z")]),
        )
        frame.attrs["_chronosift_quiet_hours_profile"] = frozenset({10})
        signal_map = {
            0: {"hour_rarity": 0.6, "quiet_time_event": 0.5}
        }
        explain_map = {0: []}
        engine._inject_profile_base_signals_sparse(
            frame, signal_map, explain_map
        )
        self.assertEqual(signal_map[0]["hour_rarity"], 1.0)
        self.assertEqual(signal_map[0]["quiet_time_event"], 2.5)
        self.assertEqual(
            [item["rule_id"] for item in explain_map[0]],
            ["HOUR_RARITY", "QUIET_TIME_EVENT"],
        )

        fresh_signal_map = {}
        fresh_explain_map = {}
        engine._inject_profile_base_signals_sparse(
            frame, fresh_signal_map, fresh_explain_map
        )
        self.assertEqual(fresh_signal_map[0]["hour_rarity"], 0.4)
        self.assertEqual(fresh_signal_map[0]["quiet_time_event"], 2.0)
        self.assertEqual(len(fresh_explain_map[0]), 2)

        engine._materialise_sparse_event_columns(
            frame, signal_map, explain_map
        )
        self.assertEqual(frame.iloc[0]["chronosift_hour_rarity_score"], 5.0)

        disabled_frame = pd.DataFrame(
            {"hour_rarity": [0.9], "hour_of_week": [10]},
            index=frame.index,
        )
        _, disabled_signals, _ = engine._run_atomic_sparse(
            disabled_frame,
            apply_profiling=False,
            enforce_required_fields=False,
        )
        self.assertNotIn("hour_rarity", disabled_signals.get(0, {}))
        self.assertNotIn("quiet_time_event", disabled_signals.get(0, {}))

    def test_default_profile_uses_rarity_for_multipliers_without_dense_emission(self):
        engine = self._engine()
        frame = pd.DataFrame(
            {"filename": [f"ordinary-{index}.txt" for index in range(32)]},
            index=pd.date_range("2024-06-17T10:00:00Z", periods=32, freq="min"),
        )
        out, signal_map, _ = engine._run_atomic_sparse(
            frame,
            apply_profiling=True,
            enforce_required_fields=False,
            profile_manifest={
                "profile": {10: 0.75},
                "quiet_hours": [10],
                "selection_mode": "test",
                "source_event_count": 32,
                "selected_event_count": 32,
            },
        )
        self.assertTrue((out["hour_rarity"] == 0.75).all())
        self.assertFalse(any(
            "hour_rarity" in signals or "quiet_time_event" in signals
            for signals in signal_map.values()
        ))

    def test_profiling_emission_schema_rejects_legacy_or_partial_policy(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        del rules["profiling"]["hour_of_week"]["rarity_signal_merge"]
        cases.append((rules, r"profiling\.hour_of_week.*rarity_signal_merge"))

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["quiet_signal_merge"] = "replace"
        cases.append((rules, r"profiling\.hour_of_week\.quiet_signal_merge"))

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["quiet_threshold"] = 0.8
        cases.append((rules, r"profiling\.hour_of_week.*unknown key.*quiet_threshold"))

        rules = deepcopy(BASE_RULES)
        del rules["profiling"]["hour_of_week"]["quiet_explanation"]["rule_id"]
        cases.append(
            (rules, r"profiling\.hour_of_week\.quiet_explanation.*rule_id")
        )

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["rarity_score_field"] = (
            "chronosift_score"
        )
        cases.append((rules, r"profiling\.hour_of_week.*reserved field chronosift_score"))

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["quiet_signal"] = "hour_rarity"
        cases.append((rules, r"profile field and signal names must be distinct"))

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["hour_of_week_field"] = (
            "geo_city_name"
        )
        cases.append((rules, r"collide with other configured derived fields"))

        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"]["quiet_explanation"]["rule_id"] = (
            "HOUR_RARITY"
        )
        cases.append((rules, r"explanation rule_id.*must be unique"))

        for rules_doc, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    self._engine(rules_doc)

    def test_nsrl_os_classification_uses_configured_application_type_tokens(self):
        rules = deepcopy(BASE_RULES)
        rules["profiling"]["hour_of_week"][
            "exclude_nsrl_application_type_contains"
        ] = ["Configured Platform"]
        rules["profiling"]["hour_of_week"].update(
            {
                "nsrl_application_type_field": "policy_nsrl_type",
                "nsrl_is_os_component_field": "policy_nsrl_os",
            }
        )
        engine = self._engine(rules)
        configured_hash = "A" * 64
        upstream_hash = "B" * 64
        cache = pd.DataFrame({
            "sha256": [configured_hash, upstream_hash],
            "nsrl_application_type": ["Configured Platform File", "Browser"],
            "nsrl_is_os_component": [False, True],
        })
        frame = pd.DataFrame(
            {
                "filename": ["configured.bin", "upstream.bin"],
                "sha256_hash": [configured_hash, upstream_hash],
            },
            index=pd.date_range("2024-06-16T10:00:00Z", periods=2, freq="min"),
        )

        out = engine.apply_atomic(
            frame,
            nsrl_cache_df=cache,
            apply_profiling=False,
            enforce_required_fields=False,
        )

        self.assertEqual(
            out.iloc[0]["policy_nsrl_type"],
            "Configured Platform File",
        )
        self.assertTrue(bool(out.iloc[0]["policy_nsrl_os"]))
        self.assertTrue(bool(out.iloc[1]["policy_nsrl_os"]))
        self.assertNotIn("nsrl_application_type", out.columns)
        self.assertNotIn("nsrl_is_os_component", out.columns)
        self.assertTrue(
            {"policy_nsrl_type", "policy_nsrl_os"}.issubset(
                engine._configured_sidecar_output_columns()
            )
        )

    def test_nsrl_duckdb_view_is_policy_neutral_across_engines(self):
        configured_hash = "C" * 64
        frame = pd.DataFrame(
            {
                "filename": ["configured.bin"],
                "sha256_hash": [configured_hash],
            },
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            parquet_path = pathlib.Path(tmpdir) / "nsrl.parquet"
            pd.DataFrame({
                "sha256": [configured_hash],
                "nsrl_application_type": ["Configured Platform File"],
            }).to_parquet(parquet_path, index=False)

            matching_rules = deepcopy(BASE_RULES)
            matching_rules["profiling"]["hour_of_week"][
                "exclude_nsrl_application_type_contains"
            ] = ["Configured Platform"]
            matching = self._engine(matching_rules).apply_atomic(
                frame.copy(),
                nsrl_parquet_path=str(parquet_path),
                apply_profiling=False,
                enforce_required_fields=False,
            )

            nonmatching_rules = deepcopy(BASE_RULES)
            nonmatching_rules["profiling"]["hour_of_week"][
                "exclude_nsrl_application_type_contains"
            ] = ["Different Platform"]
            nonmatching = self._engine(nonmatching_rules).apply_atomic(
                frame.copy(),
                nsrl_parquet_path=str(parquet_path),
                apply_profiling=False,
                enforce_required_fields=False,
            )

        self.assertTrue(bool(matching.iloc[0]["nsrl_is_os_component"]))
        self.assertFalse(bool(nonmatching.iloc[0]["nsrl_is_os_component"]))

    def test_profile_multiplier_can_adjust_a_temporal_geo_output(self):
        engine = self._engine()
        frame = pd.DataFrame(
            {"hour_rarity": [0.5], "hour_of_week": [10]},
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )
        frame.attrs["_chronosift_quiet_hours_profile"] = frozenset()
        signal_map = {0: {"boundary_crossing": 1.0}}
        explain_map = {0: []}
        engine._apply_contextual_postprocessing_sparse(
            frame,
            signal_map,
            explain_map,
            apply_profiling=True,
        )
        self.assertEqual(signal_map[0]["boundary_crossing"], 1.25)
        self.assertNotIn("hour_rarity", signal_map[0])
        self.assertNotIn("quiet_time_event", signal_map[0])
        self.assertTrue(
            any(item["rule_id"] == "QUIET_TIME_BOUNDARY" for item in explain_map[0])
        )

        zero_frame = pd.DataFrame(
            {"hour_rarity": [0.0], "hour_of_week": [10]},
            index=frame.index,
        )
        zero_signal_map = {0: {"boundary_crossing": 1.0}}
        zero_explain_map = {0: []}
        engine._apply_contextual_postprocessing_sparse(
            zero_frame,
            zero_signal_map,
            zero_explain_map,
            apply_profiling=True,
        )
        self.assertEqual(zero_signal_map[0]["boundary_crossing"], 1.0)
        self.assertEqual(zero_explain_map[0], [])

    def test_trust_inputs_selectors_targets_and_metadata_are_config_authoritative(self):
        rules = deepcopy(BASE_RULES)
        trust = rules["engine_config"]["trust_dampening"]
        trust.update(
            {
                "enabled": True,
                "multiplier": 0.25,
                "signals": ["impossible_travel"],
                "trusted_actor_principals": ["trusted@example.test"],
            }
        )
        trust["inputs"] = {
            "principal_field": "policy_principal",
            "ip_field": "policy_ip",
            "asn_field": "policy_asn",
        }
        trust["explanation"].update(
            {
                "rule_id": "POLICY_TRUST",
                "description": "Configured trust metadata",
                "confidence": "low",
            }
        )
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [{"policy_principal": " Trusted@Example.Test ", "policy_ip": "", "policy_asn": ""}],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )
        signal_map = {0: {"impossible_travel": 1.0}}
        explain_map = {0: []}
        engine._apply_trust_dampening_sparse(frame, signal_map, explain_map)
        self.assertEqual(signal_map[0]["impossible_travel"], 0.25)
        self.assertEqual(explain_map[0][0]["rule_id"], "POLICY_TRUST")
        self.assertEqual(explain_map[0][0]["description"], "Configured trust metadata")
        self.assertEqual(explain_map[0][0]["confidence"], "low")

    def test_trust_selector_composition_and_reason_order_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        trust = rules["engine_config"]["trust_dampening"]
        trust.update(
            {
                "enabled": True,
                "signals": ["impossible_travel"],
                "trusted_actor_principals": ["alice"],
                "trusted_ips": ["192.0.2.10"],
                "selector_match": "all",
                "reason_precedence": [
                    "ip", "principal_literal", "principal_regex", "asn"
                ],
            }
        )
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [{"actor_principal": "alice", "ip_address": "192.0.2.11"}],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )
        signal_map = {0: {"impossible_travel": 1.0}}
        explain_map = {0: []}
        engine._apply_trust_dampening_sparse(frame, signal_map, explain_map)
        self.assertEqual(signal_map[0]["impossible_travel"], 1.0)

        any_rules = deepcopy(rules)
        any_rules["engine_config"]["trust_dampening"]["selector_match"] = "any"
        any_engine = self._engine(any_rules)
        both_frame = frame.copy()
        both_frame.loc[both_frame.index[0], "ip_address"] = "192.0.2.10"
        any_signals = {0: {"impossible_travel": 1.0}}
        any_explain = {0: []}
        any_engine._apply_trust_dampening_sparse(
            both_frame, any_signals, any_explain
        )
        self.assertEqual(any_signals[0]["impossible_travel"], 0.5)
        self.assertEqual(any_explain[0][0]["evidence"]["reason"], "trusted_ip")

    def test_unknown_adjustment_targets_and_empty_enabled_trust_fail(self):
        rules = deepcopy(BASE_RULES)
        rules["profile_multipliers"][0]["applies_to_signals"] = [
            "missing_profile_target"
        ]
        with self.assertRaisesRegex(
            ValueError, r"profile_multipliers.*missing_profile_target"
        ):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        rules["engine_config"]["trust_dampening"]["signals"] = [
            "missing_trust_target"
        ]
        with self.assertRaisesRegex(
            ValueError, r"trust_dampening\.signals.*missing_trust_target"
        ):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        trust = rules["engine_config"]["trust_dampening"]
        trust["enabled"] = True
        with self.assertRaisesRegex(ValueError, r"requires at least one trusted selector"):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        rules["engine_config"]["trust_dampening"]["reason_precedence"] = [
            "principal_literal", "principal_regex", "ip", "ip"
        ]
        with self.assertRaisesRegex(ValueError, r"reason_precedence"):
            self._engine(rules)

    def test_config_validation_and_weights_are_complete_strict_schemas(self):
        rules = deepcopy(BASE_RULES)
        profile = rules["profiling"]["hour_of_week"]
        profile["nsrl_is_os_component_field"] = profile[
            "nsrl_application_type_field"
        ]
        with self.assertRaisesRegex(
            ValueError,
            r"NSRL application-type and OS-component fields must differ",
        ):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        rules["engine_config"]["config_validation"]["legacy"] = True
        with self.assertRaisesRegex(
            ValueError, r"engine_config\.config_validation.*unknown key.*legacy"
        ):
            self._engine(rules)

        weights = deepcopy(BASE_WEIGHTS)
        del weights["max_event_score"]
        with self.assertRaisesRegex(
            ValueError, r"weights configuration.*max_event_score"
        ):
            self._engine(weights=weights)


if __name__ == "__main__":
    unittest.main()
