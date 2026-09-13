"""YAML-only recent-client/geographic sensitive-transfer context."""
from pathlib import Path
import logging
import tempfile
import unittest

import pandas as pd
import yaml

import chronoSIFT_v2_31 as c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'rules/rules_evidence_calibrated_v12.yaml'
WEIGHTS = ROOT / 'rules/weights_evidence_calibrated_v11.yaml'
START = pd.Timestamp('2024-06-30T23:00:00Z')
CLIENT = '123.7.220.100'
OLD_CLIENT = '8.8.8.8'
RECENT = 'web_recent_client_sensitive_download'
GEO = 'web_recent_geo_sensitive_download'
FIRST = 'web_client_first_observed'
TRANSFER = 'web_external_sensitive_transfer'


def event(offset, ip=CLIENT, country=None, asn=None, host='web1', parser='text/apache_access'):
    return {'time': START + pd.Timedelta(offset), 'chronosift_web_source_ip': ip,
            'geo_country_iso': country, 'geo_asn': asn, 'hostname': host, 'parser': parser}


class WebClientContextTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(logging.getLogger().setLevel, logging.getLogger().level)
        logging.getLogger().setLevel(logging.ERROR)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.metadata = Path(self.temp.name) / 'fixture.yar'
        self.metadata.write_text('rule TEST_UNUSED { condition: false }\n')
        self.engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS,
                                                  yara_metadata_path=str(self.metadata))

    def run_events(self, rows, transfers=()):
        frame = pd.DataFrame(rows).set_index('time')
        frame.index.name = 'datetime'
        frame['chronosift_row_id'] = range(len(frame))
        frame = self.engine._apply_normalisation(frame)
        signals = {pos: {TRANSFER: 1} for pos in transfers}
        explanations = {}
        self.engine._apply_temporal_rules_sparse(frame, signals, explanations)
        self.engine._apply_policy_signal_projections_sparse(signals, explanations, stage='temporal')
        return frame, signals, explanations

    def test_only_new_configuration_sections_and_weights_change(self):
        old = yaml.safe_load((ROOT / 'rules/rules_evidence_calibrated_v11.yaml').read_text())
        new = yaml.safe_load(RULES.read_text())
        self.assertEqual(new['normalisation'][2:], old['normalisation'])
        self.assertEqual(new['temporal_rules'][6:], old['temporal_rules'])
        for key in old.keys() - {'normalisation', 'temporal_rules', 'detector_policy'}:
            self.assertEqual(new[key], old[key], key)
        detectors = dict(new['detector_policy']['detectors'])
        projection = detectors.pop('web_recent_geo_download_projection')
        self.assertEqual(detectors, old['detector_policy']['detectors'])
        self.assertEqual(projection['evidence_type'], 'contextual')
        old_weights = yaml.safe_load((ROOT / 'rules/weights_evidence_calibrated_v10.yaml').read_text())
        new_weights = yaml.safe_load(WEIGHTS.read_text())
        expected = dict(old_weights['weights'])
        expected.update(web_client_first_observed=0, web_country_first_observed=0,
                        web_asn_first_observed=0, web_recent_client_sensitive_download=8,
                        web_recent_geo_sensitive_download=3,
                        web_recent_country_sensitive_download=0,
                        web_recent_asn_sensitive_download=0)
        self.assertEqual(new_weights, {**old_weights, 'weights': expected})

    def test_recent_client_still_qualifies_after_many_requests(self):
        rows = [event(f'{i}s') for i in range(2000)] + [event('54m52s')]
        _, signals, explanations = self.run_events(rows, [2000])
        self.assertEqual(signals[0][FIRST], 1)
        self.assertEqual(sum(bool(s.get(FIRST)) for s in signals.values()), 1)
        self.assertEqual(signals[2000][RECENT], 1)
        self.assertNotIn(GEO, signals[2000])
        self.assertEqual(self.engine._score_signals(signals[2000]), 8)
        self.assertIn(CLIENT, explanations[2000][-1]['evidence']['key'])

    def test_two_hour_boundary_is_inclusive_and_activity_does_not_reset_age(self):
        _, signals, _ = self.run_events(
            [event('0s'), event('1h59m'), event('2h'), event('2h1ns')], [2, 3])
        self.assertEqual(signals[2][RECENT], 1)
        self.assertNotIn(RECENT, signals[3])

    def test_six_hour_history_boundary_and_return_after_absence(self):
        for offset, expected in [('6h', False), ('6h1ns', True)]:
            with self.subTest(offset=offset):
                _, signals, _ = self.run_events([event('0s'), event(offset)], [1])
                self.assertEqual(bool(signals[1].get(RECENT)), expected)

    def test_known_client_is_not_new_because_another_client_intervenes(self):
        _, signals, _ = self.run_events(
            [event('-3h'), event('-1h', ip=OLD_CLIENT), event('0s')], [2])
        self.assertNotIn(FIRST, signals[2])
        self.assertNotIn(RECENT, signals[2])

    def test_first_request_download_can_qualify_but_cold_geo_is_suppressed(self):
        _, signals, _ = self.run_events([event('0s', country='CN', asn=4837)], [0])
        self.assertEqual(signals[0][RECENT], 1)
        self.assertNotIn(GEO, signals[0])
        self.assertNotIn('web_country_first_observed', signals[0])

    def test_country_and_asn_corroboration_score_once(self):
        frame, signals, explanations = self.run_events([
            event('-1h', ip=OLD_CLIENT, country='GB', asn=64500),
            event('0s', country='CN', asn=4837),
            event('55m', country='CN', asn=4837),
        ], [2])
        self.assertEqual(signals[2][RECENT], 1)
        self.assertEqual(signals[2][GEO], 1)
        self.assertEqual(self.engine._score_signals(signals[2]), 11)
        self.engine._materialise_sparse_event_columns(frame, signals, explanations)
        details = frame.chronosift_explain.iloc[2]
        self.assertEqual(sum(item['score_contribution'] for item in details), 11)
        scored_geo = [item for item in details if item['rule_id'] == 'WEB_RECENT_GEO_SENSITIVE_DOWNLOAD']
        self.assertEqual(len(scored_geo), 1)
        self.assertEqual(scored_geo[0]['score_contribution'], 3)
        self.assertEqual(scored_geo[0]['evidence_type'], 'contextual')
        self.assertEqual(set(scored_geo[0]['evidence']['derived_from'].split(',')),
                         {'web_recent_country_sensitive_download', 'web_recent_asn_sensitive_download'})

    def test_country_alone_can_corroborate_without_asn(self):
        _, signals, _ = self.run_events([
            event('-1h', ip=OLD_CLIENT, country='GB'), event('0s', country='CN'),
            event('55m', country='CN'),
        ], [2])
        self.assertEqual(signals[2][GEO], 1)

    def test_known_country_and_asn_do_not_gain_bonus_for_new_ip(self):
        _, signals, _ = self.run_events([
            event('-1h', ip=OLD_CLIENT, country='CN', asn=4837),
            event('0s', country='CN', asn=4837), event('55m', country='CN', asn=4837),
        ], [2])
        self.assertEqual(signals[2][RECENT], 1)
        self.assertNotIn(GEO, signals[2])

    def test_no_country_specific_risk_weight(self):
        for country in ('CN', 'GB', 'US', 'DE'):
            with self.subTest(country=country):
                _, signals, _ = self.run_events([
                    event('-1h', ip=OLD_CLIENT, country='FR', asn=64500),
                    event('0s', country=country, asn=4837),
                    event('55m', country=country, asn=4837),
                ], [2])
                self.assertEqual(self.engine._score_signals(signals[2]), 11)

    def test_non_transfer_rows_do_not_inherit_contextual_points(self):
        _, signals, _ = self.run_events(
            [event('0s'), event('55m'), event('56m'), event('57m', ip=OLD_CLIENT)], [1])
        self.assertEqual(signals[1][RECENT], 1)
        for pos in (0, 2, 3):
            self.assertEqual(self.engine._score_signals(signals.get(pos, {})), 0)

    def test_context_does_not_cross_host_or_parser_stream(self):
        for changed in ({'host': 'web2'}, {'parser': 'text/nginx_access'}):
            with self.subTest(changed=changed):
                _, signals, _ = self.run_events([
                    event('-3h', **changed), event('0s'), event('55m', **changed),
                ], [2])
                self.assertNotIn(RECENT, signals[2])

    def test_non_web_and_empty_client_do_not_acquire_web_context(self):
        for changed in ({'parser': 'syslog'}, {'ip': ''}, {'ip': None}):
            with self.subTest(changed=changed):
                _, signals, _ = self.run_events([event('0s', **changed), event('55m', **changed)], [1])
                self.assertNotIn(RECENT, signals[1])

    def test_missing_hostname_uses_dataset_parser_stream_without_inventing_actor(self):
        frame, signals, _ = self.run_events([event('0s', host=None), event('55m', host=None)], [1])
        self.assertEqual(signals[1][RECENT], 1)
        self.assertEqual(frame.chronosift_web_history_asset.iloc[0], 'text/apache_access')
        self.assertFalse(frame.actor_principal.notna().any())

    def test_tied_nanosecond_timestamps_keep_separate_integer_ids(self):
        frame, signals, _ = self.run_events([event('1ns'), event('1ns')], [1])
        self.assertEqual(frame.chronosift_row_id.tolist(), [0, 1])
        self.assertEqual(signals[1][RECENT], 1)

    def test_month_boundary_with_standard_overlap_matches_continuous_context(self):
        rows = [event('-25h', ip=OLD_CLIENT), event('-23h'), event('-1h'), event('1h')]
        _, full, _ = self.run_events(rows, [3])
        _, window, _ = self.run_events(rows[1:], [2])
        self.assertEqual(full[3], window[2])
        self.assertEqual(full[3][RECENT], 1)

    def test_existing_overlap_guard_rejects_insufficient_context_before_output(self):
        output = Path(self.temp.name) / 'absent-output'
        with self.assertRaisesRegex(ValueError, 'Partition overlap must be at least'):
            self.engine.process_parquet_dataset_partitioned(
                'absent-input', str(output), overlap='10h', output_mode='sidecar')
        self.assertFalse(output.exists())

    def test_real_qualification_excludes_failed_post_private_and_unlinked_requests(self):
        rows = [
            {'parser': 'filestat', 'filename': '/var/www/html/dump.sql',
             'timestamp_desc': 'Creation Time', 'luhn_hit': True},
            {'parser': 'text/apache_access', 'http_request': 'GET / HTTP/1.1',
             'http_response_code': 200, 'ip_address': CLIENT},
        ]
        for method, path, status, ip in [
            ('GET', '/dump.sql', 200, CLIENT), ('GET', '/dump.sql', 404, CLIENT),
            ('POST', '/dump.sql', 200, CLIENT), ('GET', '/ordinary.sql', 200, CLIENT),
            ('GET', '/dump.sql', 200, '10.0.0.1'),
        ]:
            rows.append({'parser': 'text/apache_access', 'http_request': f'{method} {path} HTTP/1.1',
                         'http_response_code': status, 'http_response_bytes': 15000000,
                         'ip_address': ip})
        frame = pd.DataFrame(rows, index=pd.date_range(START, periods=len(rows), freq='min'))
        frame.index.name = 'datetime'
        frame['chronosift_row_id'] = range(len(frame))
        dataset = Path(self.temp.name) / 'input'
        part = dataset / 'year=2024/month=6'
        part.mkdir(parents=True)
        frame.to_parquet(part / 'part.parquet')
        manifest = c.build_global_referenced_file_hit_manifest(
            str(dataset), yara_metadata_path=str(self.metadata),
            yara_metadata_index=self.engine.yara_metadata_index,
            clamav_classifier_policy=self.engine.detector_policy.clamav_classification,
            yara_classifier_policy=self.engine.detector_policy.yara_classification,
            referenced_file_policy=self.engine.detector_policy.referenced_file_correlation)
        output = self.engine.apply_contextual(self.engine.apply_atomic(frame, apply_profiling=False),
                                               apply_profiling=False, file_hit_manifest=manifest)
        self.assertEqual((output.chronosift_signals.iloc[2] or {}).get(RECENT), 1)
        for pos in (0, 1, 3, 4, 5, 6):
            self.assertNotIn(RECENT, output.chronosift_signals.iloc[pos] or {})
        for score, explanation in zip(output.chronosift_score, output.chronosift_explain):
            self.assertAlmostEqual(float(score), min(50, sum(e.get('score_contribution', 0)
                                                            for e in (explanation or []))))


if __name__ == '__main__':
    unittest.main()
