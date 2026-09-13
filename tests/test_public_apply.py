"""F07: public whole-frame API contracts, not only separately invoked stages."""
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
from maxminddb.errors import InvalidDatabaseError
import chronoSIFT_v2_31 as c
from run_chronosift_sidecar_cli import build_arg_parser
from tests.test_geoip_failures import readers
from tests.test_v231_behaviour_policy import file, http, sudo
from tests.test_v231_linux_account_context import frame as linux, birth, auth
from tests.test_v231_windows_scoring import frame as windows, creation, grant, account, SID


class PublicApplyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.metadata = Path(cls.temp.name) / 'fixture.yar'
        cls.metadata.write_text('rule TEST_UNUSED { condition: false }\n')
        cls.args = build_arg_parser().parse_args(['input', 'output'])
        cls.level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        logging.getLogger().setLevel(cls.level)

    def engine(self):
        return c.ChronoSiftEngine.from_yaml(self.args.rules_yaml, self.args.weights_yaml,
                                          yara_metadata_path=str(self.metadata))

    def assert_accounting(self, out):
        for score, items in zip(out.chronosift_score, out.chronosift_explain):
            items = [] if items is None or items is pd.NA else items
            self.assertAlmostEqual(score, min(50, sum(item['score_contribution'] for item in items)))

    def test_actual_apply_equals_manual_stage_composition_on_three_behaviours(self):
        factories = {
            'linux': lambda: linux([('0s', birth(uid=0)), ('1s', auth()), ('2s', sudo())]),
            'windows': lambda: windows([creation(), grant(),
                ('1d', account(4698, task_name='Maintenance', win_subject_sid=SID))]),
            'web': lambda: linux([('0s', file('/srv/site/export.sql', luhn_hit=True, file_size=6000000)),
                ('1s', http('/export.sql', 'GET', 200)),
                ('2s', http('/?id=1%20UNION%20SELECT%20password', 'GET', 500))]),
        }
        for name, factory in factories.items():
            with self.subTest(behaviour=name):
                direct = self.engine().apply(factory(), apply_profiling=False)
                staged_engine = self.engine()
                atomic = staged_engine.apply_atomic(factory(), apply_profiling=False,
                                                     materialise_event_columns=False)
                staged = staged_engine.apply_contextual(atomic, apply_profiling=False)
                pd.testing.assert_frame_equal(direct, staged)
                self.assertGreater(direct.chronosift_score.max(), 0)
                self.assert_accounting(direct)
                self.assertEqual(direct.attrs['chronosift_metadata']['geoip'], {'city': None, 'asn': None})

    def test_default_profiling_and_temporal_options_equal_manual_stages(self):
        factory = lambda: linux([('0s', birth()), ('1h', auth()), ('1h1s', sudo())])
        direct = self.engine().apply(factory())
        engine = self.engine()
        staged = engine.apply_contextual(engine.apply_atomic(factory(), materialise_event_columns=False))
        pd.testing.assert_frame_equal(direct, staged)
        self.assert_accounting(direct)

    def test_all_options_forwarded_by_identity_and_metadata_recorded(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                engine = self.engine()
                source, atomic, output = pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
                cache = pd.DataFrame({'sha256': ['fixture']})
                profile, hits = {'profile': 'fixture'}, {'hits': 'fixture'}
                options = dict(apply_temporal=enabled, apply_profiling=enabled,
                    enforce_required_fields=enabled, materialise_event_columns=enabled,
                    geoip_city_db='city.mmdb', geoip_asn_db='asn.mmdb',
                    av_csv_path='av.csv', luhn_csv_path='luhn.csv',
                    nsrl_parquet_path='nsrl.parquet', nsrl_cache_df=cache,
                    profile_manifest=profile, file_hit_manifest=hits)
                with patch.object(engine, 'apply_atomic', return_value=atomic) as first, \
                     patch.object(engine, 'apply_contextual', return_value=output) as second, \
                     patch.object(c, '_geoip_db_metadata', side_effect=lambda path: {'path': path}):
                    result = engine.apply(source, **options)
                self.assertIs(result, output)
                self.assertIs(first.call_args.args[0], source)
                self.assertIs(second.call_args.args[0], atomic)
                first.assert_called_once()
                second.assert_called_once()
                self.assertEqual(set(first.call_args.kwargs), set(options) - {'apply_temporal', 'file_hit_manifest'})
                for name, value in first.call_args.kwargs.items():
                    self.assertIs(value, False if name == 'materialise_event_columns' else options[name])
                self.assertEqual(set(second.call_args.kwargs),
                                 {'apply_temporal', 'apply_profiling', 'materialise_event_columns', 'file_hit_manifest'})
                for name, value in second.call_args.kwargs.items():
                    self.assertIs(value, options[name])
                self.assertEqual(result.attrs['chronosift_metadata'], {
                    'geoip': {'city': {'path': 'city.mmdb'}, 'asn': {'path': 'asn.mmdb'}},
                    'enrichment': {'av_csv_path': 'av.csv', 'luhn_csv_path': 'luhn.csv',
                                   'nsrl_parquet_path': 'nsrl.parquet'}})

    def test_sparse_output_can_be_materialised_without_rescoring(self):
        factory = lambda: linux([('0s', birth(uid=0)), ('1s', auth()), ('2s', sudo())])
        dense = self.engine().apply(factory(), apply_profiling=False)
        engine = self.engine()
        sparse = engine.apply(factory(), apply_profiling=False, materialise_event_columns=False)
        state = sparse.attrs['chronosift_sparse']
        self.assertIsInstance(state['signal_map'], dict)
        self.assertIsInstance(state['explain_map'], dict)
        engine._materialise_sparse_event_columns(sparse, state['signal_map'], state['explain_map'])
        fields = ['chronosift_row_id', 'chronosift_score', 'chronosift_signals', 'chronosift_explain']
        pd.testing.assert_frame_equal(dense[fields], sparse[fields])

    def test_tied_nanosecond_timestamps_and_large_integer_ids_survive(self):
        frame = linux([('0s', birth(uid=0)), ('0s', auth()), ('1ns', sudo())])
        frame['chronosift_row_id'] = np.array([2**60+1, 2**60+2, 2**60+3], dtype=np.int64)
        expected_index = frame.index
        expected_ids = frame.chronosift_row_id.tolist()
        out = self.engine().apply(frame, apply_profiling=False)
        pd.testing.assert_index_equal(out.index, expected_index)
        self.assertEqual(out.chronosift_row_id.tolist(), expected_ids)
        self.assertTrue(out.chronosift_row_id.is_unique)

    def test_wide_forensic_timestamps_survive_whole_frame_api(self):
        frame = pd.DataFrame({'parser': ['filestat', 'filestat'],
            'filename': ['/ordinary/a.txt', '/ordinary/b.txt'], 'chronosift_row_id': [1, 2]},
            index=pd.DatetimeIndex(np.array(['1500-01-01', '2500-01-01'], dtype='datetime64[us]'),
                                   tz='UTC', name='datetime'))
        expected = frame.index
        out = self.engine().apply(frame, apply_profiling=False)
        pd.testing.assert_index_equal(out.index, expected)
        self.assertEqual(out.chronosift_row_id.tolist(), [1, 2])

    def test_empty_frame_is_supported(self):
        frame = pd.DataFrame(index=pd.DatetimeIndex([], tz='UTC', name='datetime'))
        out = self.engine().apply(frame)
        self.assertTrue(out.empty)
        self.assertIn('chronosift_score', out)
        self.assertIn('chronosift_metadata', out.attrs)

    def test_atomic_and_contextual_errors_are_not_hidden(self):
        for failing_stage in ('apply_atomic', 'apply_contextual'):
            with self.subTest(stage=failing_stage):
                engine = self.engine()
                error = RuntimeError('Stage failed')
                with patch.object(engine, 'apply_atomic', return_value=pd.DataFrame()) as first, \
                     patch.object(engine, 'apply_contextual', return_value=pd.DataFrame()) as second:
                    (first if failing_stage == 'apply_atomic' else second).side_effect = error
                    with self.assertRaises(RuntimeError) as raised:
                        engine.apply(pd.DataFrame())
                    self.assertIs(raised.exception, error)
                    if failing_stage == 'apply_atomic':
                        second.assert_not_called()

    def test_real_apply_surfaces_geoip_failure(self):
        city, asn = readers()
        error = InvalidDatabaseError('Broken City record')
        city.city.side_effect = error
        with patch.object(c.geoip2_database, 'Reader', side_effect=[city, asn]):
            with self.assertRaises(InvalidDatabaseError) as raised:
                self.engine().apply(linux([('0s', auth(ip='8.8.8.8'))]), apply_profiling=False,
                                    geoip_city_db='city.mmdb', geoip_asn_db='asn.mmdb')
        self.assertIs(raised.exception, error)
        city.close.assert_called_once_with()
        asn.close.assert_called_once_with()
