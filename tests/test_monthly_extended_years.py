"""Permanent regressions for extended evidence dates in default monthly profiles."""
from pathlib import Path
import hashlib
import logging
import tempfile
import unittest
import duckdb
import numpy as np
import pandas as pd
import chronoSIFT_v2_31 as c
from tests import test_monthly_activity_profiles as monthly

ROOT = Path(c.__file__).resolve().parent

class MonthlyExtendedYearsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.getLogger().setLevel(logging.ERROR)
        cls.engine = c.ChronoSiftEngine.from_yaml(str(ROOT/'rules/rules_evidence_calibrated_v27.yaml'), str(ROOT/'rules/weights_evidence_calibrated_v23.yaml'))

    def case1(self):
        stamps = ['2024-06-01T02:00:00', '2024-06-01T02:01:00',
                  '23746-07-08T09:58:21.349921', '23746-07-08T09:58:21.349921',
                  '29326-09-27T09:38:54.530617', '29326-09-27T09:38:54.530617']
        frame = pd.DataFrame({'datetime': np.array(stamps, dtype='datetime64[us]'),
            'chronosift_row_id': np.arange(6, dtype=np.int64) + 2**53 + 1,
            'parser': ['filestat']*2 + ['utmp']*4,
            'timestamp_desc': ['Creation Time']*2 + ['Content Modification Time']*4,
            'filename': ['/home/a/report']*2 + ['/Windows/Fonts/consolab.ttf']*2 + ['/Windows/Fonts/consola.ttf']*2})
        frame['datetime'] = frame.datetime.dt.tz_localize('UTC')
        return frame

    def write_dataset(self, frame, root):
        for (year, month), part in frame.groupby([frame.datetime.dt.year, frame.datetime.dt.month]):
            folder = root/f'year={year}'/f'month={month}'
            folder.mkdir(parents=True)
            part.to_parquet(folder/'part.parquet', index=False)

    def test_case1_dates_preserved_and_normal_profiles_unchanged(self):
        normal = monthly.MonthlyActivityProfilesTest.fixture(self)
        normal.index = normal.index.as_unit('us')
        original = c.build_monthly_activity_manifest_from_frame(self.engine, normal)
        future = self.case1().iloc[2:].set_index('datetime')
        mixed = pd.concat([normal, future]).sort_index()
        before = mixed.copy(deep=True)
        manifest = c.build_monthly_activity_manifest_from_frame(self.engine, mixed)
        pd.testing.assert_frame_equal(mixed, before)
        self.assertEqual(manifest['source_event_count'], len(mixed))
        for month, profile in original['months'].items():
            self.assertEqual(profile, manifest['months'][month])
        for month in ['23746-07','23746-08','29326-09','29326-10']:
            for kind in ['filesystem','web']:
                self.assertFalse(manifest['months'][month][kind]['validation']['accepted'])
        applied = self.engine._apply_monthly_activity_profiling(future.copy(), manifest)
        np.testing.assert_array_equal(self.engine._profile_score_amplifier_values(applied), np.ones(4))
        pd.testing.assert_index_equal(applied.index, future.index)
        np.testing.assert_array_equal(applied.chronosift_row_id, future.chronosift_row_id)

    def test_wide_calendar_training_and_year_9999_rollover(self):
        rows = []
        for year, month in [(23746,5),(9999,12)]:
            for day in range(23,29):
                for hour in range(24):
                    for _ in range(8 if 9 <= hour < 22 else 1):
                        rows.append((np.datetime64(f'{year}-{month:02d}-{day:02d}T{hour:02d}:00','us'), 'text/apache_access', 'GET / HTTP/1.1', 200))
        frame = pd.DataFrame(rows, columns=['datetime','parser','http_request','http_response_code'])
        frame['datetime'] = pd.DatetimeIndex(np.array(frame.datetime, dtype='datetime64[us]')).tz_localize('UTC')
        manifest = c.build_monthly_activity_manifest_from_frame(self.engine, frame)
        for key, training in [('23746-06','23746-05'),('10000-01','9999-12')]:
            web = manifest['months'][key]['web']
            self.assertTrue(web['validation']['accepted'])
            self.assertEqual(web['training']['month'], training)
            self.assertEqual(web['training']['selected_event_count'], 4*(13*8+11))

    def test_real_parquet_manifest_matches_frame_and_cache_roundtrip(self):
        frame = self.case1()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'source'
            self.write_dataset(frame, root)
            before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('year=*/month=*/*.parquet')}
            expected = c.build_monthly_activity_manifest_from_frame(self.engine, frame)
            got = c.build_monthly_activity_manifest(self.engine, str(root))
            self.assertEqual(expected['months'], got['months'])
            self.assertEqual(got['source_event_count'], 6)
            cache = Path(temp)/'manifest.json'
            c.save_profile_manifest(got, str(cache))
            restored = c.load_profile_manifest(str(cache))
            self.assertTrue(c._monthly_manifest_matches(restored, got['fingerprint']))
            self.assertEqual(got['months'], restored['months'])
            self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('year=*/month=*/*.parquet')})

    def test_default_partitioned_engine_preserves_every_extended_event(self):
        with tempfile.TemporaryDirectory() as temp:
            root, output = Path(temp)/'source', Path(temp)/'sidecar'
            self.write_dataset(self.case1(), root)
            manifest = Path(temp)/'monthly.json'
            reports = self.engine.process_parquet_dataset_partitioned(str(root),str(output),output_mode='sidecar',profile_manifest_path=str(manifest))
            self.assertTrue(reports)
            self.assertEqual({int(r['year']) for r in reports}, {2024,23746,29326})
            self.assertEqual(c.load_profile_manifest(str(manifest))['source_event_count'],6)
            db = duckdb.connect()
            try:
                raw = db.read_parquet(str(root/'year=*/month=*/*.parquet'),union_by_name=True).create_view('raw')
                db.read_parquet(str(output/'year=*/month=*/*.parquet'),union_by_name=True).create_view('scored')
                self.assertEqual(db.execute('SELECT count(*) FROM scored').fetchone()[0],6)
                self.assertEqual(db.execute('SELECT count(*) FROM raw r FULL JOIN scored s USING(chronosift_row_id) WHERE r.chronosift_row_id IS NULL OR s.chronosift_row_id IS NULL OR r.datetime IS DISTINCT FROM s.datetime').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT count(*) FROM scored WHERE year(datetime)>9999 AND (out_of_hours_activity_deficit<>0 OR chronosift_web_quiet_multiplier<>1)').fetchone()[0],0)
            finally:
                db.close()
