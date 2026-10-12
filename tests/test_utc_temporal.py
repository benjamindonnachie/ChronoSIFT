"""UTC calendar invariance across profiling, Parquet loading and DST."""
import importlib.util
from pathlib import Path
import sys
import tempfile
from copy import deepcopy
from datetime import timezone, timedelta
import unittest
from unittest import mock
import duckdb
import numpy as np
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('chronosift_utc_temporal', ROOT/'chronoSIFT_v2_31.py')
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

class UTCTemporalTests(unittest.TestCase):
    def test_new_and_cached_duckdb_sessions_enforce_utc(self):
        for cached in [False, True]:
            with self.subTest(cached=cached):
                con = duckdb.connect()
                try:
                    con.execute("SET TimeZone='Europe/London'")
                    with mock.patch.object(MODULE.ChronoSiftEngine, '_duckdb_conn', con if cached else None):
                        with mock.patch.object(MODULE.duckdb, 'connect', return_value=con):
                            actual = MODULE._get_duckdb_connection()
                        self.assertEqual(actual.execute("SELECT current_setting('TimeZone')").fetchone()[0], 'UTC')
                        hour, week = actual.execute("SELECT EXTRACT(hour FROM TIMESTAMPTZ '2024-06-02 23:30:00+00'), CAST(date_trunc('week',TIMESTAMPTZ '2024-06-02 23:30:00+00') AS VARCHAR)").fetchone()
                        self.assertEqual(hour, 23)
                        self.assertTrue(week.startswith('2024-05-27'))
                        actual.execute("SET TimeZone='Europe/London'")
                        self.assertEqual(MODULE._get_duckdb_connection().execute("SELECT current_setting('TimeZone')").fetchone()[0], 'UTC')
                finally:
                    con.close()

    def test_profile_index_uses_utc_across_both_dst_transitions(self):
        utc = pd.DatetimeIndex(['2024-03-31T00:30:00Z','2024-03-31T01:30:00Z',
                                '2024-06-02T23:30:00Z','2024-10-27T00:30:00Z','2024-10-27T01:30:00Z'])
        frame = pd.DataFrame({'value':range(5)}, index=utc.tz_convert('Europe/London'))
        actual = MODULE._ensure_datetime_series(frame)
        self.assertEqual(str(actual.dt.tz), 'UTC')
        self.assertEqual(actual.dt.hour.tolist(), [0,1,23,0,1])
        self.assertEqual(MODULE._hour_of_week(actual).tolist(), [144,145,167,144,145])
        pd.testing.assert_index_equal(frame.index, utc.tz_convert('Europe/London'))

    def test_restored_index_normalizes_timezone_without_losing_extended_dates(self):
        utc = pd.DatetimeIndex([pd.Timestamp('2024-06-02T23:30:00Z'),
                                pd.Timestamp('3850-06-18T19:12:00Z')]).as_unit('us')
        local = utc.tz_convert(timezone(timedelta(hours=2)))
        frame = pd.DataFrame({'chronosift_row_id':[1,2]}, index=local)
        restored = MODULE._restore_datetime_index(frame)
        pd.testing.assert_index_equal(restored.index, utc)
        pd.testing.assert_index_equal(frame.index, local)
        self.assertEqual(restored.index.unit, 'us')
        naive = frame.copy(); naive.index = naive.index.tz_localize(None)
        with self.assertRaisesRegex(ValueError, 'timezone-aware'):
            MODULE._restore_datetime_index(naive)

    def test_global_manifest_matches_utc_counts_across_dst(self):
        rules = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v27.yaml').read_text())
        policy = MODULE._parse_hour_of_week_profiling_policy(rules['profiling']['hour_of_week'])
        timestamps=[]
        for start in pd.date_range('2024-03-11T00:00:00Z', periods=12, freq='7D'):
            for offset in [pd.Timedelta(hours=9),pd.Timedelta(hours=23,minutes=30),pd.Timedelta(days=6,hours=23,minutes=30)]:
                timestamps.extend([start+offset]*50)
        frame=pd.DataFrame({'datetime':timestamps,'parser':['filestat']*len(timestamps),
                            'filename':['user-document.txt']*len(timestamps)})
        expected=np.zeros((10,168));expected[:,[9,23,167]]=50
        expected_manifest=MODULE._hour_of_week_manifest_from_weekly_counts(pd.DataFrame(expected),policy,
            selection_mode='filtered',used_filtered_subset=True,source_event_count=len(frame),selected_event_count=len(frame))
        con=duckdb.connect()
        try:
            con.execute("SET TimeZone='Europe/London'")
            with tempfile.TemporaryDirectory() as tmp:
                frame.to_parquet(Path(tmp)/'events.parquet',index=False)
                with mock.patch.object(MODULE.ChronoSiftEngine,'_duckdb_conn',con):
                    actual=MODULE.build_global_hour_of_week_manifest(tmp,policy)
            self.assertTrue(actual['validation']['accepted'])
            self.assertEqual(actual['validation']['complete_week_count'],10)
            self.assertEqual(actual['profile'],expected_manifest['profile'])
            self.assertEqual(actual['probabilities'],expected_manifest['probabilities'])
            self.assertEqual(actual['validation']['lower_confidence_bound'],expected_manifest['validation']['lower_confidence_bound'])
        finally:
            con.close()

if __name__=='__main__':
    unittest.main()
