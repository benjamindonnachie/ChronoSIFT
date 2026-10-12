"""Causal native monthly profiles, web admission and pipeline cache parity."""
import copy
import hashlib
import json
import logging
from pathlib import Path
import tempfile
import unittest
import numpy as np
import pandas as pd
import chronoSIFT_v2_31 as c

ROOT = Path(c.__file__).resolve().parent

class MonthlyActivityProfilesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.getLogger().setLevel(logging.ERROR)
        cls.engine = c.ChronoSiftEngine.from_yaml(str(ROOT/'rules/rules_evidence_calibrated_v27.yaml'), str(ROOT/'rules/weights_evidence_calibrated_v23.yaml'))

    def fixture(self):
        rows=[]
        # Interior complete weeks in January; OS traffic dominates overnight
        # but must never populate either profile.
        for day in pd.date_range('2024-01-01','2024-01-31',tz='UTC'):
            for hour in range(24):
                for _ in range(4 if 9<=hour<17 else 0):
                    rows.append(dict(datetime=day+pd.Timedelta(hours=hour),parser='filestat',filename='/home/a/report',nsrl_is_os_component=False))
                rows.append(dict(datetime=day+pd.Timedelta(hours=hour),parser='filestat',filename='/os',nsrl_is_os_component=True))
        # Seven days of retained logs. Boundary days excluded; fixed first four.
        for day in pd.date_range('2024-05-23','2024-05-29',tz='UTC'):
            for hour in range(24):
                for _ in range(8 if 9<=hour<22 else 1):
                    rows.append(dict(datetime=day+pd.Timedelta(hours=hour),parser='text/apache_access',http_request='GET / HTTP/1.1',http_response_code=200))
        for status in [200,206,404,500]:
            rows.append(dict(datetime=pd.Timestamp('2024-06-01T02:00Z'),parser='text/apache_access',http_request='GET /shell.php HTTP/1.1',http_response_code=status))
        rows += [dict(datetime=pd.Timestamp('2024-02-01T02:00Z'),parser='filestat',filename='/home/a/evidence'),
                 dict(datetime=pd.Timestamp('2024-07-01T02:00Z'),parser='text/apache_access',http_request='GET /shell.php HTTP/1.1',http_response_code=500)]
        frame=pd.DataFrame(rows).set_index('datetime').sort_index()
        frame.index.name='datetime';frame['chronosift_row_id']=np.arange(len(frame))+100
        return frame

    def bundle(self,frame=None):
        return c.build_monthly_activity_manifest_from_frame(self.engine,self.fixture() if frame is None else frame)

    def test_previous_month_filesystem_nsrl_and_no_fallback(self):
        b=self.bundle();jan=b['months']['2024-02']['filesystem']
        self.assertTrue(jan['validation']['accepted'])
        self.assertEqual(jan['selected_event_count'],31*8*4)
        self.assertEqual(jan['training']['month'],'2024-01')
        self.assertEqual(len(jan['training']['selected_blocks']),4)
        self.assertFalse(b['months']['2024-01']['filesystem']['validation']['accepted'])
        self.assertFalse(b['months']['2024-03']['filesystem']['validation']['accepted'])

    def test_web_fixed_window_exact_200_and_causality(self):
        f=self.fixture();b=self.bundle(f);w=b['months']['2024-06']['web']
        self.assertTrue(w['validation']['accepted'])
        self.assertEqual(w['validation']['complete_day_count'],4)
        self.assertNotIn('complete_week_count',w['validation'])
        self.assertEqual(w['training']['selected_blocks'],[str(x) for x in pd.date_range('2024-05-24',periods=4,tz='UTC')])
        self.assertEqual(w['training']['selected_event_count'],4*(13*8+11))
        extra=f.copy();extra.loc[extra.index.month==6,'http_response_code']=200
        self.assertEqual(w,self.bundle(extra)['months']['2024-06']['web'])
        variant=f.copy();variant.loc[variant.index.month==5,'http_response_code']=206
        self.assertFalse(self.bundle(variant)['months']['2024-06']['web']['validation']['accepted'])

    def test_application_all_statuses_training_only_os_utc_expiry_zero_and_cap(self):
        b=self.bundle();f=self.fixture();test=f.loc[f.index.month==6].copy();test['nsrl_is_os_component']=True
        applied=self.engine._apply_hour_of_week_profiling(test,profile_manifest=b)
        factors=self.engine._profile_score_amplifier_values(applied)
        self.assertTrue((factors>1).all());np.testing.assert_array_equal(factors,np.repeat(factors[0],4))
        scores=self.engine._score_signal_map_sparse(4,{0:{'web_shell_name_probe':1},1:{'web_shell_name_probe':50}},index=test.index,score_multipliers=factors)
        self.assertEqual(scores.iloc[2],0);self.assertLessEqual(scores.max(),50)
        expired=self.engine._apply_hour_of_week_profiling(f.loc[f.index.month==7].copy(),profile_manifest=b)
        self.assertEqual(expired.chronosift_web_quiet_multiplier.iloc[0],1)
        offset=test.copy();offset.index=offset.index.tz_convert('America/New_York')
        np.testing.assert_array_equal(factors,self.engine._profile_score_amplifier_values(self.engine._apply_hour_of_week_profiling(offset,profile_manifest=b)))

    def test_iis_raw_http_status_training_and_legacy_status_fallback(self):
        apache=self.fixture()
        reference=self.bundle(apache)['months']['2024-06']['web']
        iis=apache.copy()
        selected=iis['parser'].eq('text/apache_access')
        iis.loc[selected,'parser']='text/winiis'
        iis['http_method']=np.where(selected,'GET',None)
        iis['requested_uri_stem']=np.where(selected,'/shell.php',None)
        iis['http_status']=iis['http_response_code']
        iis=iis.drop(columns=['http_request','http_response_code'])
        got=self.bundle(iis)['months']['2024-06']['web']
        self.assertEqual(reference,got)
        legacy=iis.rename(columns={'http_status':'sc_status','requested_uri_stem':'cs_uri_stem'})
        self.assertEqual(reference,self.bundle(legacy)['months']['2024-06']['web'])
        applied=self.engine._apply_hour_of_week_profiling(iis.loc[iis.index.month==6].copy(),profile_manifest=self.bundle(iis))
        self.assertTrue((applied.chronosift_web_quiet_multiplier>1).all())
        self.assertIn('http_status',self.engine._atomic_required_columns())
        self.assertIn('sc_status',self.engine._atomic_required_columns())

    def test_numeric_month_selection_nat_leap_year_and_extended_years(self):
        frame=pd.DataFrame(index=pd.DatetimeIndex(['2024-02-29T23:59Z',None,'2024-03-01T00:00Z']))
        np.testing.assert_array_equal(c._profile_month_codes(c._ensure_datetime_series(frame)),[202402,0,202403])
        future=pd.DataFrame(index=pd.date_range('3850-12-31T23:59Z',periods=2,freq='min').as_unit('us'))
        np.testing.assert_array_equal(c._profile_month_codes(c._ensure_datetime_series(future)),[385012,385101])

    def test_other_parsers_iis_request_and_missing_fields(self):
        m=self.engine.monthly_profiling_policy
        df=pd.DataFrame([dict(parser='text/apache_access',http_request='GET / HTTP/1.1'),dict(parser='text/apache_error',http_request='GET / HTTP/1.1'),dict(parser='text/winiis',http_method='GET',cs_uri_stem='/'),dict(parser='text/winiis',http_method='GET'),dict(parser='text/apache_access',http_request='-')])
        np.testing.assert_array_equal(c._monthly_web_request_mask(df,m),[True,False,True,False,False])
        df['http_request']=pd.array([None]*5,dtype='Int32')
        self.assertFalse(c._monthly_web_request_mask(df,m)[0])

    def test_observed_zero_success_days_and_missing_days(self):
        f=self.fixture();f.loc[(f.index.month==5)&(f.index.day==25),'http_response_code']=500
        w=self.bundle(f)['months']['2024-06']['web']
        self.assertEqual(len(w['training']['selected_blocks']),4)
        missing=f[~((f.index.month==5)&(f.index.day==25))]
        self.assertEqual(self.bundle(missing)['months']['2024-06']['web']['training']['selected_blocks'],[])

    def test_weekly_validator_numeric_compatibility_and_daily_shared_bounds(self):
        rng=np.random.default_rng(71);counts=rng.integers(1,500,(4,168))
        kwargs=dict(alpha=1,minimum_complete_weeks=3,confidence_level=.95,bootstrap_resamples=2000,random_seed=0,amplification_gate='require_positive_activity_deficit')
        a=c._validate_weekly_hour_profile(pd.DataFrame(counts),**kwargs)
        b=c._validate_weekly_hour_profile(pd.DataFrame(counts),period_bins=168,**kwargs)
        for key in a:
            np.testing.assert_equal(a[key],b[key])
        daily=np.tile([1]*9+[100]*13+[1]*2,(4,1))
        d=c._validate_weekly_hour_profile(pd.DataFrame(daily),period_bins=24,**kwargs)
        self.assertTrue(d['accepted']);self.assertEqual(len(d['activity_deficits']),24)

    def test_strict_configuration_and_manifest_bounds(self):
        base=copy.deepcopy(self.engine.rules_doc['profiling']['monthly'])
        for patch in [dict(web_training_window_days=True),dict(web_training_window_days=2),dict(web_minimum_complete_days=5),dict(enabled=False),dict(parser_adapters={'bad':'anything'}),dict(status_fields={'apache':[],'iis':['http_status']}),dict(extra=True)]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):c._parse_monthly_profiling_policy(base|patch)
        with self.assertRaises(ValueError):c._profile_bin_array({'profile':{'0':float('nan')}},24)

    def test_parquet_matches_memory_cache_tamper_and_nsrl_lookup(self):
        f=self.fixture()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'source'
            for (y,m),part in f.groupby([f.index.year,f.index.month]):
                dest=root/f'year={y}'/f'month={m}';dest.mkdir(parents=True)
                part.to_parquet(dest/'part.parquet')
            expected=self.bundle(f);got=c.build_monthly_activity_manifest(self.engine,str(root))
            self.assertEqual(expected['months'],got['months'])
            path=Path(temp)/'profile.json';c.save_profile_manifest(got,str(path));loaded=c.load_profile_manifest(str(path))
            self.assertTrue(c._monthly_manifest_matches(loaded,got['fingerprint']))
            loaded['months']['2024-06']['web']['profile']['2']=.99
            self.assertFalse(c._monthly_manifest_matches(loaded,got['fingerprint']))
            (root/'year=2024/month=6/changed.parquet').write_bytes((root/'year=2024/month=6/part.parquet').read_bytes())
            self.assertNotEqual(got['fingerprint'],c._monthly_profile_fingerprint(self.engine,str(root)))
            # Raw NSRL-unlabelled filesystem records must still be excluded.
            raw=f.drop(columns=['nsrl_is_os_component']);raw['sha256_hash']='a'*64
            root2=Path(temp)/'raw';root2.mkdir();raw.to_parquet(root2/'part.parquet')
            nsrl=Path(temp)/'nsrl.parquet';pd.DataFrame({'sha256':['A'*64], 'nsrl_application_type':['Operating System'],'nsrl_is_os_component':[False]}).to_parquet(nsrl,index=False)
            filtered=c.build_monthly_activity_manifest(self.engine,str(root2),str(nsrl))
            self.assertFalse(filtered['months']['2024-02']['filesystem']['validation']['accepted'])

    def test_web_profile_owns_request_scope_without_compounding_filesystem_hours(self):
        b=self.bundle()
        fs=copy.deepcopy(b['months']['2024-02']['filesystem'])
        fs['training']['month']='2024-05'
        b['months']['2024-06']['filesystem']=fs
        f=self.fixture();requests=f.loc[f.index.month==6].copy()
        out=self.engine._apply_hour_of_week_profiling(requests,profile_manifest=b)
        self.assertTrue((out[self.engine.profiling_policy.activity_deficit_signal]==0).all())
        np.testing.assert_array_equal(self.engine._profile_score_amplifier_values(out),out.chronosift_web_quiet_multiplier)

    def test_compact_restoration_does_not_require_raw_requests(self):
        f=self.fixture();b=self.bundle(f);out=self.engine._apply_hour_of_week_profiling(f.loc[f.index.month==6].copy(),profile_manifest=b)
        factors=self.engine._profile_score_amplifier_values(out)
        self.assertEqual(set(out.attrs['_chronosift_monthly_profiles']['months']),{'2024-06'})
        compact=out[list(c.MONTHLY_PROFILE_COLUMNS)].copy();compact.attrs={}
        restored=self.engine._apply_monthly_activity_profiling(compact,b)
        np.testing.assert_array_equal(factors,self.engine._profile_score_amplifier_values(restored))
        signals={0:{'web_shell_name_probe':1}};explain={}
        self.engine._append_profile_score_amplifier_explanations_sparse(restored,signals,explain)
        self.assertEqual(explain[0][0]['rule_id'],'WEB_QUIET_HOURS_AMPLIFIER')
        self.assertEqual(explain[0][0]['evidence']['training']['month'],'2024-05')

    def test_public_full_compact_cli_scores_explanations_and_cache_reuse(self):
        import duckdb
        import subprocess
        import sys
        fixture=self.fixture()
        # A shell probe gives nonzero base danger without attack-ground-truth labels.
        bundle=self.bundle(fixture)
        expected=self.engine.apply(fixture.copy(), profile_manifest=bundle).set_index('chronosift_row_id').chronosift_score.to_dict()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);raw=root/'raw'
            for (y,m),part in fixture.groupby([fixture.index.year,fixture.index.month]):
                dest=raw/f'year={y}'/f'month={m}';dest.mkdir(parents=True)
                part.to_parquet(dest/'part.parquet')
            cache=root/'profiles.json'
            yara=root/'metadata.yar';yara.write_text('rule PROFILE_TEST_STUB {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n')
            con=duckdb.connect()
            hashes=[]
            for mode in ['full','sidecar']:
                dest=root/mode
                result=subprocess.run([sys.executable,str(ROOT/'run_chronosift_sidecar_cli.py'),str(raw),str(dest),
                    '--output-mode',mode,'--profile-manifest-path',str(cache),'--yara-metadata-path',str(yara),'--log-level','ERROR'],
                    capture_output=True,text=True,env=dict(__import__('os').environ,PYTHONDONTWRITEBYTECODE='1',TZ='UTC'))
                self.assertEqual(result.returncode,0,result.stderr[-6000:]+result.stdout[-2000:])
                got=dict(con.execute('SELECT chronosift_row_id,chronosift_score FROM read_parquet(?,union_by_name=true)',[str(dest/'**/*.parquet')]).fetchall())
                self.assertEqual(expected.keys(),got.keys())
                for ident in expected:self.assertAlmostEqual(got[ident],expected[ident],places=12)
                factors=con.execute("SELECT chronosift_web_quiet_multiplier FROM read_parquet(?,union_by_name=true) WHERE datetime >= TIMESTAMPTZ '2024-06-01' AND datetime < TIMESTAMPTZ '2024-07-01'",[str(dest/'**/*.parquet')]).fetchall()
                self.assertTrue(all(x[0]>1 for x in factors))
                hashes.append(hashlib.sha256(cache.read_bytes()).hexdigest())
                self.assertTrue(c._monthly_manifest_matches(c.load_profile_manifest(str(cache)),c._monthly_profile_fingerprint(self.engine,str(raw))))
            self.assertEqual(*hashes)
            con.close()

if __name__=='__main__':unittest.main()
