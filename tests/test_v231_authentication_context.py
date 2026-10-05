"""History-aware authentication priorities; no dataset IP/account exceptions."""
from copy import deepcopy
from dataclasses import replace
import json
import logging
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import chronoSIFT_v2_31 as c
from benchmarks.build_authentication_context_policy import build, weights, render

ROOT=Path(__file__).resolve().parents[1]
SID='S-1-5-21-101-202-303-500'
OTHER='S-1-5-21-101-202-303-1201'
START=pd.Timestamp('2024-06-30T23:59:00Z')


def login(ip='45.10.20.30', *, success=True, sid=SID, user='Administrator', remote=True, far=False, **extra):
    # XML exercises actual canonicalisation; bare optional columns do not supply
    # the canonicaliser's event-data document. Public addresses are inert test
    # values so unrelated private-subnet transitions do not enter these tests.
    event=4624 if success else 4625
    fields=dict(TargetUserSid=sid,TargetUserName=user,IpAddress=ip,
        LogonType=str(3 if remote else 2),AuthenticationPackageName='NTLM',WorkstationName='test-client')
    xml='<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>'+str(event)+'</EventID></System><EventData>'+''.join(
        f'<Data Name="{key}">{value}</Data>' for key,value in fields.items())+'</EventData></Event>'
    return dict(parser='winevtx',source_name='Microsoft-Windows-Security-Auditing',
        event_identifier=event,xml_string=xml,win_target_sid=sid,target_user_name=user,
        ip_address=ip,src_ip=ip,logon_type=3 if remote else 2,authentication_package='NTLM',
        workstation_name='test-client',geo_country_iso='CN' if far else 'GB',
        geo_asn=200 if far else 100,geo_city_name='East' if far else 'West',
        geo_latitude=32.0 if far else 51.5,geo_longitude=110.0 if far else -0.1,**extra)


def frame(rows):
    return pd.DataFrame([dict(hostname='fixture-host',win_asset_id='fixture-image',
        chronosift_row_id=900+i,**r) for i,(_,r) in enumerate(rows)],
        index=pd.DatetimeIndex([START+pd.Timedelta(t) for t,_ in rows],name='datetime'))


def signals(row):
    value=row.get('chronosift_signals')
    return value if isinstance(value,dict) else {}


def intrusion():
    return [('0s',login())]+[(f'{t}s',login('80.10.20.30',success=False,far=True)) for t in (10,20,30)]+[
        ('120s',login('80.10.20.30',far=True)),('130s',login('80.10.20.30',far=True)),('240s',login())]


class AuthenticationContextTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.metadata=Path(cls.temp.name)/'fixture.yar'
        cls.metadata.write_text('rule UNUSED { condition: false }\n')
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)
        cls.engine=c.ChronoSiftEngine.from_yaml(ROOT/'rules/rules_evidence_calibrated_v27.yaml',
            ROOT/'rules/weights_evidence_calibrated_v23.yaml',yara_metadata_path=str(cls.metadata))

    @classmethod
    def tearDownClass(cls):
        logging.getLogger().setLevel(cls.level);cls.temp.cleanup()

    def run_rows(self,rows):
        out=self.engine.apply(frame(rows),apply_profiling=False)
        self.assertEqual(out.chronosift_row_id.tolist(),list(range(900,900+len(rows))))
        for _,r in out.iterrows():
            explains=r.get('chronosift_explain')
            if not isinstance(explains,list):explains=[]
            self.assertAlmostEqual(r.chronosift_score,min(50,sum(x['score_contribution'] for x in explains)))
        return out

    def test_generated_policy(self):
        for path,expected in render().items():self.assertEqual((ROOT/path).read_text(),expected,path)

    def test_known_admin_is_context_not_execution_or_share_abuse(self):
        out=self.run_rows([('0s',login()),('1s',login()),('1d',login()),('4d',login())])
        self.assertEqual(out.chronosift_score.tolist(),[2,0,0,0])
        self.assertIn('windows_account_new_source',signals(out.iloc[0]))
        for _,r in out.iterrows():
            self.assertNotIn('exec_privileged_context',signals(r))
            self.assertNotIn('smb_admin_share',signals(r))
            self.assertNotIn('alternate_auth_material',signals(r))
            self.assertIn('privileged_login',signals(r))
        for _,r in out.iloc[1:].iterrows():self.assertNotIn('windows_account_new_source',signals(r))

    def test_takeover_high_repeat_bounded_and_home_return_low(self):
        out=self.run_rows(intrusion())
        self.assertGreaterEqual(out.iloc[4].chronosift_score,40)
        self.assertIn('auth_takeover_candidate',signals(out.iloc[4]))
        self.assertLessEqual(out.iloc[5].chronosift_score,2)
        self.assertNotIn('auth_failure_success_episode',signals(out.iloc[5]))
        self.assertLessEqual(out.iloc[6].chronosift_score,2)
        self.assertIn('impossible_travel',signals(out.iloc[6])) # evidence retained
        self.assertNotIn('auth_anomalous_travel',signals(out.iloc[6]))

    def test_other_source_failures_do_not_raise_home_success(self):
        rows=intrusion()[:4]+[('40s',login())]
        out=self.run_rows(rows)
        self.assertEqual(out.iloc[-1].chronosift_score,0)
        self.assertNotIn('fail_then_success_user',signals(out.iloc[-1]))
        self.assertNotIn('fail_then_success_ip',signals(out.iloc[-1]))

    def test_source_failure_families_are_not_two_votes(self):
        out=self.run_rows([('0s',login())]+[(f'{t}s',login(success=False)) for t in (10,20,30)]+[('40s',login())])
        r=out.iloc[-1]
        self.assertEqual(r.chronosift_score,8)
        self.assertIn('fail_then_success_ip',signals(r));self.assertIn('fail_then_success_user',signals(r))

    def test_known_ip_can_still_have_takeover_evidence(self):
        rows=[('0s',login('80.10.20.30',far=True)),('1d',login())]
        rows += [(f'1d{t}s',login('80.10.20.30',success=False,far=True)) for t in (10,20,30)]
        rows += [('1d120s',login('80.10.20.30',far=True))]
        r=self.run_rows(rows).iloc[-1]
        self.assertNotIn('windows_account_new_source',signals(r))
        self.assertIn('auth_takeover_candidate',signals(r));self.assertGreaterEqual(r.chronosift_score,40)

    def test_new_source_without_anomalies_is_modest(self):
        out=self.run_rows([('0s',login()),('1h',login('91.10.20.30'))])
        self.assertEqual(out.iloc[-1].chronosift_score,2)

    def test_missing_geography_never_invents_takeover(self):
        rows=intrusion()
        for _,r in rows:
            for k in list(r):
                if k.startswith('geo_'):r[k]=None
        r=self.run_rows(rows).iloc[4]
        self.assertLessEqual(r.chronosift_score,10);self.assertNotIn('auth_takeover_candidate',signals(r))

    def test_duplicate_timestamps_preserve_rows_not_double_novelty(self):
        out=self.run_rows([('0s',login()),('0s',login()),('1s',login())])
        self.assertEqual(out.chronosift_score.tolist(),[2,0,0])

    def test_failure_episode_new_burst_after_expiry(self):
        rows=intrusion()[:6]
        rows += [(f'7h{t}s',login('80.10.20.30',success=False,far=True)) for t in (10,20,30)]
        rows += [('7h40s',login('80.10.20.30',far=True))]
        self.assertIn('auth_failure_success_episode',signals(self.run_rows(rows).iloc[-1]))

    def test_execution_and_real_share_evidence_still_score(self):
        rows=[('0s',dict(parser='text/bash_history',message='id',command_line='id',actor_user='root')),
            ('1s',dict(parser='winevtx',source_name='Microsoft-Windows-Security-Auditing',event_identifier=5140,
                share_name=r'\\*\ADMIN$',target_user_name='Administrator'))]
        out=self.run_rows(rows)
        self.assertIn('exec_privileged_context',signals(out.iloc[0]))
        self.assertIn('smb_admin_share',signals(out.iloc[1]))
        self.assertGreater(out.iloc[0].chronosift_score,0);self.assertGreater(out.iloc[1].chronosift_score,0)

    def test_projection_conditions_are_strict_and_policy_owned(self):
        doc=build();raw=doc['detector_policy']['detectors']['authentication_context_priority']['projections'][3]
        for invalid in ('bad',[[]]):
            changed=deepcopy(doc);changed['detector_policy']['detectors']['authentication_context_priority']['projections'][3]['conditions']['all_of_any']=invalid
            with self.assertRaises(ValueError):c._parse_detector_policy(changed,weights())
        for name in ('missing_producer','auth_takeover_candidate'):
            changed=deepcopy(doc);changed['detector_policy']['detectors']['authentication_context_priority']['projections'][3]['conditions']['all_of_any']=[[name]]
            with self.assertRaises(ValueError):c._parse_detector_policy(changed,weights())
        policy=self.engine.detector_policy
        self.assertIn('windows_account_new_source',policy.definition('authentication_context_priority').payload.source_signals)

    def test_native_month_boundary_retains_history_compact_and_expanded(self):
        data=frame(intrusion()+[('5m',login())])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c.write_time_partitioned_parquet(data,str(root/'input'),normalise=False)
            results=[]
            for compact in (False,True):
                engine=c.ChronoSiftEngine.from_yaml(ROOT/'rules/rules_evidence_calibrated_v27.yaml',ROOT/'rules/weights_evidence_calibrated_v23.yaml',yara_metadata_path=str(self.metadata))
                engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
                engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
                reports=engine.process_parquet_dataset_partitioned(str(root/'input'),str(root/str(compact)),output_mode='sidecar',materialise_event_columns=True)
                self.assertEqual(sum(r['rows_written'] for r in reports),len(data))
                out=c.load_plaso_parquet_dataset(str(root/str(compact))).set_index('chronosift_row_id').sort_index()
                results.append(out.chronosift_score.tolist())
                self.assertEqual(out.iloc[-1].chronosift_score,0)
            self.assertEqual(results[0],results[1]);self.assertEqual(results[0],self.run_rows(intrusion()+[('5m',login())]).chronosift_score.tolist())


if __name__=='__main__':unittest.main()
