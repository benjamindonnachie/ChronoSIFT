"""SUID and Linux account provenance: real parser shapes and strict negatives."""
from pathlib import Path
from dataclasses import replace
import logging
import subprocess
import sys
import tempfile
import unittest
import pandas as pd
import yaml
import chronoSIFT_v2_31 as c

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v20.yaml'
WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v18.yaml'

def birth(name='child',uid=1003,**extra):
    return dict(parser='text/syslog_traditional',
        message=f'[useradd, pid: 2053] new user: name={name}, UID={uid}, GID=1003, home=/home/{name}, shell=/bin/bash',**extra)

def auth(name='child',success=True,ip='192.0.2.15',**extra):
    message=(f'Successful login of user: {name} from {ip}:50950 using authentication method: password ssh pid: 2060'
        if success else f'sshd[2060]: Failed password for {name} from {ip} port 50950 ssh2')
    return dict(parser='text/syslog_traditional',message=message,**extra)

def reset(name='child',kind='userdel',**extra):
    action='delete user' if kind=='userdel' else 'change user'
    return dict(parser='text/syslog_traditional',message=f'[{kind}, pid: 3000] {action} \'{name}\'',**extra)

def file(**extra):
    return dict(dict(parser='filestat',filename='/var/spool/service/helper',file_entry_type='file',
        owner_identifier=0.0,mode=2541.0,timestamp_desc='Content Modification Time'),**extra)

def frame(records):
    return pd.DataFrame([dict(chronosift_row_id=900+i,hostname='fixture-host',**row) if 'hostname' not in row
        else dict(chronosift_row_id=900+i,**row) for i,(_,row) in enumerate(records)],
        index=pd.DatetimeIndex([pd.Timestamp('2024-01-31T23:00:00Z')+pd.Timedelta(t) for t,_ in records],name='datetime'))

class LinuxAccountContextTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.metadata=Path(cls.temp.name)/'unused.yar'
        cls.metadata.write_text('rule UNUSED { meta: score = 75 quality = 85 condition: false }\n')
        cls.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.metadata))
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        logging.getLogger().setLevel(cls.level);cls.temp.cleanup()

    def run_rows(self,records):
        out=self.engine.apply_contextual(self.engine.apply_atomic(frame(records),apply_profiling=False),apply_profiling=False)
        self.assertEqual(len(out),len(records));self.assertTrue(out.chronosift_row_id.is_unique)
        for explanations,score in zip(out.chronosift_explain,out.chronosift_score):
            self.assertAlmostEqual(min(50,sum(e.get('score_contribution',0) for e in (explanations or []))),score)
        return out

    def signals(self,out,pos=-1):return out.iloc[pos].chronosift_signals or {}

    def test_builder_idempotent(self):
        self.assertEqual(subprocess.check_output([sys.executable,'-B',str(ROOT/'benchmarks/build_linux_account_policy.py')],text=True),
            '*** Begin Patch\n*** End Patch\n')

    def test_suid_real_numeric_shape_and_prefixed_encodings(self):
        for mode in (2541,2541.0,'2541.0','2541','0o4755','0x9ed','0b100111101101'):
            with self.subTest(mode=mode):
                out=self.run_rows([('0s',file(mode=mode))]);self.assertEqual(out.iloc[0].chronosift_score,24)
                self.assertIn('linux_root_suid_staging_file',self.signals(out))

    def test_suid_rejects_bad_or_fractional_mode(self):
        for mode in (None,-1,2541.5,'NaN','inf','True','0o9999','rwsr-xr-x','2541e0'):
            with self.subTest(mode=mode):
                self.assertNotIn('linux_root_suid_staging_file',self.signals(self.run_rows([('0s',file(mode=mode))])))

    def test_suid_is_not_blanket_system_or_owner_boost(self):
        cases=[dict(filename='/usr/bin/passwd'),dict(filename='/bin/su'),dict(filename='/var/spoolish/s'),
            dict(filename='/tmpish/s'),dict(mode=0o755),dict(mode=0o4644),dict(mode=0o2755),
            dict(owner_identifier=1000),dict(owner_identifier=None),dict(file_entry_type='directory'),
            dict(parser='text/syslog_traditional'),dict(filename='/tmp/s',mode=None,message='Mode: 0o4755 Owner identifier: 0')]
        for extra in cases:
            with self.subTest(extra=extra):
                self.assertNotIn('linux_root_suid_staging_file',self.signals(self.run_rows([('0s',file(**extra))])))

    def test_uid0_creation_adds_to_general_account_change(self):
        out=self.run_rows([('0s',birth(uid=0))])
        self.assertEqual(out.iloc[0].chronosift_score,27)
        self.assertEqual(out.iloc[0].linux_account_created_name,'child')
        self.assertNotEqual(out.iloc[0].actor_user,'child')

    def test_ordinary_creation_stays_nine(self):
        self.assertEqual(self.run_rows([('0s',birth())]).iloc[0].chronosift_score,9)

    def test_successful_new_account_use_but_not_failed_guess(self):
        out=self.run_rows([('0s',birth()),('1h',auth(success=False)),('2h',auth())])
        self.assertNotIn('linux_recent_account_use',self.signals(out,1))
        self.assertEqual(self.signals(out)['linux_recent_account_use'],1)
        self.assertNotIn('linux_recent_uid0_alias_login',self.signals(out))

    def test_uid0_alias_login_privilege_equivalent(self):
        out=self.run_rows([('0s',birth(uid=0)),('1h',auth())])
        self.assertEqual(self.signals(out)['linux_recent_uid0_alias_login'],1)
        self.assertEqual(out.iloc[-1].chronosift_score,24) # remote1 + new12 + UID0 privilege11

    def test_named_root_does_not_double_existing_privilege(self):
        out=self.run_rows([('0s',birth(name='root',uid=0)),('1h',auth(name='root'))])
        self.assertNotIn('linux_recent_uid0_alias_login',self.signals(out))
        self.assertEqual(self.signals(out)['privileged_login'],1)

    def test_no_future_creation_backfill_or_other_account(self):
        out=self.run_rows([('0s',auth()),('1h',birth(uid=0)),('2h',auth(name='someone_else'))])
        for pos in (0,2):self.assertNotIn('linux_recent_account_use',self.signals(out,pos))

    def test_missing_scope_and_cross_host_are_not_pooled(self):
        for a,b in ((None,None),('one','two'),('', '')):
            with self.subTest(scopes=(a,b)):
                out=self.run_rows([('0s',birth(uid=0,hostname=a)),('1h',auth(hostname=b))])
                self.assertNotIn('linux_recent_account_use',self.signals(out))

    def test_names_remain_case_sensitive(self):
        out=self.run_rows([('0s',birth(name='Child',uid=0)),('1h',auth(name='child'))])
        self.assertNotIn('linux_recent_uid0_alias_login',self.signals(out))

    def test_seven_day_boundary_and_no_activity_refresh(self):
        out=self.run_rows([('0s',birth(uid=0)),('6d',auth()),('7d',auth()),('7d1s',auth())])
        self.assertIn('linux_recent_account_use',self.signals(out,2))
        self.assertNotIn('linux_recent_account_use',self.signals(out,3))
        self.assertNotIn('linux_recent_uid0_alias_login',self.signals(out,3))

    def test_deletion_modification_and_recreation_revoke_uid0(self):
        for event in (reset(),reset(kind='usermod'),birth(uid=1003)):
            with self.subTest(event=event):
                out=self.run_rows([('0s',birth(uid=0)),('1h',auth()),('2h',event),('3h',auth())])
                self.assertNotIn('linux_recent_uid0_alias_login',self.signals(out))
                self.assertEqual('linux_recent_account_use' in self.signals(out),'useradd' in event['message'])

    def test_other_account_reset_does_not_revoke_child(self):
        out=self.run_rows([('0s',birth(uid=0)),('1h',reset(name='other')),('2h',auth())])
        self.assertIn('linux_recent_uid0_alias_login',self.signals(out))

    def test_host_association_is_weak_not_creator_attribution(self):
        out=self.run_rows([('0s',auth(name='root')),('10m',birth()),('6d',auth())])
        self.assertEqual(out.iloc[1].chronosift_score,15)
        self.assertEqual(self.signals(out)['linux_recent_privileged_creation_use'],1)
        e=next(e for e in out.iloc[1].chronosift_explain if e['rule_id']=='LINUX_CREATED_AFTER_PRIVILEGED_ACCESS')
        self.assertEqual(e['evidence']['supporting_row_ids'],[900,901])
        self.assertIn('creator/session/IP not attributed',e['description'])

    def test_host_association_rejects_nonprivileged_failed_expired_or_other_host(self):
        for first,t in ((auth(name='ordinary'),'10m'),(auth(name='root',success=False),'10m'),
            (auth(name='root'),'1h1s'),(auth(name='root',hostname='other'),'10m')):
            with self.subTest(first=first,time=t):
                out=self.run_rows([('0s',first),(t,birth()),('1d',auth())])
                self.assertNotIn('linux_created_after_privileged_access',self.signals(out,1))
                self.assertNotIn('linux_recent_privileged_creation_use',self.signals(out))

    def test_recreation_cannot_reuse_previous_host_provenance(self):
        out=self.run_rows([('0s',auth(name='root')),('10m',birth()),('2d',birth()),('3d',auth())])
        self.assertNotIn('linux_recent_privileged_creation_use',self.signals(out))

    def test_tied_timestamps_preserve_rows_and_reset_order(self):
        out=self.run_rows([('0s',birth(uid=0)),('0s',auth()),('0s',reset()),('0s',auth())])
        self.assertEqual(list(out.chronosift_row_id),[900,901,902,903])
        self.assertIn('linux_recent_uid0_alias_login',self.signals(out,1))
        self.assertNotIn('linux_recent_uid0_alias_login',self.signals(out,3))

    def test_parser_and_message_qualification(self):
        for row in (dict(birth(),parser='filestat'),dict(birth(),message='documentation: useradd -u 0 child'),
            birth(uid='unknown')):
            out=self.run_rows([('0s',row),('1h',auth())])
            self.assertNotIn('linux_account_created',self.signals(out,0))
            self.assertNotIn('linux_recent_account_use',self.signals(out))

    def test_reset_schema_and_eligibility_validation(self):
        config=yaml.safe_load(RULES.read_text())
        rule=next(x for x in config['temporal_rules'] if x['id']=='LINUX_RECENT_ACCOUNT_USE')
        for value in ([],['LINUX_ACCOUNT_CREATED'],['linux_account_created']*2,'linux_account_created'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.engine._parse_temporal_rules([dict(rule,reset_signals=value)])
        for value in ('missing_signal','referenced_file_av_hit'):
            doc=yaml.safe_load(RULES.read_text());target=next(x for x in doc['temporal_rules'] if x['id']==rule['id'])
            target['reset_signals']=[value]
            with self.subTest(value=value),self.assertRaises(ValueError):
                c.ChronoSiftEngine(doc,yaml.safe_load(WEIGHTS.read_text()),yara_metadata_path=str(self.metadata))

    def test_reset_is_retained_by_candidate_mask(self):
        data=frame([('0s',reset())]);data=self.engine._apply_normalisation(data)
        mask=self.engine._temporal_candidate_base_mask(data,{0:{'linux_account_lifecycle_reset':1}})
        self.assertTrue(mask.iloc[0])

    def test_horizon_remains_199_hours(self):
        self.assertEqual(self.engine.minimum_partition_overlap(),pd.Timedelta('199h'))

    def test_bitmask_format_is_opt_in_and_strict(self):
        data=pd.DataFrame({'mode':['2541.0','0o4755','2541','0x9ed']})
        spec=next(s for s in self.engine.normalisation if s.name=='linux_suid_bit')
        configured=self.engine.normalisation
        try:
            self.engine.normalisation=[replace(spec,number_format='legacy_decimal_hex')]
            out=self.engine._apply_normalisation(data)
            self.assertTrue(out.linux_suid_bit.iloc[:2].isna().all())
            self.assertEqual(out.linux_suid_bit.iloc[2:].tolist(),['1','1'])
        finally:self.engine.normalisation=configured
        doc=yaml.safe_load(RULES.read_text())
        next(x for x in doc['normalisation'] if x['name']=='linux_suid_bit')['number_format']='guess_octal'
        with self.assertRaises(ValueError):
            c.ChronoSiftEngine(doc,yaml.safe_load(WEIGHTS.read_text()),yara_metadata_path=str(self.metadata))

    def test_native_cross_month_compact_eager_and_resets(self):
        # Jan31 creation precedes a Feb login more than 24h later, then deletion.
        records=[('0s',auth(name='root')),('10m',birth(uid=0)),('2d',auth()),
            ('3d',reset()),('4d',auth()),('5d',birth(uid=1003)),('6d',auth())]
        data=frame(records)
        outputs=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            c.write_time_partitioned_parquet(data,str(root/'input'),normalise=False)
            for compact in (False,True):
                engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata))
                engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
                engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
                plan=engine.plan_partition_execution(str(root/'input'))
                self.assertEqual(plan['feature_seconds'],86400)
                self.assertGreaterEqual(plan['history_seconds'],169*3600)
                dest=root/str(compact)
                reports=engine.process_parquet_dataset_partitioned(str(root/'input'),str(dest),
                    output_mode='sidecar',materialise_event_columns=True)
                self.assertEqual(sum(x['rows_written'] for x in reports),len(data))
                out=c.load_plaso_parquet_dataset(str(dest)).set_index('chronosift_row_id').sort_index()
                outputs.append(out)
            self.assertEqual(outputs[0].chronosift_score.tolist(),outputs[1].chronosift_score.tolist())
            for out in outputs:
                signals=lambda rid:out.loc[rid].chronosift_signals or {}
                self.assertIn('linux_recent_uid0_alias_login',signals(902))
                self.assertIn('linux_recent_privileged_creation_use',signals(902))
                self.assertNotIn('linux_recent_account_use',signals(904))
                self.assertIn('linux_recent_account_use',signals(906))
                self.assertNotIn('linux_recent_uid0_alias_login',signals(906))
                self.assertNotIn('linux_recent_privileged_creation_use',signals(906))

if __name__=='__main__':unittest.main()
