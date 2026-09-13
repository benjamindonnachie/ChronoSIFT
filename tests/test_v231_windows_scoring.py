"""Windows evidence/context policy: generic identities and benign controls.

ATT&CK rationale and outcome limits: docs/WINDOWS_SCORING_DESIGN.md.
Fixture accounts and paths deliberately differ from the forensic case.
"""
import logging
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import pyarrow.dataset as ds
import yaml
import chronoSIFT_v2_31 as c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT/'rules/rules_evidence_calibrated_v13.yaml'
WEIGHTS = ROOT/'rules/weights_evidence_calibrated_v12.yaml'
SID = 'S-1-5-21-101-202-303-1501'
OTHER = 'S-1-5-21-101-202-303-1502'
START = pd.Timestamp('2024-06-29T23:00:00Z')

def frame(rows):
    events = []
    times = []
    for pos, (offset, row) in enumerate(rows):
        times.append(START+pd.Timedelta(offset))
        events.append({'chronosift_row_id':100+pos,'hostname':'fixture-host','win_asset_id':'fixture-image',**row})
    return pd.DataFrame(events,index=pd.DatetimeIndex(times,name='datetime'))

def account(event, **extra):
    return {'parser':'winevtx','source_name':'Microsoft-Windows-Security-Auditing',
            'event_identifier':float(event),'win_target_sid':SID,'target_user_name':'maint2',**extra}

def creation():
    return ('0s',account(4720))

def grant():
    return ('20s',account(4732,win_member_sid=SID,win_target_sid='S-1-5-32-544',
                         target_user_name='Administrators',group_name='Administrators'))

def archive():
    return {'parser':'filestat','filename':r'\Users\maint2\Desktop\collection.zip','timestamp_desc':'Creation Time'}

class WindowsScoringTest(unittest.TestCase):
    def test_generated_policy_matches_builder_exactly(self):
        patch=subprocess.check_output([sys.executable,'-B',str(ROOT/'benchmarks/build_windows_policy.py')],text=True)
        self.assertEqual(patch,'*** Begin Patch\n*** End Patch\n')

    def setUp(self):
        self.addCleanup(logging.getLogger().setLevel,logging.getLogger().level)
        logging.getLogger().setLevel(logging.ERROR)
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        yara=Path(self.temp.name)/'fixture.yar'
        yara.write_text('rule TEST_UNUSED { condition: false }\n')
        self.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(yara))

    def run_rows(self, rows):
        data=frame(rows)
        return self.engine.apply_contextual(self.engine.apply_atomic(data,apply_profiling=False),apply_profiling=False)

    def test_event_id_representations_create_and_group(self):
        for value, group_value in ((4720,4732),(4720.0,4732.0),('4720','4732'),('4720.0','4732.0')):
            with self.subTest(value=value):
                out=self.run_rows([('0s',account(value,event_identifier=value)),
                    ('20s',{**grant()[1],'event_identifier':group_value})])
                self.assertEqual(out.iloc[0].win_event_id,'4720')
                self.assertEqual(out.iloc[0].chronosift_signals.get('account_created'),1)
                self.assertEqual(out.iloc[1].chronosift_signals.get('privileged_account_created'),1)
                self.assertEqual(out.iloc[1].chronosift_signals.get('windows_new_privileged_account'),1)

    def test_xml_sid_and_task_user_aliases(self):
        xml='''<Event><System><EventID>4720</EventID></System><EventData>
        <Data Name="TargetSid">S-1-5-21-101-202-303-1501</Data>
        <Data Name="SubjectUserSid">S-1-5-21-101-202-303-500</Data>
        <Data Name="TargetUserName">maint2</Data></EventData></Event>'''
        out=self.run_rows([('0s',{'parser':'winevtx','xml_string':xml,'event_identifier':4720.0})])
        self.assertEqual(out.iloc[0].win_context_sid,SID)
        self.assertNotEqual(out.iloc[0].win_context_sid,out.iloc[0].win_subject_sid)

    def test_new_account_context_survives_days_and_month_boundary(self):
        out=self.run_rows([creation(),grant(),('3d',archive())])
        signals=out.iloc[-1].chronosift_signals
        self.assertEqual(out.iloc[-1].win_context_sid,SID)
        self.assertEqual(signals.get('windows_privileged_activity_context'),1)
        self.assertGreaterEqual(out.iloc[-1].chronosift_score,20)
        explanations=out.iloc[-1].chronosift_explain
        ctx=next(e for e in explanations if e['rule_id']=='WINDOWS_RECENT_PRIVILEGED_ACTION')
        self.assertEqual(ctx['evidence']['supporting_row_ids'],[101,102])

    def test_repeated_follow_on_witness_ends_on_current_trigger(self):
        out=self.run_rows([creation(),grant(),('1d',archive()),('2d',archive())])
        for pos in (2,3):
            explanation=next(e for e in out.iloc[pos].chronosift_explain if e['rule_id']=='WINDOWS_RECENT_PRIVILEGED_ACTION')
            self.assertEqual(explanation['evidence']['supporting_row_ids'],[101,100+pos])

    def test_same_basename_elsewhere_does_not_resolve_file(self):
        # Basename coincidence must not become an executed-file hash match.
        df=self.engine._apply_normalisation(frame([
            ('0s',{'parser':'filestat','filename':r'\Users\maint2\Desktop\agent.exe','sha256_hash':'a'*64,'av_hit':True}),
            ('1m',{'parser':'esedb/srum','data_type':'windows:srum:application_usage',
                   'application':r'\Device\HarddiskVolume9\Program Files\Example\agent.exe','sha256_hash':'b'*64})]))
        signals={}; self.engine._apply_referenced_file_hit_signals_sparse(df,signals,{})
        self.engine._apply_deadbox_direct_signals_sparse(df,signals,{})
        self.assertFalse(signals[1].get('windows_malware_execution'))
        self.assertFalse(signals[1].get('windows_malware_execution_candidate'))

    def test_no_context_for_old_or_different_account_or_reverse_order(self):
        for rows in ([creation(),grant(),('8d',archive())],
                     [creation(),grant(),('3d',{**archive(),'user_identifier':OTHER})],
                     [('0s',archive()),('1h',account(4720)),('1h1m',grant()[1])]):
            with self.subTest(rows=rows):
                out=self.run_rows(rows)
                pos=0 if rows[0][1].get('parser')=='filestat' else len(out)-1
                self.assertFalse(out.iloc[pos].chronosift_signals.get('windows_privileged_activity_context'))

    def test_ambiguous_profile_account_does_not_resolve(self):
        out=self.run_rows([creation(),grant(),('1m',account(4720,win_target_sid=OTHER)),('3d',archive())])
        self.assertTrue(pd.isna(out.iloc[-1].win_profile_sid))
        self.assertFalse(out.iloc[-1].chronosift_signals.get('windows_recent_privileged_action'))

    def test_failed_authentication_null_sid_does_not_poison_identity(self):
        out=self.run_rows([creation(),grant(),('1h',account(4625,win_target_sid='S-1-0-0')),
                          ('2h',archive())])
        self.assertEqual(out.iloc[-1].win_profile_sid,SID)
        self.assertEqual(out.iloc[-1].chronosift_signals.get('windows_privileged_activity_context'),1)

    def test_ftp_registry_cache_receives_context_without_upload_confirmation(self):
        out=self.run_rows([creation(),grant(),('1h',archive()),('2h',{'parser':'winreg/winreg_default',
            'display_name':r'NTFS:\Users\maint2\NTUSER.DAT',
            'message':r'[HKEY_CURRENT_USER\Software\Microsoft\FTP\Accounts\203.0.113.20\visitor] (empty)'})])
        sig=out.iloc[-1].chronosift_signals
        self.assertTrue(sig.get('windows_ftp_activity'))
        self.assertEqual(sig.get('windows_archive_ftp_evidence'),1)
        self.assertTrue(sig.get('windows_privileged_activity_context'))
        self.assertFalse(sig.get('windows_observed_sensitive_upload'))
        self.assertGreaterEqual(out.iloc[-1].chronosift_score,32)

    def test_defender_value_zero_and_one(self):
        for value, expected in (('0',False),('1',True),('0x1',True),('10',False)):
            row={'parser':'winreg','timestamp_desc':'Last Written Time',
                 'message':f'HKLM Defender DisableAntiSpyware: [REG_DWORD_LE] {value}'}
            out=self.run_rows([('0s',row)])
            self.assertEqual(bool((out.iloc[0].get('chronosift_signals') or {}).get('defender_disabled')),expected)

    def test_host_impairment_is_weaker_and_not_actor_attribution(self):
        row={'parser':'winreg','message':'DisableAntiSpyware: [REG_DWORD_LE] 1'}
        out=self.run_rows([creation(),grant(),('1d',row)])
        self.assertTrue(pd.isna(out.iloc[-1].win_context_sid))
        self.assertEqual(out.iloc[-1].chronosift_signals.get('windows_privileged_activity_context'),.5)

    def test_task_registration_links_author_not_system_account(self):
        xml='''<Event><System><EventID>106</EventID></System><EventData>
        <Data Name="TaskName">\\Nightly maintenance</Data>
        <Data Name="UserContext">LAB\\maint2</Data></EventData></Event>'''
        out=self.run_rows([creation(),grant(),('2d',{'parser':'winevtx',
            'source_name':'Microsoft-Windows-TaskScheduler','xml_string':xml,'event_identifier':106.0})])
        self.assertEqual(out.iloc[-1].win_task_sid,SID)
        self.assertEqual(out.iloc[-1].chronosift_signals.get('windows_task_registered'),1)
        self.assertGreaterEqual(out.iloc[-1].chronosift_score,24)

    def test_ftp_after_archive_keeps_inference_not_confirmed_upload(self):
        ftp={'parser':'esedb/srum','display_name':r'NTFS:\Users\maint2\AppData\WebCache.dat',
             'message':'ftp://203.0.113.20/example/','url':'ftp://203.0.113.20/example/'}
        out=self.run_rows([creation(),grant(),('1h',archive()),('1d',ftp)])
        self.assertEqual(out.iloc[-1].chronosift_signals.get('windows_archive_ftp_context'),1)
        self.assertGreaterEqual(out.iloc[-1].chronosift_score,28)
        for signal in ('web_sensitive_file_download','windows_confirmed_upload'):
            self.assertFalse(out.iloc[-1].chronosift_signals.get(signal))

    def test_execution_and_presence_are_different(self):
        out=self.run_rows([('0s',{'parser':'filestat','filename':r'\Users\maint2\tool.exe'}),
                           ('1m',{'parser':'esedb/srum','data_type':'windows:srum:application_usage',
                                  'application':r'\Device\HarddiskVolume8\Users\maint2\tool.exe','user_identifier':SID})])
        self.assertFalse(out.iloc[0].chronosift_signals.get('windows_program_execution'))
        self.assertEqual(out.iloc[1].chronosift_signals.get('windows_program_execution'),1)

    def test_malware_link_requires_av_and_execution(self):
        df=self.engine._apply_normalisation(frame([
            ('0s',{'parser':'esedb/srum','data_type':'windows:srum:application_usage'}),
            ('1m',{'parser':'filestat'}),('2m',{'parser':'esedb/srum','data_type':'windows:srum:application_usage'})]))
        signals={0:{'referenced_file_av_hit':.5},1:{'referenced_file_av_hit':.5}}
        self.engine._apply_deadbox_direct_signals_sparse(df,signals,{})
        self.assertTrue(signals[0].get('windows_malware_execution_candidate'))
        self.assertFalse(signals[0].get('windows_malware_execution'))
        self.assertGreaterEqual(self.engine._score_signals(signals[0]),30)
        self.assertFalse(signals[1].get('windows_malware_execution'))
        self.assertFalse(signals[2].get('windows_malware_execution'))

    def test_explicit_executed_hash_is_distinct_from_container_hash(self):
        digest='b'*64
        rows=[('0s',{'parser':'filestat','sha256_hash':digest,'av_hit':True}),
              ('1m',{'parser':'esedb/srum','data_type':'windows:srum:application_usage',
                     'chronosift_executed_sha256':digest}),
              ('2m',{'parser':'esedb/srum','data_type':'windows:srum:application_usage','sha256_hash':digest})]
        df=self.engine._apply_normalisation(frame(rows)); sig={}
        self.engine._apply_deadbox_direct_signals_sparse(df,sig,{})
        self.assertTrue(sig[1].get('windows_malware_execution'))
        self.assertGreaterEqual(self.engine._score_signals(sig[1]),45)
        self.assertFalse(sig[2].get('windows_malware_execution'))

    def test_failed_or_unknown_ftp_upload_scores_without_upstream_confirmation(self):
        for suffix in ('550 Upload failed',''):
            with self.subTest(suffix=suffix):
                out=self.run_rows([creation(),grant(),('1h',{'parser':'winevtx',
                    'win_subject_sid':SID,'command_line':r'ftp.exe put C:\Users\maint2\collection.zip',
                    'message':suffix})])
                signals=out.iloc[-1].chronosift_signals
                self.assertTrue(signals.get('windows_ftp_upload_attempt'))
                self.assertGreaterEqual(out.iloc[-1].chronosift_score,32)
                self.assertFalse(signals.get('windows_observed_sensitive_upload'))

    def test_ftp_navigation_alone_is_not_upload_attempt(self):
        out=self.run_rows([('0s',{'parser':'winreg','message':'ftp://203.0.113.20/','url':'ftp://203.0.113.20/'})])
        self.assertTrue(out.iloc[0].chronosift_signals.get('windows_ftp_activity'))
        self.assertFalse(out.iloc[0].chronosift_signals.get('windows_ftp_upload_attempt'))

    def test_usn_archive_creation_keeps_weak_host_context_without_invented_actor(self):
        out=self.run_rows([creation(),grant(),('1h',{'parser':'usnjrnl','filename':'collection.zip',
            'timestamp_desc':'Metadata Modification Time','message':'collection.zip Update reason: USN_REASON_FILE_CREATE'})])
        self.assertTrue(pd.isna(out.iloc[-1].win_context_sid))
        self.assertEqual(out.iloc[-1].chronosift_signals.get('windows_archive_created'),1)
        self.assertEqual(out.iloc[-1].chronosift_signals.get('windows_privileged_activity_context'),.5)
        self.assertGreaterEqual(out.iloc[-1].chronosift_score,14)

    def test_linux_file_is_not_a_windows_artefact(self):
        df=self.engine._apply_normalisation(frame([('0s',{'parser':'filestat','filename':'/usr/share/example.bin'})]))
        signals={0:{'av_ransomware':1}}
        self.engine._apply_deadbox_direct_signals_sparse(df,signals,{})
        self.assertFalse(signals[0].get('windows_ransomware_presence'))

    def test_benign_readme_has_no_new_account_boost(self):
        out=self.run_rows([creation(),grant(),('1d',{'parser':'filestat','timestamp_desc':'Creation Time',
            'filename':r'\Users\maint2\Downloads\package\README.txt'})])
        self.assertFalse(out.iloc[-1].chronosift_signals.get('windows_privileged_activity_context'))
        self.assertFalse(out.iloc[-1].chronosift_signals.get('windows_ransom_note_context'))

    def test_bare_usn_note_requires_prior_ransomware_and_has_no_actor(self):
        for prior,expected in ((True,True),(False,False)):
            df=self.engine._apply_normalisation(frame([
                ('0s',{'parser':'filestat','filename':r'\Users\maint2\payload.exe'}),
                ('1h',{'parser':'usnjrnl','filename':'READ_ME.txt','message':'READ_ME.txt USN_REASON_FILE_CREATE'}),
                ('2h',{'parser':'usnjrnl','filename':'RecoveryInfo.txt','message':'RecoveryInfo.txt USN_REASON_FILE_CREATE'})]))
            # READ_ME is deliberately not a configured filename token; generic
            # RecoveryInfo exercises the policy independently of the case name.
            sig={0:{'av_ransomware':1}} if prior else {}
            exp={}
            self.engine._apply_deadbox_direct_signals_sparse(df,sig,exp)
            self.engine._apply_temporal_contextual_sparse(df,sig,exp)
            self.assertEqual(bool(sig.get(2,{}).get('windows_ransom_note_host_context')),expected)
            self.assertFalse(sig.get(2,{}).get('windows_ransom_note_context'))
            if expected:
                self.assertGreaterEqual(self.engine._score_signals(sig[2]),16)

    def test_verified_content_and_upload_contract(self):
        base={'parser':'filestat','timestamp_desc':'Last Access Time','filename':r'\Users\maint2\data.csv',
              'chronosift_sensitive_content_type':'plaintext_credentials','chronosift_sensitive_content_verified':True}
        rows=[creation(),grant(),('1h',base),('2h',{**base,'chronosift_transfer_direction':'outbound',
              'chronosift_transfer_outcome':'success','chronosift_transfer_bytes':4096}),
              ('3h',{**base,'chronosift_sensitive_content_verified':False}),
              ('4h',{**base,'chronosift_transfer_direction':'outbound','chronosift_transfer_outcome':'failure','chronosift_transfer_bytes':0})]
        out=self.run_rows(rows)
        self.assertTrue(out.iloc[2].chronosift_signals.get('windows_sensitive_content_access'))
        self.assertTrue(out.iloc[3].chronosift_signals.get('windows_observed_sensitive_upload'))
        self.assertFalse(out.iloc[4].chronosift_signals.get('windows_sensitive_content_access'))
        self.assertFalse(out.iloc[5].chronosift_signals.get('windows_observed_sensitive_upload'))

    def test_alias_revocation_reaches_context_field(self):
        df=self.engine._apply_normalisation(frame([creation(),('1h',archive()),('2h',{'parser':'winevtx'})]))
        self.assertEqual(df.iloc[1].win_context_sid,SID)
        df.loc[df.chronosift_row_id==102,'target_user_name']='maint2'
        df.loc[df.chronosift_row_id==102,'win_target_sid']=OTHER
        df=self.engine._apply_normalisation(df)
        self.assertTrue(pd.isna(df.iloc[1].win_context_sid))

    def test_new_logon_source_context_expires_without_refresh(self):
        login=account(4624,ip_address='203.0.113.25',logon_type=10)
        out=self.run_rows([creation(),grant(),('1h',login),('2h',login),('3h',archive()),('8h',archive())])
        self.assertTrue(out.iloc[4].chronosift_signals.get('windows_recent_new_source_action'))
        self.assertFalse(out.iloc[5].chronosift_signals.get('windows_recent_new_source_action'))

    def test_bcdedit_benign_change_is_not_recovery_inhibition(self):
        for command, expected in (('bcdedit /set {current} description Test',False),
                                  ('bcdedit /set {default} recoveryenabled No',True)):
            out=self.run_rows([('0s',{'parser':'winevtx','command_line':command})])
            self.assertEqual(bool((out.iloc[0].get('chronosift_signals') or {}).get('inhibit_system_recovery')),expected)

    def test_equal_timestamps_preserve_rows_and_values(self):
        out=self.run_rows([creation(),('0s',grant()[1]),('0s',archive())])
        self.assertEqual(list(out.chronosift_row_id),[100,101,102])
        self.assertEqual(len(out),3)

    def test_partition_overlap_covers_nested_account_window(self):
        self.assertGreaterEqual(self.engine.minimum_partition_overlap(),pd.Timedelta('7d1h'))
        self.assertIn('chronosift_row_id',self.engine._temporal_required_columns())
        with self.assertRaisesRegex(ValueError,'temporal dependencies'):
            self.engine.process_parquet_dataset_partitioned('absent','absent-output',overlap='24h')

    def test_partitioned_month_boundary_matches_continuous_account_context(self):
        rows=[creation(),grant(),('3d',archive())]
        continuous=self.run_rows(rows)
        data=frame(rows); base=Path(self.temp.name)/'partition-input'
        for (year,month), part in data.groupby([data.index.year,data.index.month]):
            directory=base/f'year={year}'/f'month={month}'
            directory.mkdir(parents=True)
            part.to_parquet(directory/'part.parquet')
        output=Path(self.temp.name)/'partition-output'
        self.engine.process_parquet_dataset_partitioned(str(base),str(output),overlap='8d',
            output_mode='sidecar',materialise_event_columns=True)
        saved=ds.dataset(output,format='parquet',partitioning='hive').to_table(
            columns=['chronosift_row_id','chronosift_score']).to_pylist()
        self.assertEqual(len(saved),3)
        self.assertEqual({r['chronosift_row_id'] for r in saved},{100,101,102})
        self.assertAlmostEqual(next(r['chronosift_score'] for r in saved if r['chronosift_row_id']==102),
            float(continuous.iloc[-1].chronosift_score))

    def test_lookup_and_selector_configuration_rejected_when_invalid(self):
        cfg=yaml.safe_load(RULES.read_text())
        cfg['normalisation'].append({'name':'bad','method':'identity_lookup','from':'x','key_field':'k'})
        with self.assertRaisesRegex(ValueError,'value_field'):
            c.ChronoSiftEngine(cfg,yaml.safe_load(WEIGHTS.read_text()))

if __name__=='__main__':
    unittest.main()
