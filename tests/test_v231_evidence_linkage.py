"""Remaining Windows/web corrections, with unrelated-path and benign controls."""
from pathlib import Path
import logging
import subprocess
import sys
import tempfile
import unittest

import pandas as pd
import yaml
import chronoSIFT_v2_31 as c

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v14.yaml'
WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v13.yaml'
META='''rule TEST_WEBSHELL_Weak
{
  meta:
    score = 70
    quality = 85
  condition:
    false
}
rule TEST_MALWARE_Strong
{
  meta:
    score = 85
    quality = 90
  condition:
    false
}
'''

class EvidenceLinkageTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(logging.getLogger().setLevel,logging.getLogger().level)
        logging.getLogger().setLevel(logging.ERROR)
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.metadata=Path(self.temp.name)/'fixture.yar'; self.metadata.write_text(META)
        self.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata))

    def rows(self,*records):
        data=pd.DataFrame([{'chronosift_row_id':700+i,'hostname':'test-host',**record} for i,record in enumerate(records)])
        data.index=pd.date_range('2024-06-30T23:58:00Z',periods=len(data),freq='min',name='datetime')
        return self.engine.apply_contextual(self.engine.apply_atomic(data,apply_profiling=False),apply_profiling=False)

    def test_builder_fidelity(self):
        self.assertEqual(subprocess.check_output([sys.executable,'-B',str(ROOT/'benchmarks/build_evidence_linkage_policy.py')],text=True),'*** Begin Patch\n*** End Patch\n')

    def test_missing_rule_metadata_fails(self):
        for replaced in (META.replace('quality = 85','unused = 85'),META.replace('quality = 85','quality = invalid')):
            self.metadata.write_text(replaced)
            with self.assertRaisesRegex(ValueError,'quality'):
                c.parse_yara_forge_metadata(str(self.metadata),self.engine.detector_policy.yara_classification)

    def test_recorded_negative_quality_is_not_missing(self):
        self.metadata.write_text(META.replace('quality = 85','quality = -107'))
        index=c.parse_yara_forge_metadata(str(self.metadata),self.engine.detector_policy.yara_classification)
        self.assertEqual(index['TEST_WEBSHELL_Weak'].quality,0)

    def test_unindexed_match_fails_direct_and_reference_routes(self):
        with self.assertRaisesRegex(ValueError,'no indexed'):
            self.rows(dict(parser='filestat',filename='/var/www/html/unknown.php',yara_match=['UNKNOWN']))
        with self.assertRaisesRegex(ValueError,'no indexed'):
            c._web_relevant_yara_rule_evidence(['UNKNOWN'],self.engine.yara_metadata_index,self.engine.detector_policy.yara_classification)

    def test_local_uri_is_not_web_exploitation(self):
        for url in ('file:///C:/Users/visitor/doc.txt','ftp://example.test/collection.zip','smb://host/share/item'):
            out=self.rows(dict(parser='esedb/msie_webcache',url=url,filename=r'C:\Users\visitor\WebCache.dat'))
            self.assertFalse(out.iloc[0].chronosift_web_is_event)
            self.assertNotIn('exploit_public_facing_app',out.iloc[0].get('chronosift_signals',{}))
            self.assertNotIn('exec_from_user_writable',out.iloc[0].get('chronosift_signals',{}))

    def test_file_scheme_inside_http_query_remains_lfi_evidence(self):
        out=self.rows(dict(parser='apache_access',http_request='GET /index.php?page=file:///etc/passwd HTTP/1.1',http_response_code=404))
        self.assertTrue(out.iloc[0].chronosift_web_is_event)
        self.assertIn('local_file_inclusion',out.iloc[0].chronosift_web_attack_indicators)

    def test_userassist_uses_program_path_not_hive(self):
        out=self.rows(dict(parser='winreg/userassist',timestamp_desc='Last Execution Time',filename=r'C:\Users\visitor\NTUSER.DAT',
            message=r'[HKCU\Software\UserAssist] Value name: UEME_RUNPATH:C:\Windows\System32\NOTEPAD.EXE Count: 14'))
        self.assertEqual(out.iloc[0].evidence_execution_path,r'C:\Windows\System32\NOTEPAD.EXE')
        self.assertNotIn('exec_from_user_writable',out.iloc[0].get('chronosift_signals',{}))
        self.assertIn('windows_program_execution',out.iloc[0].get('chronosift_signals',{}))

    def test_real_execution_from_user_path_retained(self):
        out=self.rows(dict(parser='winevtx',event_identifier=4688,source_name='Microsoft-Windows-Security-Auditing',new_process_name=r'C:\Users\visitor\payload.exe'))
        self.assertIn('exec_from_user_writable',out.iloc[0].get('chronosift_signals',{}))

    def test_weak_shell_gains_same_file_context_not_qualified_metadata(self):
        out=self.rows(dict(parser='filestat',filename='/var/www/html/admin_shell.php',timestamp_desc='Creation Time',yara_match=['TEST_WEBSHELL_Weak']),
            dict(parser='apache_access',http_request='GET /admin_shell.php HTTP/1.1',http_response_code=200),
            dict(parser='apache_access',http_request='GET /different.php?cmd=id HTTP/1.1',http_response_code=200))
        self.assertEqual(out.iloc[1].evidence_web_identity,'/var/www/html/admin_shell.php')
        self.assertIn('webshell_activity',out.iloc[1].get('chronosift_signals',{}))
        self.assertNotIn('web_confirmed_webshell_access',out.iloc[1].get('chronosift_signals',{}))
        self.assertNotIn('webshell_activity',out.iloc[2].get('chronosift_signals',{}))

    def test_case_sensitive_and_ambiguous_web_aliases_reject_linkage(self):
        source=dict(parser='filestat',filename='/var/www/html/Utility.php',timestamp_desc='Creation Time',yara_match=['TEST_WEBSHELL_Weak'])
        out=self.rows(source,dict(parser='apache_access',http_request='GET /utility.php HTTP/1.1',http_response_code=200))
        self.assertTrue(pd.isna(out.iloc[1].evidence_web_identity))
        out=self.rows(source,{**source,'filename':'/srv/www/Utility.php'},dict(parser='apache_access',http_request='GET /Utility.php HTTP/1.1',http_response_code=200))
        self.assertTrue(pd.isna(out.iloc[2].evidence_web_identity))

    def test_database_command_and_metadata_are_distinct(self):
        out=self.rows(dict(parser='bash_history',message='mysql -e "DROP DATABASE olddata"'),
            dict(parser='filestat',filename='/var/lib/mysql/shop/customer.ibd',timestamp_desc='Modification Time'),
            dict(parser='filestat',filename='/var/lib/mysql/shop/customer.ibd',timestamp_desc='Deletion Time'))
        self.assertIn('evidence_database_destructive_command',out.iloc[0].get('chronosift_signals',{}))
        self.assertNotIn('evidence_database_delete',out.iloc[1].get('chronosift_signals',{}))
        self.assertIn('evidence_database_delete',out.iloc[2].get('chronosift_signals',{}))

    def test_powershell_host_application_is_command_not_container_text(self):
        for separator in ('\r\n',r'\r\n'):
            command='powershell.exe -NoProfile -Command Get-Process'
            xml='<Event><EventData><Data>HostApplication='+command+separator+'EngineVersion=5.1</Data></EventData></Event>'
            out=self.rows(dict(parser='winevtx',source_name='PowerShell',event_identifier=400,xml_string=xml),
                dict(parser='filestat',source_name='unrelated',filename='/notes.txt',xml_string=xml),
                dict(parser='winevtx',source_name='PowerShell',event_identifier=400,message='Documentation mentions powershell.exe'))
            self.assertEqual(out.iloc[0].evidence_execution_command,command)
            self.assertGreater(out.iloc[0].chronosift_score,0)
            self.assertTrue(pd.isna(out.iloc[1].evidence_execution_command))
            self.assertTrue(pd.isna(out.iloc[2].evidence_execution_command))

    def test_gpo_change_requires_change_event_not_access(self):
        base=dict(parser='winevtx',source_name='Microsoft-Windows-Security-Auditing',xml_string='<Event><EventData><Data Name="ObjectClass">groupPolicyContainer</Data></EventData></Event>')
        out=self.rows({**base,'event_identifier':4662},{**base,'event_identifier':5136})
        self.assertNotIn('evidence_gpo_directory_change',out.iloc[0].get('chronosift_signals') or {})
        self.assertIn('evidence_gpo_directory_change',out.iloc[1].get('chronosift_signals',{}))

    def test_gpo_mutating_access_includes_create_child_and_combined_masks(self):
        for mask,expected in [('0x1',True),('0x21',True),('0x10',False),('0x4',False),('bad',False)]:
            out=self.rows(dict(parser='winevtx',source_name='Microsoft-Windows-Security-Auditing',event_identifier=4662,
                evidence_gpo_access_mask=mask,evidence_gpo_detail='CN={object},CN=Policies,CN=System,DC=sample'))
            self.assertEqual('evidence_gpo_change_operation' in (out.iloc[0].get('chronosift_signals') or {}),expected,mask)

    def test_task_domain_qualification_rejects_same_name_wrong_domain(self):
        sid='S-1-5-21-101-202-303-1501'
        base=dict(parser='winevtx',event_identifier=4624,target_user_name='maint',target_domain_name='DOMAIN_A',win_target_sid=sid)
        out=self.rows(base,dict(parser='winevtx',event_identifier=106,source_name='Microsoft-Windows-TaskScheduler',win_task_user=r'DOMAIN_A\maint'),
            dict(parser='winevtx',event_identifier=106,source_name='Microsoft-Windows-TaskScheduler',win_task_user=r'DOMAIN_B\maint'))
        self.assertEqual(out.iloc[1].evidence_task_domain_sid,sid)
        self.assertTrue(pd.isna(out.iloc[2].evidence_task_domain_sid))
        self.assertTrue(pd.isna(out.iloc[2].win_context_sid))

    def test_yara_only_malware_path_use_and_exact_hash_count_once(self):
        digest='a'*64
        file=dict(parser='filestat',filename=r'\Users\maint\sample.exe',timestamp_desc='Creation Time',sha256_hash=digest,yara_match=['TEST_MALWARE_Strong'])
        use=dict(parser='esedb/srum',data_type='windows:srum:application_usage',application=r'\Device\HarddiskVolume2\Users\maint\sample.exe',sha256_hash='b'*64)
        out=self.rows(file,use,{**use,'chronosift_executed_sha256':digest})
        self.assertIn('evidence_qualified_malware_file',out.iloc[0].get('chronosift_signals') or {})
        self.assertAlmostEqual(out.iloc[1].chronosift_signals['windows_malware_use_priority']*42,26)
        self.assertAlmostEqual(out.iloc[2].chronosift_signals['windows_malware_use_priority']*42,42)
        self.assertNotIn('windows_malware_execution',out.iloc[1].chronosift_signals)

    def test_ambiguous_payload_versions_do_not_resolve_by_path(self):
        base=dict(parser='filestat',filename=r'\Users\maint\sample.exe',timestamp_desc='Creation Time',yara_match=['TEST_MALWARE_Strong'])
        out=self.rows({**base,'sha256_hash':'a'*64},{**base,'sha256_hash':'b'*64},
            dict(parser='esedb/srum',data_type='windows:srum:application_usage',application=r'\Device\HarddiskVolume2\Users\maint\sample.exe'))
        self.assertTrue(pd.isna(out.iloc[2].evidence_payload_identity))
        self.assertNotIn('windows_malware_use_priority',out.iloc[2].get('chronosift_signals') or {})

    def test_windows_web_root_alias_is_not_a_basename(self):
        for path in (r'\xampp\htdocs\APP\panel_shell.php',r'\\xampp\\htdocs\\APP\\panel_shell.php',
                     r'C:\XAMPP\HTDOCS\APP\panel_shell.php',r'NTFS:\xampp\htdocs\APP\panel_shell.php'):
            with self.subTest(path=path):
                out=self.rows(dict(parser='filestat',filename=path,timestamp_desc='Creation Time'),
                    dict(parser='apache_access',http_request='GET /app/panel_shell.php HTTP/1.1',http_response_code=200),
                    dict(parser='apache_access',http_request='GET /wrong/panel_shell.php HTTP/1.1',http_response_code=200))
                self.assertEqual(out.iloc[1].evidence_web_identity,path)
                self.assertIn('webshell_activity',out.iloc[1].get('chronosift_signals') or {})
                self.assertTrue(pd.isna(out.iloc[2].evidence_web_identity))

    def test_recent_dump_identity_boundary_and_supporting_integer_ids(self):
        for seconds,expected in [(1800,True),(1801,False)]:
            data=pd.DataFrame({'chronosift_row_id':[91,92], 'evidence_web_identity':['/var/www/html/export.sql']*2},
                index=pd.DatetimeIndex([pd.Timestamp('2024-06-30T23:55:00Z'),pd.Timestamp('2024-06-30T23:55:00Z')+pd.Timedelta(seconds=seconds)]))
            signals={0:{'evidence_web_file_created':1},1:{'web_sensitive_file_download':1}}; explain={}
            self.engine._apply_temporal_rules_sparse(data,signals,explain)
            self.assertEqual('web_recent_file_sensitive_download' in signals[1],expected)
            if expected:
                self.assertIn('91',str(explain[1])); self.assertIn('92',str(explain[1]))

    def test_tied_timestamps_remain_distinct_rows(self):
        data=pd.DataFrame([dict(chronosift_row_id=91,parser='filestat',filename='/var/www/html/export.sql',timestamp_desc='Creation Time'),
            dict(chronosift_row_id=92,parser='apache_access',http_request='GET /export.sql HTTP/1.1')],index=pd.DatetimeIndex(['2024-06-30T23:55:00Z']*2))
        out=self.engine.apply_atomic(data,apply_profiling=False)
        self.assertEqual(out.chronosift_row_id.tolist(),[91,92])
        self.assertEqual(out.evidence_web_identity.tolist(),['/var/www/html/export.sql']*2)

if __name__=='__main__': unittest.main()
