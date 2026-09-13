"""Behavioural priority: changed identifiers, attempts and benign controls."""
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
from configure_web_roots import configure_web_roots
from tests.test_v231_linux_account_context import birth, reset, frame

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v21.yaml'
WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v19.yaml'

def sudo(command='./helper',actor='operator',runas='root',pwd='/home/operator',denial='',**extra):
    return dict(dict(parser='text/syslog_traditional',message=f'[sudo] {actor} : {denial}TTY=pts/3 ; PWD={pwd} ; USER={runas} ; COMMAND={command}'),**extra)

def ftp(direction='i',outcome='c',path='/srv/staging/quarterly.tgz',**extra):
    return dict(dict(parser='text/vsftpd',text=f'78 198.51.100.28 41881803 {path} b _ {direction} r supplier ftp 0 * {outcome}'),**extra)

def file(path='/etc/ld.so.preload',**extra):
    return dict(dict(parser='filestat',filename=path,file_entry_type='file',timestamp_desc='Creation Time'),**extra)

def http(path='/wp-admin/theme-editor.php',method='POST',status=302):
    return dict(parser='apache_access',http_request=f'{method} {path} HTTP/1.1',http_response_code=status)

class BehaviourPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.metadata=Path(cls.temp.name)/'fixture.yar'
        cls.metadata.write_text('rule TEST_WEBSHELL_Weak {\nmeta:\n score = 70\n quality = 85\ncondition:\n false\n}\n')
        cls.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.metadata))
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):logging.getLogger().setLevel(cls.level);cls.temp.cleanup()

    def run_rows(self,records,engine=None):
        engine=engine or self.engine
        out=engine.apply_contextual(engine.apply_atomic(frame(records),apply_profiling=False),apply_profiling=False)
        self.assertEqual(list(out.chronosift_row_id),list(range(900,900+len(records))))
        for explains,score in zip(out.get('chronosift_explain',[None]*len(out)),out.chronosift_score):
            self.assertAlmostEqual(min(50,sum(e.get('score_contribution',0) for e in (explains or []))),score)
        return out

    def signals(self,out,pos=-1):return out.iloc[pos].get('chronosift_signals') or {}

    def test_builder_idempotent(self):
        self.assertEqual(subprocess.check_output([sys.executable,'-B','-m','benchmarks.build_behaviour_policy'],cwd=ROOT,text=True),
            '*** Begin Patch\n*** End Patch\n')

    def test_allowed_root_writable_command_without_av(self):
        out=self.run_rows([('0s',sudo())]);row=out.iloc[0]
        self.assertEqual(row.linux_sudo_path,'/home/operator/helper')
        self.assertEqual(row.actor_user,'operator');self.assertEqual(row.linux_sudo_runas,'root')
        self.assertGreaterEqual(row.chronosift_score,23)
        self.assertIn('linux_sudo_privileged_writable',self.signals(out))
        self.assertIn('exec_privileged_context',self.signals(out))

    def test_denial_is_flagged_without_execution(self):
        for denial in ('user NOT in sudoers ; ','command not allowed ; ','3 incorrect password attempts ; '):
            out=self.run_rows([('0s',sudo(denial=denial))])
            self.assertIn('linux_sudo_denied',self.signals(out));self.assertEqual(out.iloc[0].chronosift_score,8)
            self.assertTrue(pd.isna(out.iloc[0].evidence_execution_path))
            self.assertTrue(pd.isna(out.iloc[0].evidence_execution_command))
            self.assertNotIn('exec_privileged_context',self.signals(out))

    def test_unknown_denial_and_wrong_parser_do_not_imply_allow(self):
        for row in (sudo(denial='unknown rejection ; '),sudo(parser='filestat'),sudo(message='documentation sudo ./helper')):
            out=self.run_rows([('0s',row)])
            self.assertNotIn('linux_sudo_allowed',self.signals(out))
            self.assertTrue(pd.isna(out.iloc[0].evidence_execution_path))

    def test_denied_sudo_revokes_generic_command_fallback(self):
        out=self.run_rows([('0s',sudo(denial='user NOT in sudoers ; ',command_line='/tmp/helper',actor_user='root'))])
        self.assertTrue(pd.isna(out.iloc[0].evidence_execution_command))
        self.assertNotIn('exec_privileged_context',self.signals(out))
        self.assertNotIn('linux_sudo_allowed',self.signals(out))

    def test_root_downshift_and_ordinary_system_commands_not_writable_escalation(self):
        out=self.run_rows([('0s',sudo(actor='root',runas='service',command='/usr/bin/id')),
                           ('1h',sudo(command='/usr/bin/id'))])
        self.assertNotIn('exec_privileged_context',self.signals(out,0))
        for pos in (0,1):self.assertNotIn('linux_sudo_privileged_writable',self.signals(out,pos))

    def test_command_quotes_and_case(self):
        out=self.run_rows([('0s',sudo(command='"./Helper Two" --flag'))])
        self.assertEqual(out.iloc[0].linux_sudo_path,'/home/operator/Helper Two')

    def test_path_resolution_has_no_shell_path_or_symlink_guess(self):
        for command in ('helper','../helper','./$TARGET','./a/../b','./`command`','//server/a'):
            out=self.run_rows([('0s',sudo(command=command))])
            self.assertTrue(pd.isna(out.iloc[0].linux_sudo_path),command)
        out=self.run_rows([('0s',sudo(command='/opt/Helper',pwd='/elsewhere'))])
        self.assertEqual(out.iloc[0].linux_sudo_path,'/opt/Helper')

    def test_new_account_sudo_scoped_bounded_and_reset(self):
        out=self.run_rows([('0s',birth(name='operator')),('1h',sudo()),('7d',sudo()),('7d1s',sudo())])
        self.assertIn('linux_recent_account_sudo',self.signals(out,1))
        self.assertIn('linux_recent_account_sudo',self.signals(out,2))
        self.assertNotIn('linux_recent_account_sudo',self.signals(out,3))
        for change in (reset(name='operator'),birth(name='operator')):
            out=self.run_rows([('0s',birth(name='operator')),('1h',change),('2h',sudo())])
            self.assertEqual('linux_recent_account_sudo' in self.signals(out),'useradd' in change['message'])

    def test_new_account_context_rejects_other_host_name_failed_and_missing_host(self):
        for row in (sudo(actor='other'),sudo(actor='Operator'),sudo(hostname='different'),sudo(hostname=None),sudo(denial='user NOT in sudoers ; ')):
            out=self.run_rows([('0s',birth(name='operator')),('1h',row)])
            self.assertNotIn('linux_recent_account_sudo',self.signals(out))

    def test_ftp_direction_and_completion_additive(self):
        for direction,outcome,score in [('i','c',15),('i','i',12),('o','c',23),('o','i',20)]:
            out=self.run_rows([('0s',ftp(direction,outcome))]);row=out.iloc[0]
            self.assertEqual(row.chronosift_score,score)
            self.assertEqual(row.ftp_direction,direction);self.assertEqual(row.ftp_outcome,outcome)
            self.assertEqual(row.ftp_account,'supplier');self.assertEqual(row.ftp_bytes,'41881803')

    def test_ftp_space_in_path_and_ordinary_file(self):
        out=self.run_rows([('0s',ftp(path='/srv/upload/client archive.zip')),('1h',ftp(path='/pub/README.txt'))])
        self.assertEqual(out.iloc[0].ftp_path,'/srv/upload/client archive.zip')
        self.assertEqual(out.iloc[1].chronosift_score,2)

    def test_ftp_delete_invalid_or_log_quote_not_transfer(self):
        for row in (ftp(direction='d'),ftp(outcome='x'),ftp(parser='filestat'),ftp(text='documentation: '+ftp()['text'])):
            out=self.run_rows([('0s',row)])
            self.assertNotIn('ftp_transfer_observed',self.signals(out))

    def test_preload_change_not_access_similar_name_or_directory(self):
        for desc in ('Creation Time','Content Modification Time','Metadata Modification Time'):
            out=self.run_rows([('0s',file(timestamp_desc=desc))])
            self.assertGreaterEqual(out.iloc[0].chronosift_score,24)
        for row in (file(timestamp_desc='Access Time'),file('/tmp/ld.so.preload'),file('/etc/ld.so.preload.old'),file(file_entry_type='directory')):
            self.assertNotIn('linux_preload_control_change',self.signals(self.run_rows([('0s',row)])))

    def test_dump_tools_are_not_database_exports(self):
        for path in ('/tmp/PwDump7.exe','/opt/dump-helper','/tmp/dump.txt','/dump/tool.exe'):
            out=self.run_rows([('0s',file(path))]);self.assertNotIn('database_dump_candidate',self.signals(out),path)
        for path in ('/tmp/export.sql','/tmp/customer.dump','/tmp/company-dump.tgz','/tmp/shop.sqlite'):
            out=self.run_rows([('0s',file(path))]);self.assertIn('database_dump_candidate',self.signals(out),path)

    def test_web_editor_attempt_even_denied_but_not_get(self):
        for status in (200,302,403,500):
            out=self.run_rows([('0s',http('/site/wp-admin/plugin-editor.php',status=status))])
            self.assertIn('web_admin_code_edit_attempt',self.signals(out));self.assertGreaterEqual(out.iloc[0].chronosift_score,12)
            self.assertNotIn('webshell_activity',self.signals(out))
        for row in (http(method='GET'),http('/notes/theme-editor.php'),http('/wp-login.php')):
            self.assertNotIn('web_admin_code_edit_attempt',self.signals(self.run_rows([('0s',row)])))

    def configured(self,*roots):
        doc=configure_web_roots(yaml.safe_load(RULES.read_text()),roots)
        target=Path(self.temp.name)/'configured.yaml';target.write_text(yaml.safe_dump(doc,sort_keys=False))
        return c.ChronoSiftEngine.from_yaml(target,WEIGHTS,yara_metadata_path=str(self.metadata))

    def test_explicit_renamed_nested_document_root_links_existing_shell_rules(self):
        engine=self.configured('/srv/tenant','/srv/tenant/deployment')
        path='/srv/tenant/deployment/plugins/Utility.php'
        out=self.run_rows([('0s',file(path,yara_match=['TEST_WEBSHELL_Weak'])),
            ('1m',http('/plugins/Utility.php','GET',200)),('2m',http('/wrong/Utility.php','GET',200))],engine)
        self.assertEqual(out.iloc[1].evidence_web_identity,path)
        self.assertIn('webshell_activity',self.signals(out,1))
        self.assertNotIn('webshell_activity',self.signals(out,2))

    def test_root_mapping_ambiguity_case_and_invalid_paths(self):
        engine=self.configured('/srv/one','/srv/two')
        out=self.run_rows([('0s',file('/srv/one/Utility.php')),('0s',file('/srv/two/Utility.php')),
            ('1m',http('/Utility.php','GET',200)),('2m',http('/utility.php','GET',200))],engine)
        self.assertTrue(pd.isna(out.iloc[2].evidence_web_identity));self.assertTrue(pd.isna(out.iloc[3].evidence_web_identity))
        for root in ('/','//','relative','/srv/../other','/srv\x00bad','/srv/./site'):
            with self.assertRaises(ValueError):self.configured(root)

    def test_path_schema_rejects_unknown_and_missing_keys(self):
        good=dict(name='derived',method='posix_path_resolve',**{'from':'child'},base_field='pwd')
        self.assertEqual(c._parse_normalisation_policy([good],'normalisation')[0].base_field,'pwd')
        for invalid in ({k:v for k,v in good.items() if k!='base_field'},dict(good,extra=True),dict(good,base_field='')):
            with self.assertRaises(ValueError):c._parse_normalisation_policy([invalid],'normalisation')


    def test_derived_facts_reject_forward_self_and_cycles(self):
        for dependency in ('database_dump','future_fact','unknown_fact'):
            doc=yaml.safe_load(RULES.read_text())
            facts=doc['detector_policy']['detectors']['file_lifecycle']['classification']['derived_predicates']
            facts['named_dump_archive']['all']=[dependency]
            with self.assertRaises(ValueError):
                c.ChronoSiftEngine(doc,yaml.safe_load(WEIGHTS.read_text()),yara_metadata_path=str(self.metadata))

    def test_native_compact_eager_account_sudo_parity(self):
        records=[('0s',birth(name='operator')),('2d',sudo()),('3d',reset(name='operator')),
            ('4d',sudo()),('5d',birth(name='operator')),('6d',sudo()),('13d1s',sudo())]
        data=frame(records);outputs=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            c.write_time_partitioned_parquet(data,str(root/'input'),normalise=False)
            for compact in (False,True):
                engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata))
                engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
                engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
                plan=engine.plan_partition_execution(str(root/'input'))
                self.assertEqual(plan['feature_seconds'],86400)
                self.assertEqual(engine.minimum_partition_overlap(),pd.Timedelta('199h'))
                dest=root/str(compact)
                reports=engine.process_parquet_dataset_partitioned(str(root/'input'),str(dest),output_mode='sidecar',materialise_event_columns=True)
                self.assertEqual(sum(x['rows_written'] for x in reports),len(data))
                outputs.append(c.load_plaso_parquet_dataset(str(dest)).set_index('chronosift_row_id').sort_index())
            self.assertEqual(outputs[0].chronosift_score.tolist(),outputs[1].chronosift_score.tolist())
            for out in outputs:
                for rid,present in ((901,True),(903,False),(905,True),(906,False)):
                    self.assertEqual('linux_recent_account_sudo' in (out.loc[rid].chronosift_signals or {}),present)

if __name__=='__main__':unittest.main()
