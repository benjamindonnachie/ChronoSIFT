"""Low-information observations versus supported behaviour, without allowlists."""
from dataclasses import replace
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import pandas as pd
import yaml
import chronoSIFT_v2_31 as c
from configure_web_roots import configure_web_roots
from tests.test_v231_linux_account_context import frame
from tests.test_v231_behaviour_policy import file, http

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v22.yaml'
WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v20.yaml'


def cron(command='run-parts /etc/cron.hourly',actor='root',**extra):
    return dict(dict(parser='text/syslog_traditional',message=f'[CROND, pid: 42] ({actor}) CMD ({command})'),**extra)


class RankingPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.meta=Path(cls.temp.name)/'fixture.yar'
        cls.meta.write_text('\n'.join('rule '+name+' {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n'
            for name in ['TEST_WEBSHELL_Strong','TEST_Hacktool_Strong','TEST_MALWARE_Strong']))
        cls.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.meta))
        cls.old=c.ChronoSiftEngine.from_yaml(ROOT/'rules/rules_evidence_calibrated_v21.yaml',ROOT/'rules/weights_evidence_calibrated_v19.yaml',yara_metadata_path=str(cls.meta))
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup();logging.getLogger().setLevel(cls.level)

    def run_rows(self,records,engine=None):
        engine=engine or self.engine
        out=engine.apply_contextual(engine.apply_atomic(frame(records),apply_profiling=False),apply_profiling=False)
        self.assertEqual(out.chronosift_row_id.tolist(),list(range(900,900+len(records))))
        for _,row in out.iterrows():
            self.assertAlmostEqual(min(50,sum(e.get('score_contribution',0) for e in (row.get('chronosift_explain') or []))),row.chronosift_score)
        return out

    def signals(self,out,pos=-1):return out.iloc[pos].get('chronosift_signals') or {}

    def test_builder_idempotent(self):
        self.assertEqual(subprocess.check_output([sys.executable,'-B','-m','benchmarks.build_ranking_policy'],cwd=ROOT,text=True),'*** Begin Patch\n*** End Patch\n')

    def test_routine_cron_not_automatically_interpreter(self):
        for command in ['run-parts /etc/cron.hourly','/usr/bin/true','echo python3 /tmp/helper.py','/usr/bin/python-report']:
            out=self.run_rows([('0s',cron(command))]);s=self.signals(out)
            self.assertFalse(s.get('interpreter_exec_linux'),command)
            self.assertEqual(out.iloc[0].chronosift_score,3,command)

    def test_real_interpreters_retain_context(self):
        for command in ['python3 /opt/maintenance.py','nohup /usr/bin/python3.11 /opt/check.py &',
            '"/usr/bin/python3" /opt/check.py','cd /opt && nohup python3 check.py &','/opt/Tool/nohup python3 check.py &','/bin/bash /opt/backup.sh']:
            out=self.run_rows([('0s',cron(command))])
            self.assertTrue(self.signals(out).get('interpreter_exec_linux'),command)
        out=self.run_rows([('0s',cron('python3 /opt/maintenance.py'))])
        self.assertEqual(out.iloc[0].chronosift_score,6)

    def test_cron_wrapper_requires_parser(self):
        out=self.run_rows([('0s',cron('python3 /tmp/check.py',parser='filestat'))])
        self.assertFalse(self.signals(out).get('interpreter_exec_linux'))

    def qualified(self,repository=False,actor='root'):
        rows=[('0s',file('/opt/Renamed/linux/collector.py',yara_match=[] if repository else ['TEST_Hacktool_Strong']))]
        if repository:rows += [('0s',file('/opt/Renamed/.git/HEAD')),('0s',file('/opt/Renamed/mac/source.c',yara_match=['TEST_Hacktool_Strong']))]
        rows += [(t,cron('nohup python3 /opt/Renamed/linux/collector.py &',actor)) for t in ['1m','2m','3m']]
        return rows

    def test_qualified_exact_and_repository_scores_preserved(self):
        for repository in (False,True):
            for actor in ('root','maintainer'):
                rows=self.qualified(repository,actor)
                old=self.run_rows(rows,self.old);new=self.run_rows(rows)
                self.assertEqual(old.chronosift_score.tolist(),new.chronosift_score.tolist())
                self.assertGreater(new.iloc[-1].chronosift_score,new.iloc[-3].chronosift_score)
                self.assertTrue(any(self.signals(new).get('linux_qualified_'+route+'_schedule_repetition') for route in ('file','repository')))

    def test_qualified_context_does_not_cross_host_or_expiry(self):
        for event in ('different_host','expired'):
            rows=[('0s',file('/opt/Renamed/linux/collector.py',yara_match=['TEST_Hacktool_Strong'])),
                ('24h1s' if event=='expired' else '1m',cron('python3 /opt/Renamed/linux/collector.py',**({'hostname':'other'} if event=='different_host' else {})))]
            out=self.run_rows(rows)
            self.assertFalse(any(self.signals(out).get('linux_qualified_'+route+'_schedule_context') for route in ('file','repository')))

    def test_exact_route_wins_without_double_repository_context(self):
        rows=self.qualified(repository=True)
        rows[0][1]['yara_match']=['TEST_Hacktool_Strong']
        old=self.run_rows(rows,self.old);out=self.run_rows(rows)
        self.assertEqual(old.chronosift_score.tolist(),out.chronosift_score.tolist())
        for pos in (-1,-2,-3):
            signals=self.signals(out,pos)
            self.assertTrue(signals.get('linux_qualified_file_invocation'))
            self.assertFalse(signals.get('linux_qualified_repository_invocation'))
            self.assertFalse(signals.get('linux_qualified_repository_schedule_context'))

    def test_repetition_without_payload_stays_low(self):
        out=self.run_rows([(t,cron()) for t in ['0s','1m','2m']])
        self.assertTrue(self.signals(out).get('repeated_scheduled_exec'))
        self.assertEqual(out.iloc[-1].chronosift_score,4)
        self.assertFalse(any(self.signals(out).get('linux_qualified_'+route+'_schedule_repetition') for route in ('file','repository')))

    def test_bare_unit_changes_low_but_visible(self):
        for prefix in ['/etc','/lib','/usr/lib']:
            out=self.run_rows([('0s',file(prefix+'/systemd/system/renamed.service'))])
            self.assertAlmostEqual(out.iloc[0].chronosift_score,4)
            self.assertGreater(self.signals(out).get('systemd_service_persistence',0),0)

    def test_malware_supported_unit_and_management_commands_not_dampened(self):
        for row in [file('/etc/systemd/system/renamed.service',yara_match=['TEST_MALWARE_Strong']),
            dict(parser='bash_history',command_line='systemctl enable renamed.service')]:
            old=self.run_rows([('0s',row)],self.old);new=self.run_rows([('0s',row)])
            self.assertEqual(old.chronosift_score.tolist(),new.chronosift_score.tolist())

    def test_access_and_windows_not_dampened(self):
        for row in [file('/etc/systemd/system/renamed.service',timestamp_desc='Access Time'),
            file('C:/Windows/System32/config/SYSTEM/CurrentControlSet/Services/renamed.service',parser='mft')]:
            old=self.run_rows([('0s',row)],self.old);new=self.run_rows([('0s',row)])
            self.assertEqual(old.chronosift_score.tolist(),new.chronosift_score.tolist())

    def test_weak_basename_does_not_establish_shell_or_use(self):
        for basename in ['async-upload.php','c99.php','shell-helper.php']:
            out=self.run_rows([('0s',file('/var/www/html/'+basename)),('1m',http('/'+basename,'GET',200))])
            self.assertEqual(self.signals(out,0).get('webshell_name_hint'),1)
            self.assertEqual(out.iloc[0].chronosift_score,10)
            for i in (0,1):
                for name in ['webshell_artifact','webshell_activity','web_upload_execution_chain']:
                    self.assertFalse(self.signals(out,i).get(name),(basename,name))

    def test_generic_message_or_nonweb_path_not_shell_hint(self):
        for row in [file('/var/www/html/Utility.php',message='upload multipart/form-data filename=shell.php'),
            file('/tmp/upload.php'),file('/var/www/html/upload/readme.php'),file('/var/www/html/upload.txt'),
            file('/var/www/html/upload.php',parser='text/syslog_traditional')]:
            out=self.run_rows([('0s',row)])
            self.assertFalse(self.signals(out).get('webshell_name_hint'))
            self.assertFalse(self.signals(out).get('webshell_artifact'))

    def test_real_category_support_survives_innocuous_and_weak_names(self):
        for basename in ['Utility.php','async-upload.php']:
            records=[('0s',file('/var/www/html/'+basename,yara_match=['TEST_WEBSHELL_Strong'])),('1m',http('/'+basename,'GET',200))]
            old=self.run_rows(records,self.old);out=self.run_rows(records)
            self.assertTrue(self.signals(out,0).get('webshell_artifact'))
            self.assertFalse(self.signals(out,0).get('webshell_name_hint'))
            self.assertTrue(self.signals(out,1).get('webshell_activity'))
            self.assertEqual(old.chronosift_score.tolist(),out.chronosift_score.tolist())

    def test_configured_roots_and_ambiguity(self):
        doc=configure_web_roots(yaml.safe_load(RULES.read_text()),['/srv/tenant','/srv/tenant/deployment'])
        engine=c.ChronoSiftEngine(doc,yaml.safe_load(WEIGHTS.read_text()),yara_metadata_path=str(self.meta))
        out=self.run_rows([('0s',file('/srv/tenant/deployment/Utility.php',yara_match=['TEST_WEBSHELL_Strong'])),
            ('1m',http('/Utility.php','GET',200)),('2m',http('/utility.php','GET',200))],engine)
        self.assertTrue(self.signals(out,1).get('webshell_activity'))
        self.assertFalse(self.signals(out,2).get('webshell_activity'))

    def test_av_classification_and_all_av_weights_unchanged(self):
        before=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v21.yaml').read_text())
        after=yaml.safe_load(RULES.read_text())
        self.assertEqual(before['detector_policy']['detectors']['clamav_classification'],after['detector_policy']['detectors']['clamav_classification'])
        before=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v19.yaml').read_text())['weights']
        after=yaml.safe_load(WEIGHTS.read_text())['weights']
        self.assertEqual({k:v for k,v in before.items() if k.startswith(('av_','ransomware_'))},
                         {k:v for k,v in after.items() if k.startswith(('av_','ransomware_'))})

    def test_native_compact_eager_qualified_cron_parity(self):
        data=frame(self.qualified(repository=True))
        data.index=data.index+pd.Timedelta('58m')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c.write_time_partitioned_parquet(data,str(root/'input'),normalise=False)
            outputs=[]
            for compact in (False,True):
                engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.meta))
                engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
                engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
                reports=engine.process_parquet_dataset_partitioned(str(root/'input'),str(root/str(compact)),output_mode='sidecar',materialise_event_columns=True)
                self.assertEqual(sum(x['rows_written'] for x in reports),len(data))
                outputs.append(c.load_plaso_parquet_dataset(str(root/str(compact))).set_index('chronosift_row_id').sort_index())
            self.assertEqual(outputs[0].chronosift_score.tolist(),outputs[1].chronosift_score.tolist())
            self.assertEqual(outputs[1].chronosift_score.tolist(),self.run_rows(self.qualified(repository=True)).chronosift_score.tolist())


if __name__=='__main__':unittest.main()
