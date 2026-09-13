"""Qualified Linux invocation outranks failed guesses without inventing effects."""
from dataclasses import replace
from pathlib import Path
import logging
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
import yaml
import chronoSIFT_v2_31 as c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'rules/rules_evidence_calibrated_v19.yaml'
WEIGHTS = ROOT / 'rules/weights_evidence_calibrated_v16.yaml'
META = '''rule TEST_Hacktool_Strong {
 meta:
  score = 75
  quality = 80
 condition:
  false
}
'''


class LinuxToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)
        cls.temp = tempfile.TemporaryDirectory()
        cls.meta = Path(cls.temp.name) / 'fixture.yar'
        cls.meta.write_text(META)
        cls.engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(cls.meta))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        logging.getLogger().setLevel(cls.level)

    def file(self, path, **kw):
        return dict(parser='filestat', file_entry_type='file', filename=path,
                    timestamp_desc='Content Modification Time', sha256_hash=None, **kw)

    def cron(self, command='nohup python3 /opt/Tool/linux/collector.py &', **kw):
        return dict(parser='text/syslog_traditional', message=f'[CROND, pid: 42] (root) CMD ({command})', **kw)

    def frame(self, *records, start='2024-05-31T23:57:00Z'):
        frame = pd.DataFrame([dict(chronosift_row_id=9000+i, hostname=None, **row) for i, row in enumerate(records)])
        frame.index = pd.date_range(start, periods=len(frame), freq='min', name='datetime')
        return frame

    def fixture(self, **kw):
        return self.frame(self.file('/opt/Tool/.git/HEAD'),
            self.file('/opt/Tool/mac/source.c', yara_match=['TEST_Hacktool_Strong']),
            self.file('/opt/Tool/linux/collector.py'), self.cron(**kw), self.cron(**kw), self.cron(**kw))

    def score(self, data, engine=None):
        engine = engine or self.engine
        return engine.apply_contextual(engine.apply_atomic(data, apply_profiling=False), apply_profiling=False)

    def signals(self, row):
        value = row.get('chronosift_signals')
        return value if isinstance(value, dict) else {}

    def linked(self, row):
        return any(self.signals(row).get(name, 0) > 0 for name in
                   ('linux_qualified_repository_invocation', 'linux_qualified_file_invocation'))

    def test_builder_fidelity(self):
        self.assertEqual(subprocess.check_output([sys.executable, '-B', str(ROOT / 'benchmarks/build_linux_tool_policy.py')], text=True),
                         '*** Begin Patch\n*** End Patch\n')

    def test_repository_link_and_repetition(self):
        out = self.score(self.fixture())
        self.assertTrue(self.signals(out.iloc[1]).get('qualified_tool_file'))
        for pos in (3, 4, 5):
            self.assertTrue(self.signals(out.iloc[pos]).get('linux_qualified_repository_invocation'))
            self.assertEqual(out.iloc[pos].actor_user, 'root')
            self.assertEqual(out.iloc[pos].actor_principal, 'root')
            self.assertGreaterEqual(out.iloc[pos].chronosift_score, 31)
        self.assertGreater(out.iloc[5].chronosift_score, out.iloc[3].chronosift_score)
        self.assertFalse(self.linked(out.iloc[2]))
        explanation = next(x for x in out.iloc[3].chronosift_explain if x['rule_id'] == 'LINUX_QUALIFIED_REPOSITORY_INVOCATION')
        self.assertEqual(explanation['evidence']['source_row_id'], 9001)
        self.assertEqual(explanation['evidence']['target_file_row_id'], 9002)
        self.assertEqual(explanation['evidence']['marker_row_id'], 9000)
        self.assertEqual(explanation['confidence'], 'low')
        self.assertEqual(explanation['score_contribution'], 18)
        for _, row in out.iterrows():
            explanations = row.get('chronosift_explain')
            if isinstance(explanations, list):
                self.assertAlmostEqual(min(50, sum(x.get('score_contribution', 0) for x in explanations)), row.chronosift_score)

    def test_exact_path_is_stronger_without_repository(self):
        out = self.score(self.frame(self.file('/opt/Tool/linux/collector.py', yara_match=['TEST_Hacktool_Strong']), self.cron()))
        self.assertTrue(self.signals(out.iloc[1]).get('linux_qualified_file_invocation'))
        self.assertFalse(self.signals(out.iloc[1]).get('linux_qualified_repository_invocation'))
        self.assertGreaterEqual(out.iloc[1].chronosift_score, 39)

    def test_explicit_directory_and_malformed_prefix_are_honest_references(self):
        for command, basis in (
            ('cd /opt/Tool/linux && nohup python3 collector.py &', 'working_directory'),
            ('/opt/Tool/linux/nohup python3 collector.py &', 'prefix_directory_hint')):
            with self.subTest(command=command):
                out = self.score(self.fixture(command=command))
                self.assertTrue(self.linked(out.iloc[3]))
                item = next(x for x in out.iloc[3].chronosift_explain if x['rule_id'] == 'LINUX_QUALIFIED_REPOSITORY_INVOCATION')
                self.assertEqual(item['evidence']['reference_basis'], basis)
                self.assertEqual(item['evidence']['command'], command)
                self.assertIn('unproved', item['evidence']['outcome'])

    def test_unsafe_unbound_and_unrelated_references(self):
        commands = ('python3 collector.py', 'python3 /opt/tool/linux/collector.py',
            'python3 /opt/Tool-other/linux/collector.py', 'python3 /opt/Tool/linux/../linux/collector.py',
            'python3 $ROOT/linux/collector.py', 'python3 /opt/Tool/linux/collector.py; echo done',
            'echo python3 /opt/Tool/linux/collector.py')
        for command in commands:
            with self.subTest(command=command):
                self.assertFalse(self.linked(self.score(self.fixture(command=command)).iloc[3]))

    def test_missing_marker_target_and_unqualified_source(self):
        for pos in (0, 1, 2):
            data = self.fixture()
            data.iloc[pos, data.columns.get_loc('filename')] = '/unrelated/file'
            self.assertFalse(self.linked(self.score(data).iloc[3]))
        data = self.fixture()
        data['yara_match'] = None
        self.assertFalse(self.linked(self.score(data).iloc[3]))

    def test_weak_metadata_does_not_qualify(self):
        path = Path(self.temp.name) / 'weak.yar'
        path.write_text(META.replace('score = 75', 'score = 10'))
        engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(path))
        self.assertFalse(self.linked(self.score(self.fixture(), engine).iloc[3]))

    def test_known_host_mismatch_and_unknown_host_do_not_pool(self):
        data = self.fixture()
        data['hostname'] = 'a'
        for other in ('b', None):
            data.iloc[3:, data.columns.get_loc('hostname')] = other
            self.assertFalse(self.linked(self.score(data).iloc[3]))

    def test_future_and_expired_sources_do_not_link(self):
        data = self.fixture()
        data.index = pd.DatetimeIndex(['2024-05-01T00:00Z', '2024-05-01T00:01Z', '2024-05-01T00:02Z',
                                      '2024-05-03T00:00Z', '2024-05-03T00:01Z', '2024-05-03T00:02Z'], name='datetime')
        self.assertFalse(self.linked(self.score(data).iloc[3]))
        data = self.fixture().iloc[[3, 0, 1, 2]].reset_index(drop=True)
        data.index = pd.date_range('2024-05-01', periods=4, freq='min', tz='UTC', name='datetime')
        self.assertFalse(self.linked(self.score(data).iloc[0]))

    def test_nested_repository_does_not_inherit_parent_tool(self):
        data = self.frame(self.file('/opt/Tool/.git/HEAD'), self.file('/opt/Tool/mac/source.c', yara_match=['TEST_Hacktool_Strong']),
            self.file('/opt/Tool/linux/.git/HEAD'), self.file('/opt/Tool/linux/collector.py'), self.cron())
        self.assertFalse(self.linked(self.score(data).iloc[-1]))

    def test_failed_ssh_low_success_escalation_retained(self):
        out = self.score(self.frame(
            dict(parser='text/syslog_traditional', message='[sshd] Failed password for invalid user root\\r from 192.0.2.10 port 23 ssh2'),
            dict(parser='text/syslog_traditional', message='[sshd] Invalid user admin\\r from 192.0.2.10 port 24'),
            dict(parser='text/syslog_traditional', message='[sshd] Failed password for root from 192.0.2.10 port 24 ssh2'),
            dict(parser='text/syslog_traditional', message='Successful login of user: root from 192.0.2.10:25 using authentication method: password ssh pid: 123'),
            dict(parser='text/syslog_traditional', message='[sshd] Disconnected from 192.0.2.10 port 25')))
        for pos in (0, 1, 2):
            signals = self.signals(out.iloc[pos])
            self.assertLessEqual(out.iloc[pos].chronosift_score, 2)
            for name in ('privileged_login', 'exec_privileged_context', 'auth_pivot_accounts_from_same_src', 'ssh_success'):
                self.assertFalse(signals.get(name, 0), (pos, name, signals))
        success = self.signals(out.iloc[3])
        self.assertTrue(success.get('ssh_success'))
        self.assertTrue(success.get('auth_remote_success'))
        self.assertTrue(success.get('fail_then_success_ip'))
        self.assertEqual(out.iloc[3].auth_outcome, 'success')
        self.assertFalse(self.signals(out.iloc[4]).get('auth_pivot_accounts_from_same_src'))

    def test_real_successful_account_pivot_remains(self):
        out = self.score(self.frame(*[dict(parser='text/syslog_traditional', message=f'[sshd] Accepted password for {user} from 192.0.2.10 port 22 ssh2') for user in ('root', 'admin')]))
        self.assertTrue(self.signals(out.iloc[1]).get('auth_pivot_accounts_from_same_src'))

    def test_non_auth_failed_text_is_not_authentication(self):
        out = self.score(self.frame(dict(parser='text/apache_access', message='GET /failed/ HTTP/1.1'),
            dict(parser='systemd_journal', message='Failed to resolve name for update service')))
        for _, row in out.iterrows():
            self.assertFalse(self.signals(row).get('auth_fail_generic'))

    def test_duplicate_timestamps_keep_distinct_integer_ids(self):
        data = self.fixture()
        data.index = pd.DatetimeIndex(['2024-05-01T00:00:00.123456789Z'] * len(data), name='datetime')
        out = self.score(data)
        self.assertEqual(out.chronosift_row_id.tolist(), list(range(9000, 9006)))
        self.assertTrue(all(self.linked(out.iloc[i]) for i in (3, 4, 5)))

    def test_policy_validation_and_input_dependency_tracking(self):
        fields = set(self.engine._contextual_required_columns())
        self.assertTrue({'file_entry_type', 'filename', 'linux_cron_command', 'sha256_hash', 'chronosift_row_id'} <= fields)
        for replacement in (dict(lookback='0h'), dict(source_signals=['UNKNOWN_SIGNAL']),
                            dict(marker_pattern=r'(.+)'), dict(references={'bad': r'.+'})):
            policy = yaml.safe_load(RULES.read_text())
            policy['detector_policy']['detectors']['linux_qualified_tool_invocation'].update(replacement)
            path = Path(self.temp.name) / 'invalid.yaml'
            path.write_text(yaml.safe_dump(policy, sort_keys=False))
            with self.assertRaises(ValueError):
                c.ChronoSiftEngine.from_yaml(path, WEIGHTS)

    def test_feature_horizon_stays_24_hours(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture().to_parquet(Path(directory) / 'part.parquet')
            plan = self.engine.plan_partition_execution(directory)
            self.assertEqual(plan['feature_seconds'], 86400)

    def test_native_cross_month_compact_and_eager_agree(self):
        data = self.fixture()
        data.iloc[3:, data.columns.get_loc('hostname')] = 'localhost'
        # Unknown parser forces the conservative 199h history, still 24h raw
        # features. The actual cron observations cross May/June at midnight.
        extra = self.frame(dict(parser='text/selinux', message='unrelated'))
        extra['chronosift_row_id'] = 9900
        data = pd.concat([data, extra]).sort_index(kind='stable')
        outputs = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            c.write_time_partitioned_parquet(data, str(root / 'input'), normalise=False)
            for compact in (False, True):
                engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(self.meta))
                engine.partition_execution_policy = {**engine.partition_execution_policy, 'compact_history': compact}
                engine.profiling_policy = replace(engine.profiling_policy, enabled=False)
                destination = root / str(compact)
                reports = engine.process_parquet_dataset_partitioned(str(root / 'input'), str(destination),
                    output_mode='sidecar', materialise_event_columns=True)
                self.assertEqual(sum(r['rows_written'] for r in reports), len(data))
                out = c.load_plaso_parquet_dataset(str(destination)).set_index('chronosift_row_id').sort_index()
                out.attrs = {}
                outputs.append(out)
            self.assertEqual(outputs[0].index.tolist(), outputs[1].index.tolist())
            self.assertEqual(outputs[0].chronosift_score.tolist(), outputs[1].chronosift_score.tolist())
            for rid in (9003, 9004, 9005):
                self.assertTrue(self.linked(outputs[1].loc[rid]))
                for name in ('linux_qualified_repository_invocation', 'repeated_scheduled_exec'):
                    self.assertEqual(self.signals(outputs[0].loc[rid]).get(name), self.signals(outputs[1].loc[rid]).get(name))

    def test_conflicting_hashes_and_late_marker_are_rejected(self):
        data = self.fixture()
        data['sha256_hash'] = None
        data.iloc[2, data.columns.get_loc('sha256_hash')] = 'a' * 64
        duplicate = data.iloc[[2]].assign(chronosift_row_id=9901, sha256_hash='b' * 64)
        data = pd.concat([data, duplicate]).sort_index(kind='stable')
        self.assertFalse(self.linked(self.score(data).loc[lambda d: d.chronosift_row_id == 9003].iloc[0]))
        data = self.fixture()
        times = list(data.index)
        times[0] = times[-1] + pd.Timedelta('1min')
        data.index = pd.DatetimeIndex(times, name='datetime')
        out = self.score(data.sort_index(kind='stable'))
        self.assertFalse(self.linked(out.loc[out.chronosift_row_id == 9003].iloc[0]))

    def test_configured_rule_id_does_not_control_explanation_accounting(self):
        policy = yaml.safe_load(RULES.read_text())
        detector = policy['detector_policy']['detectors']['linux_qualified_tool_invocation']
        detector['emissions']['repository']['rule_id'] = 'OTHER_CONFIGURED_RULE_ID'
        path = Path(self.temp.name) / 'other_rule_id.yaml'
        path.write_text(yaml.safe_dump(policy, sort_keys=False))
        engine = c.ChronoSiftEngine.from_yaml(path, WEIGHTS, yara_metadata_path=str(self.meta))
        out = self.score(self.fixture(), engine)
        item = next(x for x in out.iloc[3].chronosift_explain if x['rule_id'] == 'OTHER_CONFIGURED_RULE_ID')
        self.assertEqual(item['score_contribution'], 18)

    def test_non_file_marker_is_not_repository_evidence(self):
        data = self.fixture()
        data.iloc[0, data.columns.get_loc('file_entry_type')] = 'symbolic_link'
        self.assertFalse(self.linked(self.score(data).iloc[3]))

    def test_unlabelled_image_files_match_named_local_cron(self):
        # Actual Plaso shape: filestat.hostname is null, CROND.hostname is local.
        data = self.fixture(command='/opt/Tool/linux/nohup python3 collector.py &')
        data.iloc[3:, data.columns.get_loc('hostname')] = 'localhost'
        out = self.score(data)
        self.assertTrue(all(self.linked(out.iloc[i]) for i in (3, 4, 5)))
        policy = yaml.safe_load(RULES.read_text())
        policy['detector_policy']['detectors']['linux_qualified_tool_invocation']['unlabelled_file_scope'] = 'isolated'
        path = Path(self.temp.name) / 'strict_scope.yaml'
        path.write_text(yaml.safe_dump(policy, sort_keys=False))
        strict = c.ChronoSiftEngine.from_yaml(path, WEIGHTS, yara_metadata_path=str(self.meta))
        self.assertFalse(self.linked(self.score(data, strict).iloc[3]))

    def test_explicit_conflicting_file_host_is_not_dataset_scope(self):
        data = self.fixture()
        data.iloc[1, data.columns.get_loc('hostname')] = 'different-host'
        data.iloc[3:, data.columns.get_loc('hostname')] = 'localhost'
        self.assertFalse(self.linked(self.score(data).iloc[3]))


if __name__ == '__main__':
    unittest.main()
