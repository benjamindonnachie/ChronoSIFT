"""Execution policy and native compact-history regressions, not timing tests."""
from copy import deepcopy
from dataclasses import replace
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
import pyarrow as pa
import yaml

from test_v231_memory import M, ROOT, rule
from test_v231_context_provenance import account, bam, frame, PARENT, CHILD

RULES = ROOT / 'rules/rules_evidence_calibrated_v18.yaml'
WEIGHTS = ROOT / 'rules/weights_evidence_calibrated_v15.yaml'


def engine(version=18):
    return M.ChronoSiftEngine.from_yaml(ROOT / f'rules/rules_evidence_calibrated_v{version}.yaml', WEIGHTS)


def normal(value):
    if isinstance(value, dict):
        return {str(k): normal(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, np.ndarray)):
        return [normal(v) for v in value]
    if value is None or value is pd.NA or value is pd.NaT:
        return None
    if isinstance(value, (float, np.floating)) and np.isnan(value):
        return None
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    return value


class PartitionExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = engine()
        cls.level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        logging.getLogger().setLevel(cls.level)

    def data(self, parsers=('systemd_journal',), **extra):
        return pd.DataFrame({'chronosift_row_id': np.arange(len(parsers), dtype=np.int64) + 100,
            'parser': parsers, **extra}, index=pd.DatetimeIndex(['2024-05-31T23:59:59.123456789Z'] * len(parsers), name='datetime'))

    def plan(self, data, overlap=None):
        with tempfile.TemporaryDirectory() as directory:
            data.to_parquet(Path(directory) / 'part.parquet')
            return self.engine.plan_partition_execution(directory, overlap)

    def test_policy_changes_execution_only_and_preserves_versioned_rules(self):
        old = (ROOT / 'rules/rules_evidence_calibrated_v17.yaml').read_text()
        new = RULES.read_text()
        self.assertTrue(new.endswith(old))
        parsed = yaml.safe_load(new); parsed.pop('partition_execution')
        self.assertEqual(parsed, yaml.safe_load(old))
        self.assertIsNone(engine(17).partition_execution_policy)

    def test_qualified_malware_rule_names_do_not_hide_windows_prerequisites(self):
        policy = yaml.safe_load(RULES.read_text())
        rules = {r['id']: r for r in policy['temporal_rules']}
        self.assertEqual(rules['QUALIFIED_MALWARE_PATH_USE']['sequence'][-1]['signal'], 'windows_program_execution')
        self.assertEqual(rules['QUALIFIED_MALWARE_EXACT_HASH_USE']['sequence'][-1]['signal'], 'evidence_exact_hash_program_use')
        producer = next(r for d in policy['detector_policy']['detectors'].values()
                        for r in d.get('ordered_rules', []) if r['id'] == 'evidence_exact_hash_program_use')
        self.assertIn('windows_program_execution', producer['when']['all'][0]['signals'])

    def test_unscored_raw_note_and_copy_support_are_not_discarded(self):
        data = pd.DataFrame({'chronosift_row_id': [11, 12, 13],
            'filename': ['/home/a.locked', '/home/README', '/tmp/unrelated'],
            'message': ['', '', 'cp /tmp/lsass.dmp /tmp/archive/lsass.dmp']},
            index=pd.date_range('2024-05-01', periods=3, freq='s', tz='UTC', name='datetime'))
        self.engine._mark_compact_temporal_payload_candidates(data)
        self.assertTrue(data['__chronosift_composite_payload_candidate'].iloc[1])
        self.assertTrue(data['__chronosift_composite_payload_candidate'].iloc[2])
        signals = {0: {'ransomware_extension_burst': 1}}
        reference_signals = deepcopy(signals); reference_explain = {}
        self.engine._apply_deadbox_temporal_composites_sparse(data, reference_signals, reference_explain)
        candidate = data[[c for c in self.engine._compact_temporal_columns() if c in data]]
        class Source:
            row_id_col = 'chronosift_row_id'
            def fetch(self, ids, fields):
                selected = data.set_index('chronosift_row_id').loc[ids.tolist()]
                return pd.DataFrame({field: selected[field].to_numpy() if field in selected else [None] * len(ids) for field in fields})
        explanations = {}
        self.engine._apply_compact_temporal_composites(candidate, signals, explanations, Source())
        self.assertEqual(signals, reference_signals)
        self.assertEqual(explanations, reference_explain)
        self.assertEqual(signals[0]['ransomware_activity_candidate'], 1)

    def test_artifact_follow_on_retains_unscored_copy_text(self):
        policy = self.engine.detector_policy.credential_dump_collection
        label = policy.source_label_tokens[0]
        data = pd.DataFrame({'chronosift_row_id': [71, 72],
            'filename': [f'/tmp/{label}.dmp'] * 2,
            'message': [label, f'{policy.copy_tokens[0]} {policy.copy_text_support_tokens[0]} {label}']},
            index=pd.date_range('2024-05-01', periods=2, freq='s', tz='UTC', name='datetime'))
        signals = {0: {next(iter(policy.source_signals)): 1}}
        expected = deepcopy(signals); expected_explain = {}
        self.engine._apply_deadbox_temporal_composites_sparse(data, expected, expected_explain)
        self.assertIn(policy.emission.name, expected[0])
        self.engine._mark_compact_temporal_payload_candidates(data)
        self.assertTrue(data['__chronosift_composite_payload_candidate'].iloc[1])
        candidate = data[[c for c in self.engine._compact_temporal_columns() if c in data]]
        class Source:
            row_id_col = 'chronosift_row_id'
            def fetch(self, ids, fields):
                selected = data.set_index('chronosift_row_id').loc[ids.tolist()]
                return pd.DataFrame({field: selected[field].to_numpy() if field in selected else [None] * len(ids) for field in fields})
        explanations = {}
        self.engine._apply_compact_temporal_composites(candidate, signals, explanations, Source())
        self.assertEqual(signals, expected)
        self.assertEqual(explanations, expected_explain)

    def test_linux_omits_windows_execution_dependencies_regardless_of_rule_name(self):
        plan = self.plan(self.data(('systemd_journal', 'filestat', 'text/apache_access')))
        self.assertEqual(plan['configured_history_seconds'], 199 * 3600)
        self.assertEqual(plan['history_seconds'], 24 * 3600)
        self.assertEqual(plan['feature_seconds'], 24 * 3600)
        self.assertFalse(plan['compact_history'])
        self.assertIn('WINDOWS_ACCOUNT_NEW_SOURCE', plan['omitted_rule_ids'])
        self.assertIn('QUALIFIED_MALWARE_PATH_USE', plan['omitted_rule_ids'])
        self.assertIn('QUALIFIED_MALWARE_EXACT_HASH_USE', plan['omitted_rule_ids'])
        self.assertEqual(len(plan['applicability_proofs']), 1)
        self.assertEqual(self.engine.minimum_partition_overlap(), pd.Timedelta('199h'))

    def test_unknown_mixed_null_and_neutral_only_keep_all_rules(self):
        for parsers in [('unknown',), ('systemd_journal', 'winevtx'), ('systemd_journal', None), ('filestat', 'pe')]:
            with self.subTest(parsers=parsers):
                plan = self.plan(self.data(parsers))
                self.assertEqual(plan['history_seconds'], 199 * 3600)
                self.assertEqual(plan['omitted_rule_ids'], [])

    def test_guarded_columns_even_null_keep_rules(self):
        for field in ('event_identifier', 'win_context_sid', 'identity_acting_sid'):
            with self.subTest(field=field):
                self.assertFalse(self.plan(self.data(**{field: None}))['omitted_rule_ids'])

    def test_parser_census_is_whole_corpus_not_first_file(self):
        with tempfile.TemporaryDirectory() as directory:
            self.data().to_parquet(Path(directory) / 'first.parquet')
            self.data(('winevtx',)).to_parquet(Path(directory) / 'last.parquet')
            self.assertFalse(self.engine.plan_partition_execution(directory)['omitted_rule_ids'])

    def test_explicit_short_history_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'applicable temporal dependencies'):
            self.plan(self.data(('winevtx',)), '24h')
        self.assertEqual(self.plan(self.data(), '200h')['history_seconds'], 200 * 3600)

    def test_windows_data_type_with_linux_parser_keeps_long_history(self):
        self.assertFalse(self.plan(self.data(data_type='windows:registry:bam'))['omitted_rule_ids'])
        self.assertTrue(self.plan(self.data(command_line='apt upgrade', data_type='systemd:journal'))['omitted_rule_ids'])

    def test_longer_feature_window_is_not_silently_truncated(self):
        policy = {**self.engine.partition_execution_policy, 'feature_overlap': pd.Timedelta('240h'), 'applicability_groups': []}
        with patch.object(self.engine, 'partition_execution_policy', policy):
            plan = self.plan(self.data())
            self.assertEqual(plan['feature_seconds'], 240 * 3600)
            self.assertEqual(plan['history_seconds'], 240 * 3600)
            self.assertFalse(plan['compact_history'])
            with self.assertRaisesRegex(ValueError, 'feature windows'):
                self.plan(self.data(), '199h')

    def test_policy_validation_rejects_malformed_and_unknown_rules(self):
        raw = yaml.safe_load(RULES.read_text())['partition_execution']
        for value in ({}, {**raw, 'compact_history': 'yes'}, {**raw, 'feature_overlap': '0h'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.engine._parse_partition_execution_policy(value)
        bad = deepcopy(raw); bad['applicability_groups'][0]['temporal_rule_ids'] = ['NONEXISTENT']
        with self.assertRaises(ValueError):
            self.engine._parse_partition_execution_policy(bad)

    def test_dependent_rule_prevents_pruning(self):
        consumer = next(t for t in self.engine.temporal_rules if t.rule_id == 'WINDOWS_RECENT_NEW_SOURCE_ACTION')
        extra = replace(consumer, rule_id='CUSTOM_CONSUMER')
        with patch.object(self.engine, 'temporal_rules', self.engine.temporal_rules + [extra]):
            self.assertFalse(self.plan(self.data())['omitted_rule_ids'])

    def test_rule_scope_restored_after_driver_failure(self):
        previous = self.engine.temporal_rules
        with tempfile.TemporaryDirectory() as directory:
            self.data().to_parquet(Path(directory) / 'input.parquet')
            with patch.object(self.engine, '_process_partitioned_with_plan', side_effect=RuntimeError('fixture')):
                with self.assertRaisesRegex(RuntimeError, 'fixture'):
                    self.engine.process_parquet_dataset_partitioned(directory, directory + '-out')
        self.assertIs(self.engine.temporal_rules, previous)

    def test_history_key_lookup_keeps_identical_nanosecond_stamps_distinct(self):
        data = self.data(('fixture',) * 3); data['chronosift_row_id'] = [71, 19, 103]
        keys = M.ChronoSiftEngine._history_key_index(data, 'chronosift_row_id')
        self.assertEqual(M.ChronoSiftEngine._history_key_positions(keys, pd.Series([103, 71])).tolist(), [2, 0])
        with self.assertRaisesRegex(ValueError, 'Missing core row ID'):
            M.ChronoSiftEngine._history_key_positions(keys, pd.Series([999]))
        with self.assertRaisesRegex(ValueError, 'Duplicate persistent'):
            M.ChronoSiftEngine._history_key_index(pd.concat([data, data]), 'chronosift_row_id')
        data['chronosift_row_id'] = ['71', '19', '103']
        with self.assertRaisesRegex(ValueError, 'integer'):
            M.ChronoSiftEngine._history_key_index(data, 'chronosift_row_id')

    def test_cache_read_preserves_nullable_large_integers_and_booleans(self):
        batch = pa.record_batch({'datetime': pa.array(pd.DatetimeIndex(['2024-05-01T00:00:00Z'] * 2)),
            'chronosift_row_id': pa.array([71, 72], type=pa.int64()),
            'large_nullable': pa.array([2**60 + 1, None], type=pa.int64()),
            'nullable_flag': pa.array([True, None], type=pa.bool_())})
        result = M.ChronoSiftEngine._history_batch_to_frame(batch)
        self.assertTrue(pd.api.types.is_integer_dtype(result.large_nullable.dtype))
        self.assertEqual(result.large_nullable.iloc[0], 2**60 + 1)
        self.assertTrue(pd.isna(result.large_nullable.iloc[1]))
        self.assertIs(result.nullable_flag.iloc[0], True)
        self.assertTrue(pd.isna(result.nullable_flag.iloc[1]))

    def native_compare(self, data, *, custom_rule=False, empty_month=None, profiling=False, profile_manifest=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); inputs = root / 'input'
            M.write_time_partitioned_parquet(data, str(inputs), normalise=False)
            if empty_month:
                y, m = empty_month
                dest = inputs / f'year={y}' / f'month={m:02d}'
                dest.mkdir(parents=True); data.iloc[:0].to_parquet(dest / 'empty.parquet')
            outputs = []
            for version in (17, 18):
                current = engine(version)
                current.profiling_policy = replace(current.profiling_policy, enabled=profiling)
                if custom_rule:
                    current.rules = [rule()]; current.required_fields = current._collect_required_fields()
                    current.weights['fixture_signal'] = 10.0
                with patch.object(M, 'load_plaso_parquet_timerange', wraps=M.load_plaso_parquet_timerange) as reads:
                    reports = current.process_parquet_dataset_partitioned(str(inputs), str(root / str(version)),
                        output_mode='sidecar', materialise_event_columns=True, profile_manifest=profile_manifest)
                result = M.load_plaso_parquet_dataset(str(root / str(version))).set_index('chronosift_row_id').sort_index()
                result.attrs = {}; outputs.append(result)
                if version == 18:
                    raw_reads = [c for c in reads.call_args_list if c.args[0] == str(inputs)]
                    history_reads = [c for c in reads.call_args_list if c.args[0] != str(inputs)]
                    self.assertTrue(raw_reads and history_reads)
                    self.assertTrue(all(c.kwargs['overlap'] == '86400s' for c in raw_reads))
                    self.assertTrue(all('message' not in c.kwargs['columns'] and 'chronosift_explain' not in c.kwargs['columns'] for c in history_reads))
                    self.assertEqual(sum(r['rows_written'] for r in reports), len(data))
                    cache = Path(reports[0]['history_cache'])
                    self.assertTrue((cache / 'complete.json').exists())
                    self.assertTrue(all(r['execution_plan']['compact_history'] for r in reports))
            self.assertEqual(outputs[0].index.tolist(), outputs[1].index.tolist())
            self.assertEqual(set(outputs[0].columns), set(outputs[1].columns))
            for rid in outputs[0].index:
                for column in outputs[0].columns:
                    self.assertEqual(normal(outputs[0].loc[rid, column]), normal(outputs[1].loc[rid, column]), (rid, column))
            return outputs[1]

    def test_accepted_profile_amplification_survives_cache_roundtrip(self):
        data = self.data(('fixture',) * 3); data['flag'] = ['yes', 'no', 'yes']; data['payload'] = ['one', '', 'three']
        manifest = dict(profile={str(i): 0.5 for i in range(168)}, quiet_hours=[],
            probabilities={str(i): 0.001 for i in range(168)}, upper_probability_bounds={str(i): 0.002 for i in range(168)},
            validation=dict(accepted=True, reference_probability=1 / 168, lower_confidence_bound=0.1, complete_week_count=12))
        result = self.native_compare(data, custom_rule=True, profiling=True, profile_manifest=manifest)
        self.assertEqual(result.loc[100].chronosift_score, 15.0)

    def test_native_tied_timestamps_payload_profiling_and_empty_checkpoint(self):
        data = self.data(('fixture',) * 6)
        data.index = pd.DatetimeIndex(['2024-05-31T23:59:59.123456789Z'] * 3 + ['2024-06-01T00:00:00.123456789Z'] * 3, name='datetime')
        data['flag'] = ['yes', 'no', 'yes'] * 2
        data['payload'] = ['one', 'unused', 'three', 'four', 'unused', 'six']
        result = self.native_compare(data, custom_rule=True, empty_month=(2024, 4), profiling=True)
        self.assertEqual(len(result), 6)
        self.assertEqual(next(e for e in result.loc[103].chronosift_explain if e['rule_id'] == 'MEMORY')['evidence']['payload'], 'four')

    def test_native_creator_and_novel_tool_survive_cross_month_history(self):
        records = [(f'{i}s', account(4625, PARENT, logon_type=3, ip_address='8.8.8.8')) for i in range(3)]
        records += [('3s', account(4624, PARENT, logon_type=3, ip_address='8.8.8.8')),
            ('1h', account(4720, win_subject_sid=PARENT)),
            ('1h1m', account(4732, 'S-1-5-32-544', win_member_sid=CHILD, win_subject_sid=PARENT, group_name='Administrators')),
            ('3d', bam()), ('3d1s', bam()), ('8d1s', bam())]
        result = self.native_compare(frame(records))
        self.assertEqual(result.loc[906].chronosift_signals['windows_risky_creator_context'], 1)
        self.assertEqual(result.loc[906].chronosift_signals['windows_first_observed_dual_use_execution'], 1)
        self.assertNotIn('windows_first_observed_dual_use_execution', result.loc[907].chronosift_signals)


if __name__ == '__main__':
    unittest.main()
