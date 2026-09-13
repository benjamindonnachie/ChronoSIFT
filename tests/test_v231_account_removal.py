"""Additive affected-group severity; duplicate evidence never repeats base points."""
import json
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import duckdb
import pandas as pd
import yaml

import chronoSIFT_v2_31 as c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT/'rules/rules_evidence_calibrated_v15.yaml'
WEIGHTS = ROOT/'rules/weights_evidence_calibrated_v14.yaml'
PRIVILEGE = 'privileged_group_access_removal'
BUILDER = ROOT/'benchmarks/build_account_removal_policy.py'


def removal(event=4733, group='Administrators', **extra):
    return dict(parser='winevtx', source_name='Microsoft-Windows-Security-Auditing',
                event_identifier=event, target_user_name=group, **extra)


class AccountRemovalTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(logging.getLogger().setLevel, logging.getLogger().level)
        logging.getLogger().setLevel(logging.ERROR)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.metadata = self.root/'fixture.yar'
        self.metadata.write_text('rule TEST {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n')
        self.engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(self.metadata))

    def rows(self, *records):
        frame = pd.DataFrame([dict(chronosift_row_id=900+i, hostname='fixture-host', **record)
                              for i, record in enumerate(records)],
                             index=pd.DatetimeIndex(['2024-06-30T23:59:00Z']*len(records), name='datetime'))
        out = self.engine.apply_contextual(self.engine.apply_atomic(frame, apply_profiling=False), apply_profiling=False)
        for _, row in out.iterrows():
            self.assertAlmostEqual(row.chronosift_score,
                                   min(50, sum(e['score_contribution'] for e in (row.get('chronosift_explain') or []))))
        return out

    def test_builder_fidelity(self):
        self.assertEqual(subprocess.check_output([sys.executable, '-B', str(BUILDER)], text=True),
                         '*** Begin Patch\n*** End Patch\n')

    def test_only_account_removal_policy_changes(self):
        old = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v14.yaml').read_text())
        new = yaml.safe_load(RULES.read_text())
        before = old['detector_policy']['detectors']['direct_attack_semantics']
        after = new['detector_policy']['detectors']['direct_attack_semantics']
        after['inputs'].pop('removal_group'); after['evidence'].pop('removal_group')
        names = {'account_disabled_or_deleted', 'privileged_group_removal', 'other_account_access_removal'}
        originals = {r['id']: r for r in before['ordered_rules']}
        after['ordered_rules'] = [originals[r['id']] if r['id'] in names else r
                                  for r in after['ordered_rules'] if r['id'] != 'account_access_removal_base']
        for name in ('account_removal_event_evidence', 'account_removal_other_evidence', PRIVILEGE):
            after['emissions'].pop(name)
        self.assertEqual(new, old)
        old_weights = yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v13.yaml').read_text())
        new_weights = yaml.safe_load(WEIGHTS.read_text())
        for name, value in [('account_removal_event_evidence', 0), ('account_removal_other_evidence', 0), (PRIVILEGE, 6)]:
            self.assertEqual(new_weights['weights'].pop(name), value)
        self.assertEqual(new_weights, old_weights)

    def test_privileged_groups_score_base_plus_increment(self):
        for event in (4729, 4733, 4757):
            for group in ('Administrators', 'Domain Admins', 'Enterprise Admins', 'Remote Desktop Users'):
                with self.subTest(event=event, group=group):
                    row = self.rows(removal(event, group)).iloc[0]
                    self.assertEqual(row.chronosift_score, 8)
                    self.assertEqual(row.chronosift_signals['account_access_removal'], 1)
                    self.assertEqual(row.chronosift_signals[PRIVILEGE], 1)
                    contributions = sorted(e['score_contribution'] for e in row.chronosift_explain if e['score_contribution'])
                    self.assertEqual(contributions, [2, 6])

    def test_ordinary_group_has_only_base(self):
        row = self.rows(removal(group='Project Readers')).iloc[0]
        self.assertEqual(row.chronosift_score, 2)
        self.assertNotIn(PRIVILEGE, row.chronosift_signals)

    def test_affected_group_not_privileged_subject_member_or_message(self):
        row = self.rows(removal(group='Project Readers', subject_user_name='Administrator',
                                member_name='CN=Domain Admins,CN=Users,DC=example',
                                message='Administrator removed from group; reference Enterprise Admins')).iloc[0]
        self.assertEqual(row.chronosift_score, 2)
        self.assertNotIn(PRIVILEGE, row.chronosift_signals)

    def test_group_name_precedes_target_alias_and_requires_whole_name(self):
        for record in (removal(group='Administrators', group_name='Project Readers'),
                       removal(group='Former Domain Admins'), removal(group='Administrators Backup')):
            row = self.rows(record).iloc[0]
            self.assertEqual(row.chronosift_score, 2)
        self.assertEqual(self.rows(removal(group='domain admins')).iloc[0].chronosift_score, 8)

    def test_text_alone_does_not_prove_affected_privileged_group(self):
        row = self.rows(dict(parser='winevtx', message='removed from group Domain Admins')).iloc[0]
        self.assertEqual(row.chronosift_score, 2)
        self.assertNotIn(PRIVILEGE, row.chronosift_signals)

    def test_disable_event_and_matching_text_count_base_once(self):
        for event in (4725, 4726):
            row = self.rows(removal(event, 'ordinary-user', message='user account disabled; user account deleted')).iloc[0]
            # Existing account-manipulation rules may independently contribute.
            # Reconcile the whole event above; here inspect only removal points.
            removal_items = [e for e in row.chronosift_explain if e['rule_id'] in {
                'ACCOUNT_ACCESS_REMOVAL', 'ACCOUNT_REMOVAL_EVENT_EVIDENCE', 'ACCOUNT_REMOVAL_OTHER_EVIDENCE'}]
            self.assertEqual(sum(e['score_contribution'] for e in removal_items), 2)
            self.assertEqual(sum(e['score_contribution'] != 0 for e in removal_items), 1)
            self.assertNotIn(PRIVILEGE, row.chronosift_signals)
            self.assertIn('account_removal_event_evidence', row.chronosift_signals)
            self.assertIn('account_removal_other_evidence', row.chronosift_signals)

    def test_unrelated_event_does_not_get_removal_increment(self):
        row = self.rows(removal(9999)).iloc[0]
        self.assertFalse((row.get('chronosift_signals') or {}).get(PRIVILEGE))
        self.assertFalse((row.get('chronosift_signals') or {}).get('account_access_removal'))

    def test_numeric_event_representations_and_tied_ids(self):
        out = self.rows(*(removal(event, 'Enterprise Admins') for event in (4757, 4757., '4757', '4757.0')))
        self.assertEqual(out.chronosift_row_id.tolist(), [900, 901, 902, 903])
        self.assertEqual(out.chronosift_score.tolist(), [8]*4)

    def test_duplicate_rule_execution_is_idempotent(self):
        frame = pd.DataFrame([removal()], index=pd.DatetimeIndex(['2024-06-30T23:59:00Z'], name='datetime'))
        frame = self.engine._apply_normalisation(frame)
        signals, explanations = {}, {}
        self.engine._apply_deadbox_direct_signals_sparse(frame, signals, explanations)
        first = json.dumps(explanations, sort_keys=True)
        self.engine._apply_deadbox_direct_signals_sparse(frame, signals, explanations)
        self.assertEqual(json.dumps(explanations, sort_keys=True), first)
        self.engine._materialise_sparse_event_columns(frame, signals, explanations)
        self.assertEqual(sum(e['score_contribution'] for e in frame.iloc[0].chronosift_explain), 8)

    def test_weights_remain_yaml_owned(self):
        weights = yaml.safe_load(WEIGHTS.read_text())
        weights['weights']['account_access_removal'] = 5
        weights['weights'][PRIVILEGE] = 9
        path = self.root/'weights.yaml'; path.write_text(yaml.safe_dump(weights))
        self.engine = c.ChronoSiftEngine.from_yaml(RULES, path, yara_metadata_path=str(self.metadata))
        self.assertEqual(self.rows(removal()).iloc[0].chronosift_score, 14)

    def test_real_nested_sidecar_preserves_tied_rows_and_sums(self):
        data = pd.DataFrame([dict(chronosift_row_id=900+i, hostname='fixture-host', **removal()) for i in range(2)],
                            index=pd.DatetimeIndex(['2024-06-30T23:59:00Z']*2, name='datetime'))
        base = self.root/'input/year=2024/month=6'; base.mkdir(parents=True)
        data.to_parquet(base/'part.parquet')
        output = self.root/'output'
        self.engine.process_parquet_dataset_partitioned(str(self.root/'input'), str(output),
                                                        output_mode='sidecar', materialise_event_columns=True)
        con = duckdb.connect(); self.addCleanup(con.close)
        saved = con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_explain FROM read_parquet(?) ORDER BY 1',
                            [str(output/'**/*.parquet')]).fetchall()
        self.assertEqual([(r[0], r[1]) for r in saved], [(900, 8), (901, 8)])
        for _, score, explanations in saved:
            self.assertEqual(sum(json.loads(item)['score_contribution'] for item in explanations), score)


if __name__ == '__main__':
    unittest.main()
