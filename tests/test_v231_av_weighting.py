"""Classified AV malware presence must outrank generic scheduled activity.

All policy changes are YAML-owned. No filename/family-specific score exception.
"""
from pathlib import Path
import logging
import subprocess
import sys
import tempfile
import unittest

import pandas as pd
import yaml
import chronoSIFT_v2_31 as c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'rules/rules_evidence_calibrated_v19.yaml'
OLD = ROOT / 'rules/weights_evidence_calibrated_v16.yaml'
NEW = ROOT / 'rules/weights_evidence_calibrated_v17.yaml'


class AVWeightingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)
        cls.temp = tempfile.TemporaryDirectory()
        meta = Path(cls.temp.name) / 'fixture.yar'
        meta.write_text('rule TEST_UNUSED { condition: false }\n')
        cls.old = c.ChronoSiftEngine.from_yaml(RULES, OLD, yara_metadata_path=str(meta))
        cls.new = c.ChronoSiftEngine.from_yaml(RULES, NEW, yara_metadata_path=str(meta))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        logging.getLogger().setLevel(cls.level)

    def test_only_four_classified_weights_change(self):
        old, new = (yaml.safe_load(path.read_text()) for path in (OLD, NEW))
        expected = {'av_malware':24, 'av_exploit':24, 'av_ransomware':25, 'av_webshell':25}
        delta = {key:value for key,value in new['weights'].items() if value != old['weights'].get(key)}
        self.assertEqual(delta, expected)
        self.assertEqual(new['weights'].keys(), old['weights'].keys())
        self.assertEqual({k:v for k,v in new.items() if k != 'weights'},
                         {k:v for k,v in old.items() if k != 'weights'})

    def test_builder_is_idempotent(self):
        output = subprocess.check_output([sys.executable, '-B', str(ROOT / 'benchmarks/build_av_weight_policy.py')], text=True)
        self.assertEqual(output, '*** Begin Patch\n*** End Patch\n')

    def test_category_scores_and_lower_priority_controls(self):
        cases = [
            ('Unix.Malware.Agent-6835737-0', 16, 32),
            ('Unix.Rootkit.Example-1-0', 16, 32),
            ('Win.Exploit.Example-1-0', 16, 32),
            ('Win.Ransomware.Example-1-0', 17, 33),
            ('PHP.Backdoor.C99Shell-1-0', 17, 33),
            ('Win.Tool.Example-1-0', 18, 18),
            ('Win.Adware.Example-1-0', 2, 2),
            ('', 8, 8),
        ]
        for signature, old_score, new_score in cases:
            with self.subTest(signature=signature):
                maps = []
                for engine, score in ((self.old, old_score), (self.new, new_score)):
                    data = pd.DataFrame([dict(filename='/evidence/ordinary.bin', av_hit=True, av_signature=signature)])
                    signals, explains = {}, {}
                    engine._inject_av_signal_sparse(data, signals, explains)
                    self.assertEqual(engine._score_signals(signals[0]), score)
                    maps.append(signals)
                self.assertEqual(*maps)

    def test_no_filename_only_or_hit_free_boost(self):
        data = pd.DataFrame([dict(filename='/tmp/rk.tar', av_hit=False, av_signature='')])
        signals = {}
        self.new._inject_av_signal_sparse(data, signals, {})
        self.assertEqual(self.new._score_signals(signals.get(0, {})), 0)

    def test_repeated_av_injection_does_not_multiply_score(self):
        data = pd.DataFrame([dict(filename='/evidence/ordinary.bin', av_hit=True,
            av_signature='Unix.Malware.Agent-6835737-0')])
        signals, explains = {}, {}
        self.new._inject_av_signal_sparse(data, signals, explains)
        self.new._inject_av_signal_sparse(data, signals, explains)
        self.assertEqual(self.new._score_signals(signals[0]), 32)

    def test_full_pipeline_accounting_and_timestamp_ties(self):
        records = [dict(chronosift_row_id=101+i, parser='filestat', filename='/evidence/ordinary.bin',
            timestamp_desc='Last Access Time', av_hit=True,
            av_signature='Unix.Malware.Agent-6835737-0') for i in range(2)]
        data = pd.DataFrame(records, index=pd.DatetimeIndex(['2024-01-01T00:00:00Z']*2, name='datetime'))
        out = self.new.apply_contextual(self.new.apply_atomic(data, apply_profiling=False), apply_profiling=False)
        self.assertEqual(list(out.chronosift_row_id), [101, 102])
        self.assertEqual(list(out.chronosift_score), [32, 32])
        for explanations in out.chronosift_explain:
            self.assertEqual(sum(e.get('score_contribution', 0) for e in explanations), 32)
            self.assertFalse(any(e['rule_id'] in ('WINDOWS_MALWARE_EXECUTION', 'LINUX_QUALIFIED_FILE_INVOCATION')
                for e in explanations))

    def test_cap_and_extra_execution_context(self):
        presence = dict(av_hit=1, av_malware=1)
        self.assertEqual(self.new._score_signals(presence), 32)
        self.assertGreater(self.new._score_signals({**presence, 'windows_program_execution':1}), 32)
        self.assertEqual(self.new._score_signals({**presence, 'windows_malware_use_priority':1}), 50)


if __name__ == '__main__':
    unittest.main()
