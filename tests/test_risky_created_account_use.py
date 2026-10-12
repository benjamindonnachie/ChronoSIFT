"""Persistence: risky creator -> new account -> successful use, scoped and bounded."""
import logging
from pathlib import Path
import tempfile
import unittest
import pandas as pd
import chronoSIFT_v2_31 as c
from tests.test_v231_context_provenance import account, frame, PARENT, CHILD, OTHER, START
from tests.test_v231_authentication_context import login

ROOT=Path(c.__file__).resolve().parent
RISK='windows_risky_creator_context'
PRIV='windows_privileged_activity_context'

class RiskyCreatedAccountUseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.metadata=Path(cls.temp.name)/'fixture.yar'
        cls.metadata.write_text('rule UNUSED { condition: false }\n')
        cls.engine=c.ChronoSiftEngine.from_yaml(ROOT/'rules/rules_evidence_calibrated_v27.yaml',ROOT/'rules/weights_evidence_calibrated_v23.yaml',yara_metadata_path=str(cls.metadata))
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        logging.getLogger().setLevel(cls.level);cls.temp.cleanup()

    def chain(self, *, grant=True, success=True, user='admin', use='1d', sid=CHILD):
        rows=[('0s',login(sid=PARENT)),('1h',account(4720,win_subject_sid=PARENT))]
        if grant: rows.append(('1h1m',account(4732,'S-1-5-32-544',win_member_sid=CHILD,group_name='Administrators')))
        rows.append((use,login(sid=sid,user=user,success=success)))
        return rows

    def run_rows(self,rows,*,risk=True):
        out=self.engine.apply_atomic(frame(rows),apply_profiling=False,materialise_event_columns=False)
        if risk: out.attrs['chronosift_sparse']['signal_map'].setdefault(out.index.get_loc(START),{}).update(impossible_travel=1,fail_then_success_user=1)
        out=self.engine.apply_contextual(out,apply_profiling=False)
        for _,r in out.iterrows():
            self.assertAlmostEqual(r.chronosift_score,min(50,sum(e['score_contribution'] for e in (r.get('chronosift_explain') or []))))
        return out

    def test_created_privileged_account_use_has_existing_twenty_points_of_context(self):
        r=self.run_rows(self.chain()).iloc[-1]
        self.assertEqual(r.chronosift_signals.get(RISK),1)
        self.assertEqual(r.chronosift_signals.get(PRIV),1)
        owners={e['rule_id']:e['score_contribution'] for e in r.chronosift_explain}
        self.assertEqual(owners['WINDOWS_RISKY_CREATOR_CONTEXT'],8)
        self.assertEqual(owners['WINDOWS_PRIVILEGED_ACTIVITY_CONTEXT'],12)
        self.assertTrue(any(e.get('evidence',{}).get('supporting_row_ids') for e in r.chronosift_explain if 'ACCOUNT_USE' in e['rule_id']))

    def test_no_membership_required_for_risky_created_account_use(self):
        r=self.run_rows(self.chain(grant=False,user='support2')).iloc[-1]
        self.assertEqual(r.chronosift_signals.get(RISK),1)
        self.assertFalse(r.chronosift_signals.get(PRIV))

    def test_provisioning_without_risky_creator_receives_no_login_context(self):
        r=self.run_rows(self.chain(),risk=False).iloc[-1]
        self.assertFalse(r.chronosift_signals.get(RISK))
        self.assertFalse(r.chronosift_signals.get(PRIV))

    def test_name_does_not_determine_persistence(self):
        for user in ('admin','maint2','support2'):
            with self.subTest(user=user):self.assertEqual(self.run_rows(self.chain(user=user)).iloc[-1].chronosift_signals.get(RISK),1)

    def test_failed_login_does_not_complete_account_use(self):
        r=self.run_rows(self.chain(success=False)).iloc[-1]
        self.assertFalse(r.chronosift_signals.get(RISK));self.assertFalse(r.chronosift_signals.get(PRIV))

    def test_other_identity_asset_and_expired_context_are_excluded(self):
        variants=[self.chain(sid=OTHER),self.chain(use='9d')]
        rows=self.chain();rows[-1][1]['win_asset_id']='different-image';variants.append(rows)
        rows=self.chain();rows[1][1]['win_subject_sid']=OTHER;variants.append(rows)
        rows=self.chain(use='-1h');variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows):
                out=self.run_rows(rows);r=out.loc[START+pd.Timedelta(rows[-1][0])]
                self.assertFalse(r.chronosift_signals.get(RISK));self.assertFalse(r.chronosift_signals.get(PRIV))

    def test_successful_local_use_also_completes_persistence(self):
        rows=self.chain();rows[-1]=(rows[-1][0],login(sid=CHILD,user='admin',remote=False))
        r=self.run_rows(rows).iloc[-1]
        self.assertEqual(r.chronosift_signals.get(RISK),1);self.assertEqual(r.chronosift_signals.get(PRIV),1)

    def test_context_is_not_inherited_recursively(self):
        rows=self.chain()+[('1d1h',account(4720,OTHER,win_subject_sid=CHILD)),('1d2h',login(sid=OTHER,user='support3'))]
        r=self.run_rows(rows).iloc[-1]
        self.assertFalse(r.chronosift_signals.get(RISK))

    def test_real_failure_success_creation_use_without_injection(self):
        rows=[('0s',login(sid=PARENT))]+[(f'{t}s',login('80.10.20.30',sid=PARENT,success=False,far=True)) for t in (10,20,30)]
        rows += [('120s',login('80.10.20.30',sid=PARENT,far=True)),('130s',account(4720,win_subject_sid=PARENT)),('140s',account(4732,'S-1-5-32-544',win_member_sid=CHILD,group_name='Administrators')),('150s',login('80.10.20.30',sid=CHILD,user='admin',far=True))]
        out=self.engine.apply(frame(rows),apply_profiling=False);r=out.iloc[-1]
        self.assertEqual(r.chronosift_signals.get(RISK),1);self.assertEqual(r.chronosift_signals.get(PRIV),1)
        self.assertGreaterEqual(r.chronosift_score,30)

if __name__=='__main__':unittest.main()
