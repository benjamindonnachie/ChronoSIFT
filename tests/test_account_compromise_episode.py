"""YAML-owned compromise episodes and generic sequence admission controls."""
from copy import deepcopy
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import duckdb
import pandas as pd
import yaml
import chronoSIFT_v2_31 as c
from tests.test_v231_authentication_context import login, frame, signals, SID, OTHER, START
from tests.test_v231_context_provenance import account
ROOT=Path(c.__file__).resolve().parent
SEED='auth_sustained_bruteforce_success'
STRONG='auth_corroborated_bruteforce_success'
CONTEXT='auth_account_compromise_context'


def native(event, record, **changes):
    return {**event,'record_number':record,'pathspec':'fixture-security.evtx',**changes}


def episode(count=10, *, duplicate=1, far=True):
    rows=[('-1h',native(login(),1))]
    for i in range(count):
        rows += [(f'{i*5}s',native(login('80.10.20.30',success=False,far=far),10+i))]*duplicate
    rows += [('120s',native(login('80.10.20.30',far=far),100))]
    return rows


def episode_frame(rows):
    return pd.DataFrame([{'hostname':'fixture-host','win_asset_id':'fixture-image',
                          'chronosift_row_id':900+i,**r} for i,(_,r) in enumerate(rows)],
                        index=pd.DatetimeIndex([START+pd.Timedelta(t) for t,_ in rows],name='datetime'))


class AccountCompromiseEpisodeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.metadata=Path(cls.temp.name)/'fixture.yar'
        cls.metadata.write_text('rule UNUSED { condition: false }\n')
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)
        cls.engine=c.ChronoSiftEngine.from_yaml(ROOT/'rules/rules_evidence_calibrated_v27.yaml',ROOT/'rules/weights_evidence_calibrated_v23.yaml',yara_metadata_path=str(cls.metadata))
    @classmethod
    def tearDownClass(cls):logging.getLogger().setLevel(cls.level);cls.temp.cleanup()

    def run_rows(self,rows,engine=None):
        out=(engine or self.engine).apply(episode_frame(rows),apply_profiling=False)
        for _,r in out.iterrows():
            self.assertAlmostEqual(r.chronosift_score,min(50,sum(e['score_contribution'] for e in (r.get('chronosift_explain') or []))))
        return out

    def test_seed_has_distinct_witnesses_and_single_priority_owner(self):
        r=self.run_rows(episode(duplicate=2)).iloc[-1]
        self.assertEqual(signals(r).get(SEED),1);self.assertEqual(signals(r).get(STRONG),1)
        e=next(e for e in r.chronosift_explain if e['rule_id']==STRONG.upper())
        self.assertEqual(len(e['evidence']['supporting_row_ids']),11)
        owner=[e for e in r.chronosift_explain if e['rule_id']=='AUTH_TAKEOVER_CANDIDATE']
        self.assertEqual(len(owner),1);self.assertEqual(owner[0]['score_contribution'],20)
        self.assertEqual(r.chronosift_score,42)

    def test_duplicate_emissions_and_typos_do_not_make_sustained_burst(self):
        for count,duplicates in ((3,1),(3,10),(9,3)):
            with self.subTest(count=count,duplicates=duplicates):self.assertNotIn(SEED,signals(self.run_rows(episode(count,duplicate=duplicates)).iloc[-1]))

    def test_known_return_annotated_but_novel_travel_prioritised(self):
        rows=episode()+[('240s',native(login(),101)),('1d',native(login('90.10.20.30',far=True),102))]
        out=self.run_rows(rows);home=out.iloc[-2];novel=out.iloc[-1]
        self.assertIn(CONTEXT,signals(home));self.assertNotIn('auth_takeover_candidate',signals(home))
        self.assertLessEqual(home.chronosift_score,2)
        self.assertIn('auth_corroborated_compromise_novel_use',signals(novel))
        self.assertEqual(signals(novel).get('auth_takeover_candidate'),1)
        self.assertEqual(signals(novel).get('auth_privileged_takeover'),1)

    def test_original_source_and_expiry_do_not_refresh_from_use(self):
        rows=episode()+[('6d',native(login('80.10.20.30',far=True),110)),
                        ('7d120s',native(login('80.10.20.30',far=True),111)),
                        ('7d121s',native(login('80.10.20.30',far=True),112))]
        out=self.run_rows(rows)
        for _,r in out.iloc[-3:-1].iterrows():self.assertIn('auth_corroborated_compromise_source_use',signals(r))
        r=out.iloc[-1];self.assertNotIn(CONTEXT,signals(r));self.assertNotIn('auth_takeover_candidate',signals(r))
        self.assertEqual(sum(bool(signals(r).get(STRONG)) for _,r in out.iterrows()),1)

    def test_uncorroborated_burst_has_only_suspected_carry(self):
        out=self.run_rows(episode(far=False)+[('1d',native(login('80.10.20.30'),110))])
        self.assertIn(SEED,signals(out.iloc[-2]));self.assertNotIn(STRONG,signals(out.iloc[-2]))
        self.assertEqual(signals(out.iloc[-1]).get('auth_suspected_compromise_priority'),1)
        self.assertNotIn('auth_takeover_candidate',signals(out.iloc[-1]))
        self.assertEqual(out.iloc[-1].chronosift_score,8)

    def test_account_source_and_asset_boundaries(self):
        variants=[]
        rows=episode();rows[-1]=(rows[-1][0],native(login('80.10.20.30',far=True,sid=OTHER,user='other'),100));variants.append(rows)
        rows=episode();rows[-1]=(rows[-1][0],native(login('90.10.20.30',far=True),100));variants.append(rows)
        rows=episode();rows[-1][1]['win_asset_id']='other-image';variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows):self.assertNotIn(SEED,signals(self.run_rows(rows).iloc[-1]))
        rows=episode()+[('1d',native(login('90.10.20.30',far=True,sid=OTHER,user='other'),111))]
        self.assertNotIn(CONTEXT,signals(self.run_rows(rows).iloc[-1]))

    def test_missing_native_identity_fails_closed_and_is_reported(self):
        rows=episode()
        for _,r in rows:r.pop('record_number');r.pop('pathspec')
        with self.assertLogs(level=logging.INFO) as logs:out=self.run_rows(rows)
        self.assertNotIn(SEED,signals(out.iloc[-1]))
        self.assertTrue(any('missing_identity=' in line and 'missing_identity=0' not in line for line in logs.output))

    def test_success_only_then_later_travel_does_not_reuse_consumed_failures(self):
        rows=episode(far=False)+[('240s',native(login('80.10.20.30',far=True),110))]
        out=self.run_rows(rows)
        self.assertEqual(sum(bool(signals(r).get(SEED)) for _,r in out.iterrows()),1)
        self.assertNotIn(STRONG,signals(out.iloc[-1]))

    def test_new_qualified_attempts_can_renew(self):
        rows=episode()+[('6d',native(login('80.10.20.30',far=True),110))]
        for i in range(10):rows.append((f'6d{10+i*5}s',native(login('90.10.20.30',success=False),200+i)))
        rows += [('6d120s',native(login('90.10.20.30'),220)),('8d',native(login('90.10.20.30'),221))]
        out=self.run_rows(rows);self.assertIn(STRONG,signals(out.iloc[-2]));self.assertIn('auth_takeover_candidate',signals(out.iloc[-1]))

    def test_creator_link_survives_beyond_short_failure_window(self):
        rows=episode()+[('2d',native(account(4720,OTHER,win_subject_sid=SID),300)),
            ('2d1m',native(account(4732,'S-1-5-32-544',win_member_sid=OTHER,group_name='Administrators'),301)),
            ('2d2m',native(login('90.10.20.30',sid=OTHER,user='support2'),302))]
        out=self.run_rows(rows)
        self.assertIn('windows_created_by_compromised_account',signals(out.iloc[-3]))
        self.assertIn('windows_compromised_creator_privileged_account_use',signals(out.iloc[-1]))
        self.assertEqual(signals(out.iloc[-1]).get('windows_risky_creator_context'),1)
        self.assertEqual(signals(out.iloc[-1]).get('windows_privileged_activity_context'),1)

    def test_policy_threshold_window_and_qualifiers_are_authoritative(self):
        rules=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v27.yaml').read_text())
        weights=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v23.yaml').read_text())
        for t in rules['temporal_rules']:
            if t['id'] in (SEED.upper(),STRONG.upper()):t['sequence'][0]['min_count']=11
        engine=c.ChronoSiftEngine(rules,weights,yara_metadata_path=str(self.metadata))
        self.assertNotIn(SEED,signals(self.run_rows(episode(),engine).iloc[-1]))
        for t in rules['temporal_rules']:
            if t['id'] in (SEED.upper(),STRONG.upper()):t['sequence'][0]['min_count']=10;t['lookback']='10s'
        engine=c.ChronoSiftEngine(rules,weights,yara_metadata_path=str(self.metadata))
        self.assertNotIn(SEED,signals(self.run_rows(episode(),engine).iloc[-1]))

    def test_unresolved_failure_identity_binds_to_resolved_success(self):
        rows=episode()
        for _,r in rows:
            if r['event_identifier']==4625:
                r['win_target_sid']='S-1-0-0'
                r['xml_string']=r['xml_string'].replace(SID,'S-1-0-0')
            else:
                r['xml_string']=r['xml_string'].replace('<EventData>','<EventData><Data Name="TargetDomainName">BRANCH</Data>')
        rows.append(('1d',native(login('90.10.20.30',far=True),111)))
        out=self.run_rows(rows)
        self.assertIn(STRONG,signals(out.iloc[-2]));self.assertIn('auth_takeover_candidate',signals(out.iloc[-1]))

    def test_sustained_burst_and_travel_can_seed_from_a_known_source(self):
        rows=episode()
        rows.insert(0,('-2h',native(login('80.10.20.30',far=True),2)))
        out=self.run_rows(rows);r=out.iloc[-1]
        self.assertNotIn('windows_account_new_source',signals(r))
        self.assertNotIn('new_country',signals(r))
        self.assertIn(STRONG,signals(r))

    def test_conflicting_known_failure_realm_and_sid_do_not_taint_success(self):
        for conflict in ('realm','sid'):
            rows=episode()
            for _,r in rows:
                realm='OTHER' if conflict=='realm' and r['event_identifier']==4625 else 'BRANCH'
                r['xml_string']=r['xml_string'].replace('<EventData>',f'<EventData><Data Name="TargetDomainName">{realm}</Data>')
                if conflict=='sid' and r['event_identifier']==4625:
                    r['xml_string']=r['xml_string'].replace(SID,OTHER);r['win_target_sid']=OTHER
            with self.subTest(conflict=conflict):self.assertNotIn(SEED,signals(self.run_rows(rows).iloc[-1]))

    def test_controls_validate_types_modes_and_signal_contracts(self):
        doc=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v27.yaml').read_text())
        rule=next(t for t in doc['temporal_rules'] if t['id']==STRONG.upper())
        for change in ({'deduplicate_by':[]},{'deduplicate_by':'record'},{'consume_on_completion':'true'},
                       {'match_signals_any':[]},{'match_signals_all':['UPPER']},
                       {'cooccur':{'all':[{'signal':'auth_success','min_count':1}]},'sequence':None}):
            trial=deepcopy(rule);trial.update(change)
            if 'cooccur' in trial:trial.pop('sequence')
            with self.subTest(change=change),self.assertRaises(ValueError):self.engine._parse_temporal_rules([trial])
        bad=deepcopy(doc);next(t for t in bad['temporal_rules'] if t['id']==STRONG.upper())['match_signals_all']=['not_a_producer']
        with self.assertRaises(ValueError):c.ChronoSiftEngine(bad,yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v23.yaml').read_text()),yara_metadata_path=str(self.metadata))

    def test_history_projection_and_composed_overlap_include_new_dependencies(self):
        self.assertIn('auth_native_record_key',self.engine._temporal_required_columns())
        self.assertIn('auth_native_record_key',self.engine._compact_temporal_columns())
        self.assertGreaterEqual(self.engine.minimum_partition_overlap(),pd.Timedelta('14d30m'))

    def test_partitioned_native_output_equals_whole_frame_across_month_and_expiry(self):
        rows=episode()+[('1d',native(login('90.10.20.30',far=True),120)),
                        ('6d',native(login('80.10.20.30',far=True),121)),
                        ('7d121s',native(login('80.10.20.30',far=True),122))]
        raw=episode_frame(rows);expected=self.run_rows(rows)
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'input';output=Path(td)/'output'
            for (year,month),g in raw.groupby([raw.index.year,raw.index.month]):
                d=base/f'year={year}'/f'month={month}';d.mkdir(parents=True);g.to_parquet(d/'part.parquet')
            self.engine.process_parquet_dataset_partitioned(str(base),str(output),output_mode='sidecar',file_hit_manifest={},materialise_event_columns=True)
            con=duckdb.connect();self.addCleanup(con.close)
            actual=con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_signals FROM read_parquet(?) ORDER BY 1',[str(output/'**/*.parquet')]).fetchall()
            expected=expected.sort_values('chronosift_row_id')
            self.assertEqual(len(actual),len(expected))
            for (rid,score,sig),(_,r) in zip(actual,expected.iterrows()):
                self.assertEqual(rid,r.chronosift_row_id);self.assertAlmostEqual(score,r.chronosift_score);self.assertEqual(sig,r.chronosift_signals)

if __name__=='__main__':unittest.main()
