"""Chronological carry, qualified novelty and one-hop creator-risk regression."""
from copy import deepcopy
from dataclasses import replace
import json
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import duckdb
import pandas as pd
import yaml
import chronoSIFT_v2_31 as c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT/'rules/rules_evidence_calibrated_v16.yaml'
WEIGHTS = ROOT/'rules/weights_evidence_calibrated_v15.yaml'
PARENT = 'S-1-5-21-101-202-303-500'
CHILD = 'S-1-5-21-101-202-303-1501'
OTHER = 'S-1-5-21-101-202-303-1502'
START = pd.Timestamp('2024-06-30T10:00:00Z')
RISK = 'windows_risky_creator_context'
NOVEL = 'windows_first_observed_dual_use_execution'


def account(event, sid=CHILD, **extra):
    result = dict(parser='winevtx', source_name='Microsoft-Windows-Security-Auditing',
                event_identifier=event, win_target_sid=sid,
                target_user_name='operator' if sid==PARENT else 'maint2', **extra)
    if event in (4624,4625):
        result.update(auth_outcome='success' if event==4624 else 'failure',
                      auth_direction='remote',auth_protocol='windows-network')
    return result


def bam(**extra):
    return dict(parser='winreg/bam', data_type='windows:registry:bam',
                message=rf'\Device\HarddiskVolume2\Users\maint2\Downloads\PsExec.exe [{CHILD}]',
                user_identifier=CHILD, timestamp_desc='Last Time Executed', **extra)


def frame(records):
    return pd.DataFrame([{'chronosift_row_id':900+i, 'hostname':'fixture-host', 'win_asset_id':'fixture-image', **row}
                         for i, (_, row) in enumerate(records)],
                        index=pd.DatetimeIndex([START+pd.Timedelta(t) for t, _ in records], name='datetime'))


class ContextProvenanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.metadata = cls.root/'fixture.yar'
        cls.metadata.write_text('rule UNUSED {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n')
        cls.engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(cls.metadata))
        cls.old_log_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        logging.getLogger().setLevel(cls.old_log_level)
        cls.temp.cleanup()

    def run_rows(self, records, injected=None):
        out = self.engine.apply_atomic(frame(records), apply_profiling=False, materialise_event_columns=False)
        if injected:
            signals = out.attrs['chronosift_sparse']['signal_map']
            for pos, value in injected.items():
                signals.setdefault(pos, {}).update(value)
        out = self.engine.apply_contextual(out, apply_profiling=False)
        if not injected:
            for _, row in out.iterrows():
                self.assertAlmostEqual(row.chronosift_score, min(50, sum(
                    e['score_contribution'] for e in (row.get('chronosift_explain') or []))))
        return out

    def chain(self, create='1h', grant='1h1m', action='3d'):
        return [
            ('0s', account(4624, PARENT, logon_type=3, ip_address='8.8.8.8')),
            (create, account(4720, win_subject_sid=PARENT)),
            (grant, account(4732, 'S-1-5-32-544', win_member_sid=CHILD, group_name='Administrators')),
            (action, bam()),
        ]

    def test_builder_and_yaml_horizon(self):
        output = subprocess.check_output([sys.executable, '-B', str(ROOT/'benchmarks/build_context_provenance_policy.py')], text=True)
        self.assertEqual(output, '*** Begin Patch\n*** End Patch\n')
        self.assertEqual(self.engine.minimum_partition_overlap(), pd.Timedelta('199h'))

    def test_observation_filter_rejects_invalid_signal_lists(self):
        rules=yaml.safe_load(RULES.read_text())
        original=rules['temporal_rules'][-1]
        for value in ('windows_program_execution', [], ['WINDOWS_PROGRAM_EXECUTION'],
                      ['windows_program_execution','windows_program_execution'], [None]):
            rule=deepcopy(original);rule['condition']['signals_any']=value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.engine._parse_temporal_rules([rule])

    def test_observation_filter_keeps_eligibility_guard(self):
        rules=yaml.safe_load(RULES.read_text());weights=yaml.safe_load(WEIGHTS.read_text())
        rules['engine_config']['temporal_signal_policy']['ineligible_signals'].append('windows_program_execution')
        with self.assertRaisesRegex(ValueError,'temporally ineligible'):
            c.ChronoSiftEngine(rules,weights,yara_metadata_path=str(self.metadata))

    def test_ignored_observation_does_not_remove_active_baseline_on_expiry(self):
        present=dict(parser='filestat',filename=rf'C:\Users\maint2\Downloads\PsExec.exe',
                     user_identifier=CHILD,timestamp_desc='Creation Time')
        out=self.run_rows([('0s',present),('1d',bam()),('7d1s',bam())])
        self.assertEqual([bool((r.get('chronosift_signals') or {}).get(NOVEL)) for _,r in out.iterrows()],
                         [False,True,False])

    def test_creator_and_child_remain_distinct(self):
        out = self.run_rows(self.chain(), {0:dict(impossible_travel=1)})
        self.assertEqual(out.iloc[1].win_creator_sid, PARENT)
        self.assertEqual(out.iloc[1].win_context_sid, CHILD)
        self.assertEqual(out.iloc[-1].chronosift_signals[RISK], 1)
        self.assertEqual(out.iloc[-1].chronosift_signals['windows_privileged_activity_context'], 1)
        e = next(e for e in out.iloc[1].chronosift_explain if e['rule_id']=='WINDOWS_CREATED_BY_RISKY_TRAVEL_ACCOUNT')
        self.assertEqual(e['evidence']['supporting_row_ids'], [900,901])
        self.assertIn(PARENT.casefold(), str(e['evidence']))

    def test_two_risk_routes_have_one_eight_point_owner(self):
        out = self.run_rows(self.chain(), {0:dict(impossible_travel=1,fail_then_success_user=1)})
        row = out.iloc[-1]
        owners = [e for e in row.chronosift_explain if e['rule_id']=='WINDOWS_RISKY_CREATOR_CONTEXT']
        self.assertEqual(len(owners), 1)
        self.assertEqual(owners[0]['score_contribution'], 8)

    def test_actual_failure_success_chain_without_injected_signals(self):
        records = [('0s',account(4625,PARENT,logon_type=3,ip_address='8.8.8.8')),
                   ('1s',account(4625,PARENT,logon_type=3,ip_address='8.8.8.8')),
                   ('2s',account(4625,PARENT,logon_type=3,ip_address='8.8.8.8'))]
        records += [('3s',self.chain()[0][1]),*self.chain()[1:]]
        out = self.run_rows(records)
        self.assertEqual(out.iloc[3].chronosift_signals['fail_then_success_user'], 1)
        self.assertEqual(out.iloc[-1].chronosift_signals[RISK], 1)

    def test_no_risk_from_new_account_or_new_ip_alone(self):
        out = self.run_rows(self.chain())
        self.assertFalse((out.iloc[-1].get('chronosift_signals') or {}).get(RISK))
        self.assertTrue(out.iloc[-1].chronosift_signals['windows_privileged_activity_context'])

    def test_no_cross_creator_or_asset_or_action_actor(self):
        variants = []
        rows = self.chain(); rows[1][1]['win_subject_sid']=OTHER; variants.append(rows)
        rows = self.chain(); rows[1][1]['win_asset_id']='different-image'; variants.append(rows)
        rows = self.chain(); rows[-1][1]['user_identifier']=OTHER
        rows[-1][1]['message']=rows[-1][1]['message'].replace(CHILD,OTHER); variants.append(rows)
        for records in variants:
            with self.subTest(records=records):
                out=self.run_rows(records,{0:dict(impossible_travel=1)})
                self.assertFalse((out.iloc[-1].get('chronosift_signals') or {}).get(RISK))

    def test_expiry_and_reverse_order(self):
        for records in (self.chain(create='25h',grant='25h1m'), self.chain(action='9d'),
                        self.chain(create='-2h',grant='-1h')):
            # Injection follows the actual auth row after atomic stable sorting.
            auth_pos = sorted(range(len(records)),key=lambda i:pd.Timedelta(records[i][0])).index(0)
            out=self.run_rows(records,{auth_pos:dict(impossible_travel=1)})
            self.assertFalse((out.iloc[-1].get('chronosift_signals') or {}).get(RISK))

    def test_inherited_risk_is_not_recursive_source(self):
        out=self.run_rows(self.chain(),{0:{RISK:1}})
        self.assertFalse((out.iloc[-1].get('chronosift_signals') or {}).get(RISK))

    def test_tool_presence_and_zero_count_do_not_seed_novelty(self):
        use=rf'C:\Users\maint2\Downloads\PsExec64.exe'
        rows=[('0s',dict(parser='filestat',filename=use,user_identifier=CHILD,timestamp_desc='Creation Time')),
              ('1s',dict(parser='winreg/userassist',application=use,user_identifier=CHILD,
                         timestamp_desc='Last Time Executed',message=f'Value name: {use} Count: 0 Application focus count: 0')),
              ('2s',bam()),('3s',bam())]
        out=self.run_rows(rows)
        self.assertEqual([bool((r.get('chronosift_signals') or {}).get(NOVEL)) for _,r in out.iterrows()], [False,False,True,False])
        self.assertFalse((out.iloc[1].get('chronosift_signals') or {}).get('windows_program_execution'))

    def test_tool_family_case_and_32_64_share_baseline(self):
        first=bam(); first['message']=first['message'].replace('PsExec.exe','PSEXEC64.EXE')
        out=self.run_rows([('0s',first),('2s',bam())])
        self.assertEqual(out.win_dual_use_tool.tolist(),['psexec','psexec'])
        self.assertEqual([bool(r.chronosift_signals.get(NOVEL)) for _,r in out.iterrows()],[True,False])

    def test_novelty_scope_expiry_and_tied_stable_ids(self):
        other=bam(); other['user_identifier']=OTHER; other['message']=other['message'].replace(CHILD,OTHER)
        out=self.run_rows([('0s',bam()),('0s',bam()),('1s',other),('8d',bam())])
        self.assertEqual(out.chronosift_row_id.tolist(),[900,901,902,903])
        self.assertEqual([bool(r.chronosift_signals.get(NOVEL)) for _,r in out.iterrows()],[True,False,True,True])

    def test_container_exclusion_preserves_real_sensitive_file(self):
        path=r'NTFS:\Windows\System32\config\SYSTEM'
        out=self.run_rows([('0s',bam(display_name=path)),
                           ('1s',dict(parser='filestat',filename=path,timestamp_desc='Access Time'))])
        self.assertFalse(out.iloc[0].chronosift_signals.get('sensitive_file_access'))
        self.assertEqual(out.iloc[1].chronosift_signals['sensitive_file_access'],1)

    def geo_frame(self, times, ips):
        values={'a':('8.8.8.8',0.,0.,'AA','1'),'b':('1.1.1.1',0.,120.,'BB','2'),
                'p':('10.1.1.1',0.,0.,'AA','1')}
        rows=[]
        for i,ip in enumerate(ips):
            addr,lat,lon,country,asn=values[ip]
            rows.append(dict(chronosift_row_id=100+i,continuity_scope='host',continuity_actor='sid',
                             src_ip=addr,ip_address=addr,geo_latitude=lat,geo_longitude=lon,
                             geo_country_iso=country,geo_asn=asn,geo_city_name=country))
        return pd.DataFrame(rows,index=pd.DatetimeIndex(times,name='datetime'))

    def continuity(self, data, states, cutoff=None):
        data['continuity_key']=[f'{scope}|{actor}' if scope and actor else ''
                                for scope,actor in zip(data.continuity_scope,data.continuity_actor)]
        sig={i:{'auth_remote_success':1} for i in range(len(data))}; exp={}
        self.engine._apply_geo_continuity_sparse(data,sig,exp,states[0],commit_before=cutoff)
        self.engine._apply_impossible_travel_sparse(data,sig,exp,states[1],commit_before=cutoff)
        self.engine._apply_private_ip_continuity_sparse(data,sig,exp,states[2],commit_before=cutoff)
        return {int(data.chronosift_row_id.iloc[i]):(sig.get(i,{}),exp.get(i,[])) for i in range(len(data))}

    def test_nearby_refresh_retains_distant_subminute_reference(self):
        f=self.geo_frame(['2024-01-01T00:00Z','2024-02-01T00:00Z','2024-02-01T00:00:30Z',
                          '2024-02-01T00:00:30Z','2024-02-01T00:01:01Z'],['a','a','b','b','b'])
        states=[{},{},{}]; result=self.continuity(f,states)
        self.assertFalse(result[102][0].get('impossible_travel'))
        self.assertFalse(result[103][0].get('impossible_travel'))
        self.assertTrue(result[104][0].get('impossible_travel'))
        travel=next(e for e in result[104][1] if e['rule_id']=='IMPOSSIBLE_TRAVEL')
        self.assertAlmostEqual(travel['evidence']['dt_hours'],61/3600,places=4)

    def test_overlapping_carry_matches_single_pass_all_three_detectors(self):
        raw=self.geo_frame(['2024-01-01T00:00Z','2024-01-25T00:00Z','2024-02-05T10:00Z',
                            '2024-02-05T10:02Z','2024-02-05T10:04Z','2024-02-09T12:00Z'],
                           ['a','a','a','b','p','b'])
        expected=self.continuity(raw.copy(),[{},{},{}])
        states=[{},{},{}]
        january=raw.loc[raw.index<pd.Timestamp('2024-02-08T06:00Z')].copy()
        cutoff=pd.Timestamp('2024-01-24T18:00Z')
        self.continuity(january,states,cutoff)
        self.assertLess(states[1][('host|sid',)]['retained_reference']['ts'],cutoff)
        february=raw.loc[raw.index>=cutoff].copy()
        actual=self.continuity(february,states)
        self.assertEqual(actual,{rid:value for rid,value in expected.items() if rid in actual})

    def test_checkpoint_exact_boundary_and_history_isolation(self):
        raw=self.geo_frame(['2024-01-01T00:00Z','2024-01-02T00:00Z','2024-01-02T00:02Z'],['a','b','p'])
        prefix=[{},{},{}];self.continuity(raw.iloc[:1].copy(),prefix)
        states=[{},{},{}];self.continuity(raw,states,pd.Timestamp('2024-01-02T00:00Z'))
        self.assertEqual(states,prefix)

    def test_scope_and_sid_isolate_travel(self):
        raw=self.geo_frame(['2024-01-01T00:00Z','2024-01-01T00:02Z','2024-01-01T00:04Z'],['a','b','b'])
        raw.loc[raw.index[1],'continuity_actor']='different-sid'
        raw.loc[raw.index[2],'continuity_scope']='different-host'
        result=self.continuity(raw,[{},{},{}])
        self.assertFalse(any(value[0].get('impossible_travel') for value in result.values()))

    def test_no_recursive_or_dataframe_copy_for_checkpoint(self):
        class NoDeepcopy:
            def __deepcopy__(self,memo):raise AssertionError('recursive copy')
        marker=NoDeepcopy();entry=dict(seen_countries={'AA':{'ip':'8.8.8.8'}},marker=marker)
        committed={'actor':entry,'untouched':NoDeepcopy()}; speculative={}
        with patch.object(pd.DataFrame,'copy',side_effect=AssertionError('dataframe copy')):
            work=c._continuity_working_state(committed,speculative,'actor',2,1)
            again=c._continuity_working_state(committed,speculative,'actor',3,1)
        self.assertIs(work,again);self.assertIs(work['actor']['marker'],marker)
        self.assertIsNot(work['actor']['seen_countries'],entry['seen_countries'])
        self.assertEqual(set(speculative),{'actor'})

    def test_partial_scoped_identity_does_not_seed_any_continuity(self):
        for missing in ('continuity_actor','continuity_scope'):
            raw=self.geo_frame(['2024-01-01T00:00Z','2024-01-01T00:02Z','2024-01-01T00:04Z'],['a','b','p'])
            raw[missing]='';states=[{},{},{}]
            result=self.continuity(raw,states)
            self.assertEqual(states,[{},{},{}])
            self.assertTrue(all(signals=={'auth_remote_success':1} and not explain
                                for signals,explain in result.values()))

    def test_yaml_join_requires_both_scope_and_identity(self):
        raw=pd.DataFrame([dict(win_asset_id='scope',win_target_sid=PARENT),
                          dict(win_asset_id='scope'),dict(win_target_sid=PARENT)],
                         index=pd.date_range('2024-01-01',periods=3,freq='s',tz='UTC'))
        out=self.engine._apply_normalisation(raw)
        self.assertEqual(out.continuity_key.iloc[0],f'scope|{PARENT.casefold()}')
        self.assertTrue(out.continuity_key.iloc[1:].isna().all())

    def test_native_monthly_sidecar_matches_one_frame_with_mock_geo(self):
        records=[('-28d',account(4624,PARENT,logon_type=3,ip_address='8.8.8.8')),
                 ('5d',account(4624,PARENT,logon_type=3,ip_address='8.8.8.8')),
                 ('5d2m',account(4624,PARENT,logon_type=3,ip_address='1.1.1.1')),
                 ('5d3m',account(4720,win_subject_sid=PARENT)),
                 ('5d4m',account(4732,'S-1-5-32-544',win_member_sid=CHILD,group_name='Administrators')),
                 ('8d',bam()),('8d',bam())]
        raw=frame(records)
        def geo(df,*args,ip_field,output_fields,**kwargs):
            return pd.DataFrame([{ip_field:ip,**{field:({'latitude':0.,'longitude':0. if ip=='8.8.8.8' else 120.,
                'country_iso':'AA' if ip=='8.8.8.8' else 'BB','city_name':'city','city_geoname_id':1,'asn':'1'})[role]
                for role,field in output_fields.items()}} for ip in df[ip_field].dropna().unique()])
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);base=root/'base'
        for (year,month),group in raw.groupby([raw.index.year,raw.index.month]):
            loc=base/f'year={year}'/f'month={month}';loc.mkdir(parents=True);group.to_parquet(loc/'part.parquet')
        with patch.object(c,'build_geoip_enrichment_table',side_effect=geo):
            expected=self.engine.apply_contextual(self.engine.apply_atomic(raw,apply_profiling=False,
                geoip_city_db='mock-city',geoip_asn_db='mock-asn'),apply_profiling=False)
            self.engine.process_parquet_dataset_partitioned(str(base),str(root/'output'),output_mode='sidecar',
                geoip_city_db='mock-city',geoip_asn_db='mock-asn',file_hit_manifest={},materialise_event_columns=True)
        con=duckdb.connect();self.addCleanup(con.close)
        saved=con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_signals,chronosift_explain FROM read_parquet(?) ORDER BY 1',
                          [str(root/'output/**/*.parquet')]).fetchall()
        self.assertEqual([row[0] for row in saved],expected.chronosift_row_id.tolist())
        for (rid,score,signals,explain),(_,row) in zip(saved,expected.iterrows()):
            self.assertAlmostEqual(score,row.chronosift_score)
            self.assertEqual(signals,row.chronosift_signals)
            self.assertAlmostEqual(score,min(50,sum(json.loads(e)['score_contribution'] for e in (explain or []))))
        self.assertTrue(saved[2][2].get('impossible_travel'))
        self.assertTrue(saved[-1][2].get(RISK))


if __name__=='__main__': unittest.main()
