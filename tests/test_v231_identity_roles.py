"""Reporting identity is not the authenticated user or the affected account."""
from copy import deepcopy
import json
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from xml.sax.saxutils import escape

import duckdb
import pandas as pd
import yaml
import chronoSIFT_v2_31 as c

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v17.yaml'
WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v15.yaml'
SEC='Microsoft-Windows-Security-Auditing'
RDP='Microsoft-Windows-TerminalServices-RemoteConnectionManager'
PARENT='S-1-5-21-101-202-303-500'
CHILD='S-1-5-21-101-202-303-1501'


def evtx(event, provider=SEC, data=None, user_data=None, **extra):
    payload=''.join(f'<Data Name="{name}">{escape(value)}</Data>' for name,value in (data or {}).items())
    if user_data is not None:
        payload='<UserData><EventXML xmlns="Event_NS">'+''.join(
            f'<Param{i}>{escape(value)}</Param{i}>' if value else f'<Param{i}/>'
            for i,value in enumerate(user_data,1))+'</EventXML></UserData>'
    else: payload='<EventData>'+payload+'</EventData>'
    xml=f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID>{event}</EventID><Security UserID="S-1-5-20"/></System>{payload}</Event>'
    return dict(parser='winevtx',source_name=provider,event_identifier=event,
                xml_string=xml,user_sid='S-1-5-20',hostname='host-a',win_asset_id='image-a',**extra)


class IdentityRolesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.metadata=cls.root/'fixture.yar'
        cls.metadata.write_text('rule UNUSED {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n')
        cls.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.metadata))
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        logging.getLogger().setLevel(cls.level);cls.temp.cleanup()

    def frame(self, records):
        return pd.DataFrame([dict(chronosift_row_id=800+i,**row) for i,row in enumerate(records)],
            index=pd.DatetimeIndex(['2024-06-30T23:59:00Z']*len(records),name='datetime'))

    def rows(self, *records):
        result=self.engine.apply_contextual(self.engine.apply_atomic(self.frame(records),apply_profiling=False),apply_profiling=False)
        for _,row in result.iterrows():
            self.assertAlmostEqual(row.chronosift_score,min(50,sum(e['score_contribution'] for e in (row.get('chronosift_explain') or []))))
        return result

    def test_builder_and_unchanged_weights_horizon(self):
        output=subprocess.check_output([sys.executable,'-B',str(ROOT/'benchmarks/build_identity_roles_policy.py')],text=True)
        self.assertEqual(output,'*** Begin Patch\n*** End Patch\n')
        self.assertEqual(self.engine.minimum_partition_overlap(),pd.Timedelta('199h'))

    def test_named_userdata_leaves_and_entities(self):
        row=self.rows(evtx(1149,RDP,user_data=['alice&bob','ACME','8.8.8.8'])).iloc[0]
        self.assertEqual(row.actor_principal,'alice&bob')
        self.assertEqual(row.identity_authenticated_account,r'ACME\alice&bob')
        self.assertEqual(row.identity_reporting_sid,'S-1-5-20')
        self.assertTrue(pd.isna(row.identity_authenticated_sid))
        self.assertEqual(row.continuity_actor,r'acme\alice&bob')

    def test_no_domain_keeps_name_but_no_continuity_or_invented_sid(self):
        row=self.rows(evtx(1149,RDP,user_data=['maint',None,'8.8.8.8'])).iloc[0]
        self.assertEqual(row.actor_principal,'maint')
        self.assertTrue(pd.isna(row.continuity_key))
        self.assertTrue(pd.isna(row.win_context_sid))
        self.assertTrue(pd.isna(row.identity_authenticated_sid))
        self.assertTrue(all(e['canonical_actor']=='maint' for e in row.chronosift_explain))

    def test_unknown_and_wrong_provider_never_use_reporting_account(self):
        for record in (evtx(1149,RDP,user_data=[None,None,'1.1.1.1']),
                       evtx(1149,'unrelated-provider',user_data=['someone','ACME','1.1.1.1']),
                       dict(parser='winevtx',event_identifier=1149,user_sid='S-1-5-20',hostname='host-a')):
            with self.subTest(record=record):
                row=self.rows(record).iloc[0]
                self.assertTrue(pd.isna(row.actor_principal))
                self.assertTrue(pd.isna(row.continuity_key))
                self.assertTrue(all(e['canonical_actor'] is None for e in (row.get('chronosift_explain') or [])))

    def test_missing_or_malformed_xml_does_not_guess_from_message(self):
        record=evtx(1149,RDP,user_data=['ignored','ACME','8.8.8.8'])
        record['xml_string']='<invalid';record['message']="Strings: ['administrator', None, '8.8.8.8']"
        row=self.rows(record).iloc[0]
        self.assertTrue(pd.isna(row.actor_principal));self.assertTrue(pd.isna(row.continuity_key))

    def test_4624_target_wins_over_subject_and_provider(self):
        row=self.rows(evtx(4624,data=dict(TargetUserSid=CHILD,TargetUserName='maint',TargetDomainName='ACME',
            SubjectUserSid='S-1-5-18',SubjectUserName='SYSTEM',LogonType='3',IpAddress='8.8.8.8'))).iloc[0]
        self.assertEqual(row.actor_principal,'maint')
        self.assertEqual(row.identity_authenticated_sid,CHILD)
        self.assertEqual(row.continuity_actor,CHILD.casefold())

    def test_null_sid_and_unqualified_target_do_not_pool(self):
        row=self.rows(evtx(4624,data=dict(TargetUserSid='S-1-0-0',TargetUserName='maint',LogonType='3',IpAddress='8.8.8.8'))).iloc[0]
        self.assertTrue(pd.isna(row.continuity_key))

    def test_removal_distinguishes_actor_member_and_group(self):
        row=self.rows(evtx(4729,data=dict(SubjectUserSid=CHILD,SubjectUserName='maint',SubjectDomainName='ACME',
            MemberSid=PARENT,MemberName='CN=Administrator,CN=Users,DC=acme',
            TargetUserName='Domain Admins',TargetDomainName='ACME',TargetSid='S-1-5-21-101-202-303-512'))).iloc[0]
        self.assertEqual(row.actor_principal,'maint');self.assertEqual(row.win_context_sid,CHILD)
        self.assertEqual(row.identity_affected_sid,PARENT);self.assertEqual(row.identity_affected_group,'Domain Admins')
        self.assertEqual(row.chronosift_score,8)
        for e in row.chronosift_explain:
            self.assertEqual(e['canonical_actor'],'maint')
        weighted=[e for e in row.chronosift_explain if e['score_contribution']]
        self.assertEqual(sorted(e['score_contribution'] for e in weighted),[2,6])
        self.assertTrue(all(e['evidence']['identity_acting_sid']==CHILD for e in weighted))

    def test_missing_management_subject_never_promotes_target_to_actor(self):
        row=self.rows(evtx(4729,data=dict(TargetUserName='Domain Admins',MemberSid=PARENT))).iloc[0]
        self.assertEqual(row.chronosift_score,8)
        self.assertTrue(pd.isna(row.actor_principal));self.assertTrue(pd.isna(row.win_context_sid))

    def test_creation_and_grant_keep_child_lifecycle_key(self):
        create=evtx(4720,data=dict(SubjectUserSid=PARENT,SubjectUserName='creator',SubjectDomainName='ACME',
            TargetSid=CHILD,TargetUserName='maint',TargetDomainName='ACME'))
        grant=evtx(4732,data=dict(SubjectUserSid=PARENT,SubjectUserName='creator',SubjectDomainName='ACME',
            MemberSid=CHILD,TargetSid='S-1-5-32-544',TargetUserName='Administrators'))
        out=self.rows(create,grant)
        self.assertEqual(out.win_context_sid.tolist(),[CHILD,CHILD])
        self.assertEqual(out.actor_principal.tolist(),['creator']*2)
        self.assertEqual(out.iloc[0].win_creator_sid,PARENT)

    def test_repeated_normalisation_revokes_stale_unknown_actor(self):
        record=evtx(1149,RDP,user_data=[None,None,'8.8.8.8'],actor_principal='stale',actor_user='stale')
        out=self.engine.apply_atomic(self.frame([record]),apply_profiling=False)
        out=self.engine._apply_normalisation(out)
        self.assertTrue(pd.isna(out.iloc[0].actor_principal))

    def test_non_windows_unchanged(self):
        out=self.rows(dict(parser='text/syslog_traditional',message='sshd: Accepted password for root from 8.8.8.8 port 50022 ssh2',hostname='linux'))
        self.assertEqual(out.iloc[0].actor_principal,'root')

    def test_domain_display_preserves_privilege_and_failure_sequence_contract(self):
        records=[evtx(4625,data=dict(TargetUserName='Administrator',TargetDomainName='-',
                    LogonType='3',IpAddress='8.8.8.8')) for _ in range(3)]
        records.append(evtx(4624,data=dict(TargetUserName='Administrator',TargetDomainName='ACME',
            TargetUserSid=PARENT,LogonType='3',IpAddress='8.8.8.8')))
        data=self.frame(records)
        data.index=pd.date_range('2024-06-30T23:00Z',periods=4,freq='s',name='datetime')
        out=self.engine.apply_contextual(self.engine.apply_atomic(data,apply_profiling=False),apply_profiling=False)
        row=out.iloc[-1]
        self.assertEqual(row.actor_principal,'Administrator')
        self.assertEqual(row.identity_authenticated_account,r'ACME\Administrator')
        for signal in ('privileged_login','exec_privileged_context','fail_then_success_user'):
            self.assertEqual(row.chronosift_signals.get(signal),1,signal)

    def test_selector_validation_and_first_match_null(self):
        spec=dict(name='chosen',method='select_coalesce',cases=[dict(field='kind',pattern='^auth$',fields=['missing']),
            dict(field='kind',pattern='.*',fields=['provider'])],default_fields=['provider'])
        parsed=c._parse_normalisation_policy([spec],'normalisation')
        engine=deepcopy(self.engine);engine.normalisation=parsed
        raw=pd.DataFrame(dict(kind=['auth','other'],provider=['service','other-service']))
        out=engine._apply_normalisation(raw)
        self.assertTrue(pd.isna(out.iloc[0].chosen));self.assertEqual(out.iloc[1].chosen,'other-service')
        for change in ({'cases':[]},{'default_fields':'provider'},{'unknown':True}):
            with self.assertRaises(ValueError):c._parse_normalisation_policy([{**spec,**change}],'normalisation')
        for change in ({'pattern':'['},{'fields':['x','x']},{'field':''},{'extra':True}):
            invalid=deepcopy(spec);invalid['cases'][0].update(change)
            with self.assertRaises(ValueError):c._parse_normalisation_policy([invalid],'normalisation')

    def test_scoped_accounts_and_anonymous_do_not_share_geo_state(self):
        records=[evtx(1149,RDP,user_data=['maint','ACME','8.8.8.8']),
                 evtx(1149,RDP,user_data=['maint','OTHER','1.1.1.1']),
                 evtx(1149,RDP,user_data=[None,None,'1.1.1.1'])]
        out=self.engine.apply_atomic(self.frame(records),apply_profiling=False)
        self.assertNotEqual(out.iloc[0].continuity_key,out.iloc[1].continuity_key)
        self.assertTrue(pd.isna(out.iloc[2].continuity_key))
        out['geo_latitude']=[0.,0.,0.];out['geo_longitude']=[0.,120.,120.]
        out['geo_country_iso']=['AA','BB','BB'];out['geo_asn']=['1','2','2']
        state={};signals={i:{'auth_remote_success':1} for i in range(3)}
        self.engine._apply_geo_continuity_sparse(out,signals,{},state)
        self.assertEqual(len(state),2)

    def test_native_tied_rows_keep_role_columns_and_explanations(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);base=root/'base/year=2024/month=6';base.mkdir(parents=True)
            self.frame([evtx(1149,RDP,user_data=['maint',None,'8.8.8.8']),
                        evtx(1149,RDP,user_data=[None,None,'1.1.1.1'])]).to_parquet(base/'part.parquet')
            self.engine.process_parquet_dataset_partitioned(str(root/'base'),str(root/'sidecar'),output_mode='sidecar',materialise_event_columns=True)
            con=duckdb.connect()
            try:
                rows=con.execute('SELECT chronosift_row_id,actor_principal,identity_reporting_sid,continuity_key,chronosift_explain FROM read_parquet(?) ORDER BY 1',[str(root/'sidecar/**/*.parquet')]).fetchall()
            finally:con.close()
            self.assertEqual([r[0] for r in rows],[800,801]);self.assertEqual([r[1] for r in rows],['maint',None])
            self.assertEqual([r[2] for r in rows],['S-1-5-20']*2);self.assertEqual([r[3] for r in rows],[None,None])
            self.assertTrue(all(json.loads(e)['canonical_actor'] is None for e in rows[1][4]))


if __name__=='__main__':unittest.main()
