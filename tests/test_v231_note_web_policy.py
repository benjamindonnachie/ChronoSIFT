"""v26 boundaries: weak URL names != exploit; note content != encryptor."""
from copy import deepcopy
from dataclasses import replace
import json
import logging
from pathlib import Path
import tempfile
import unittest
import pandas as pd
import yaml

import chronoSIFT_v2_31 as c
from benchmarks.build_note_web_policy import build, weights, render, NOTE_RULES

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v26.yaml'
WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v22.yaml'


def fs(path, **extra):
    return dict(parser='filestat',filename=path,timestamp_desc='Creation Time',file_entry_type='file',**extra)


def web(path,status=404):
    return dict(parser='apache_access',http_request=f'GET {path} HTTP/1.1',http_response_code=status)


def sig(row):
    value=row.get('chronosift_signals')
    return value if isinstance(value,dict) else {}


class NoteWebPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.metadata=Path(cls.temp.name)/'fixture.yar'
        rules={name:(75,70,'') for name in NOTE_RULES}
        rules.update(TEST_WEBSHELL_Strong=(75,85,''),TEST_Ransomware_Binary=(75,85,''),
            FUTURE_Note=(60,60,'category = "ransom_note"'),
            LOW_SCORE=(49,90,'category = "ransom_note"'),
            LOW_QUALITY=(90,49,'category = "ransom_note"'),
            UNREVIEWED_Ransom_Note_Dropper=(75,85,''),
            TEST_UNUSED=(75,70,''))
        cls.metadata.write_text('\n'.join(f'rule {name} {{\nmeta:\n score = {s}\n quality = {q}\n {tag}\ncondition:\n false\n}}'
            for name,(s,q,tag) in rules.items()))
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)
        cls.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.metadata))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup();logging.getLogger().setLevel(cls.level)

    def rows(self,*records,engine=None):
        data=pd.DataFrame([dict(hostname='fixture-host',chronosift_row_id=710+i,**record) for i,record in enumerate(records)],
            index=pd.date_range('2024-06-30T23:59:00Z',periods=len(records),freq='min',name='datetime'))
        result=(engine or self.engine).apply(data,apply_profiling=False)
        self.assertEqual(result.chronosift_row_id.tolist(),list(range(710,710+len(records))))
        self.assertEqual(result.index.tolist(),data.index.tolist())
        for _,row in result.iterrows():
            explanations=row.get('chronosift_explain')
            if not isinstance(explanations,list): explanations=[]
            self.assertAlmostEqual(row.chronosift_score,min(50,sum(x['score_contribution'] for x in explanations)))
        return result

    def test_reproducible_policy_and_bounded_weight_changes(self):
        for name,content in render().items(): self.assertEqual((ROOT/name).read_text(),content)
        prior=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v21.yaml').read_text())
        new=weights();extra={k:new['weights'].pop(k) for k in ('web_shell_name_probe','yara_ransom_note')}
        self.assertEqual(extra,dict(web_shell_name_probe=1,yara_ransom_note=8));self.assertEqual(new,prior)

    def test_name_only_is_one_point_even_on_success_or_unknown_status(self):
        for status in (404,'404',200,403,None):
            for path in ('/manual/shell.php','/manual/c99-guide.html','/webshell','/cmd.php'):
                with self.subTest(status=status,path=path):
                    row=self.rows(web(path,status)).iloc[0]
                    self.assertEqual(row.chronosift_score,1)
                    self.assertNotIn('web_exploitation_hint',sig(row))
                    self.assertNotIn('exploit_public_facing_app',sig(row))
        self.assertEqual(self.rows(web('/manual/help.php')).iloc[0].chronosift_score,0)

    def test_real_exploit_syntax_on_404_and_independent_webshell_remain(self):
        for path in ('/../../etc/passwd','/shell.php?cmd=id','/index.php?exec=whoami'):
            row=self.rows(web(path)).iloc[0]
            self.assertIn('exploit_public_facing_app',sig(row));self.assertGreater(row.chronosift_score,1)
        rows=self.rows(fs('/var/www/html/DVWA/hackable/uploads/utility.php',yara_match=['TEST_WEBSHELL_Strong']),
                       web('/DVWA/hackable/uploads/utility.php',200))
        self.assertIn('webshell_artifact',sig(rows.iloc[0]));self.assertIn('webshell_activity',sig(rows.iloc[1]))

    def test_readme_no_longer_corroborates_ransomware(self):
        source=fs('/opt/payload.bin',av_hit=True,av_signature='Win.Ransomware.Sample-1-0')
        alone=self.rows(source).iloc[0]
        self.assertEqual(alone.chronosift_score,33)
        for name in ('README','HOW_TO_DECRYPT.txt','Restore.wav'):
            rows=self.rows(source,dict(fs('/usr/share/doc/'+name),timestamp_desc='Access Time'))
            self.assertEqual(rows.iloc[0].chronosift_score,33)
            self.assertNotIn('ransomware_activity_candidate',sig(rows.iloc[0]))
            self.assertEqual(rows.iloc[1].chronosift_score,0)

    def test_six_reviewed_content_rules_and_future_explicit_category(self):
        for name in (*NOTE_RULES,'FUTURE_Note'):
            with self.subTest(name=name):
                row=self.rows(fs('/home/operator/arbitrary.bin',yara_match=[name])).iloc[0]
                self.assertIn('yara_ransom_note',sig(row));self.assertNotIn('yara_ransomware',sig(row))
                self.assertNotIn('ransomware_activity_candidate',sig(row))
                self.assertGreaterEqual(row.chronosift_score,8)
                item=next(e for e in row.chronosift_explain if e['rule_id']=='YARA_RANSOM_NOTE')
                self.assertEqual(item['evidence']['rule_names'],[name])

    def test_generic_ransomware_and_dropper_are_not_note_evidence(self):
        for name in ('TEST_Ransomware_Binary','UNREVIEWED_Ransom_Note_Dropper'):
            row=self.rows(fs('/home/operator/README',yara_match=[name])).iloc[0]
            self.assertIn('yara_ransomware',sig(row));self.assertNotIn('yara_ransom_note',sig(row))
            self.assertNotIn('ransomware_activity_candidate',sig(row))

    def test_one_rules_score_and_quality_must_both_qualify(self):
        row=self.rows(fs('/home/operator/note',yara_match=['LOW_SCORE','LOW_QUALITY'])).iloc[0]
        self.assertNotIn('yara_ransom_note',sig(row));self.assertIn('yara_hit_strength',sig(row))
        with self.assertRaisesRegex(ValueError,'metadata'):
            self.rows(fs('/home/operator/note',yara_match=['UNKNOWN_Ransomnote']))

    def test_real_note_corroboration_preserves_path_and_not_self_linkage(self):
        source=fs('/opt/payload.bin',av_hit=True,av_signature='Win.Ransomware.Sample-1-0')
        note=fs('/home/operator/arbitrary.bin',yara_match=[NOTE_RULES[0]])
        rows=self.rows(source,note)
        self.assertEqual(rows.iloc[0].chronosift_score,42)
        item=next(x for x in rows.iloc[0].chronosift_explain if x['rule_id']=='RANSOMWARE_IMPACT')
        self.assertEqual(item['evidence']['ransom_note_path'],note['filename'])
        self.assertEqual(item['evidence']['ransom_note_signals'],'yara_ransom_note')
        for first,second in [('/opt/payload.bin','/opt/payload.bin'),(r'C:\Users\a\note.txt',r'c:\users\A\NOTE.TXT')]:
            rows=self.rows(dict(source,filename=first),dict(note,filename=second))
            self.assertNotIn('ransomware_activity_candidate',sig(rows.iloc[0]))
        rows=self.rows(dict(source,yara_match=[NOTE_RULES[0]]))
        self.assertNotIn('ransomware_activity_candidate',sig(rows.iloc[0]))

    def test_windows_created_notes_require_content_not_names(self):
        source=fs(r'\Users\operator\payload.exe',av_hit=True,av_signature='Win.Ransomware.Sample-1-0')
        note=fs(r'\Users\operator\README.txt')
        for direct in (False,True):
            first=dict(source);second=dict(note)
            for item in (first,second):
                item['pathspec']='{"location":"fixture.E01"}'
                if direct:item['user_identifier']='S-1-5-21-101-202-303-1501'
            bare=self.rows(first,second)
            self.assertNotIn('windows_note_created',sig(bare.iloc[1]))
            positive=self.rows(first,dict(second,filename=r'\Users\operator\arbitrary.bin',yara_match=[NOTE_RULES[0]]))
            self.assertIn('windows_note_created',sig(positive.iloc[1]))
            expected='windows_ransom_note_context' if direct else 'windows_ransom_note_host_context'
            self.assertIn(expected,sig(positive.iloc[1]))

    def test_prior_recovery_inhibition_and_closed_time_boundaries(self):
        data=pd.DataFrame({'filename':['/opt/payload.bin','/home/operator/note']},
                          index=pd.to_datetime(['2024-06-01T00:00:00Z','2024-06-01T02:00:00Z']))
        for delta,expected in [('0s',True),('1us',False)]:
            data.index=pd.DatetimeIndex([data.index[0],pd.Timestamp('2024-06-01T02:00:00Z')+pd.Timedelta(delta)])
            signals={0:{'av_ransomware':1},1:{'yara_ransom_note':1}}
            self.engine._apply_ransomware_impact_policy_sparse(data,signals,{})
            self.assertEqual('ransomware_activity_candidate' in signals[0],expected)
        signals={0:{'inhibit_system_recovery':1},1:{'av_ransomware':1}}
        data.index=pd.date_range('2024-06-01',periods=2,freq='min',tz='UTC')
        self.engine._apply_ransomware_impact_policy_sparse(data,signals,{})
        self.assertIn('ransomware_activity_candidate',signals[1])

    def test_policy_validation_and_dependency_visibility(self):
        changes=[lambda p:p['detector_policy']['detectors']['ransomware_impact']['branches']['ransom_note'].update(basename_contains=['readme']),
                 lambda p:p['detector_policy']['detectors']['ransomware_impact']['branches']['ransom_note'].update(any_signals=['undefined_note']),
                 lambda p:p['detector_policy']['detectors']['yara_classification']['categories']['ransom_note']['qualification'].update(minimum_score=101)]
        for change in changes:
            doc=deepcopy(build());change(doc)
            with self.assertRaises(ValueError): c.ChronoSiftEngine(doc,weights(),yara_metadata_path=str(self.metadata))
        self.assertIn('yara_ransom_note',self.engine.detector_policy.ransomware_impact.target_signals)

    def test_private_helpers_cannot_overwrite_public_rule_metadata(self):
        text='''rule PUBLIC_A {
meta:
 score = 80
 quality = 85
condition:
 false
}
private rule PRIVATE_HELPER {
meta:
 score = 5
 quality = 6
 tc_detection_type = "ransomware"
condition:
 false
}
global rule PUBLIC_GLOBAL {
meta:
 score = 60
 quality = 70
condition:
 false
}
global private rule PRIVATE_GLOBAL_HELPER {
meta:
 score = 1
 quality = 2
 tc_detection_type = "ransomware"
condition:
 false
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'helpers.yar';path.write_text(text)
            index=c.parse_yara_forge_metadata(str(path),self.engine.detector_policy.yara_classification)
            self.assertEqual(set(index),{'PUBLIC_A','PUBLIC_GLOBAL'})
            self.assertEqual((index['PUBLIC_A'].score,index['PUBLIC_A'].quality),(80,85))
            self.assertEqual((index['PUBLIC_GLOBAL'].score,index['PUBLIC_GLOBAL'].quality),(60,70))
            self.assertEqual(index['PUBLIC_A'].category,'malware')
            self.assertEqual(index['PUBLIC_GLOBAL'].category,'malware')

    def test_native_two_month_compact_and_expanded_history_parity(self):
        records=[fs('/opt/payload.bin',av_hit=True,av_signature='Win.Ransomware.Sample-1-0'),
                 fs('/usr/share/doc/pkg/README'),fs('/home/operator/note.bin',yara_match=[NOTE_RULES[0]]),web('/manual/shell.php')]
        data=pd.DataFrame([dict(chronosift_row_id=910+i,hostname='fixture-host',**r) for i,r in enumerate(records)],
                          index=pd.date_range('2024-06-30T23:59:00Z',periods=4,freq='min',name='datetime'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c.write_time_partitioned_parquet(data,str(root/'input'),normalise=False)
            outs=[]
            for compact in (False,True):
                e=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata))
                e.partition_execution_policy={**e.partition_execution_policy,'compact_history':compact}
                e.profiling_policy=replace(e.profiling_policy,enabled=False)
                reports=e.process_parquet_dataset_partitioned(str(root/'input'),str(root/str(compact)),output_mode='sidecar',materialise_event_columns=True)
                self.assertEqual(sum(r['rows_written'] for r in reports),4)
                out=c.load_plaso_parquet_dataset(str(root/str(compact))).set_index('chronosift_row_id').sort_index()
                self.assertEqual(out.index.tolist(),[910,911,912,913]);self.assertEqual(out.loc[910].chronosift_score,42)
                self.assertEqual(out.loc[911].chronosift_score,0);self.assertEqual(out.loc[913].chronosift_score,1)
                outs.append(out.chronosift_score.tolist())
            self.assertEqual(*outs)


if __name__=='__main__': unittest.main()
