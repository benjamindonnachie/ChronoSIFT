"""Small, real-Parquet checks of the isolated full-run validation harness."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

import duckdb
import pandas as pd

SCRIPT=Path(__file__).resolve().parents[1]/'benchmarks/run_final_dataset_validation.py'
SPEC=importlib.util.spec_from_file_location('final_dataset_validation',SCRIPT)
runner=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)

class FinalDatasetValidationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.run=self.root/'run'; self.run.mkdir()
        self.con=duckdb.connect(); self.addCleanup(self.con.close)

    def fixture(self,ids=(10,11,12),scores=(0.,5.,50.),contributions=(None,[5.],[30.,30.])):
        dataset=self.root/'base'; dataset.mkdir()
        side=self.run/'sidecar'; side.mkdir()
        pd.DataFrame(dict(chronosift_row_id=[10,11,12],year=[2024]*3,month=[5]*3)).to_parquet(dataset/'part.parquet',index=False)
        pd.DataFrame(dict(chronosift_row_id=ids,chronosift_score=scores,
            chronosift_explain=[None if items is None else [json.dumps(dict(score_contribution=n)) for n in items] for items in contributions],
            year=[2024]*3,month=[5]*3)).to_parquet(side/'part.parquet',index=False)
        (self.run/'reports.json').write_text(json.dumps([dict(year=2024,month=5,rows_written=3)]))
        return dataset

    def test_keys_and_capped_explanations_including_null(self):
        result=runner.validate(self.con,self.fixture(),self.run,[(2024,5,3)])
        self.assertTrue(result['valid']); self.assertEqual(result['rows'],3)

    def test_missing_and_duplicate_id_fail(self):
        with self.assertRaisesRegex(RuntimeError,'identity/score'):
            runner.validate(self.con,self.fixture(ids=(10,10,12)),self.run,[(2024,5,3)])
        result=json.loads((self.run/'validation.json').read_text())
        self.assertEqual(result['unique_ids'],2); self.assertEqual(result['missing_or_extra_keys'],1)

    def test_wrong_contribution_fails(self):
        with self.assertRaisesRegex(RuntimeError,'identity/score'):
            runner.validate(self.con,self.fixture(scores=(0.,6.,50.)),self.run,[(2024,5,3)])
        self.assertEqual(json.loads((self.run/'validation.json').read_text())['explanation_sum_errors'],1)

    def test_report_mismatch_fails(self):
        dataset=self.fixture(); (self.run/'reports.json').write_text('[]')
        with self.assertRaises(RuntimeError): runner.validate(self.con,dataset,self.run,[(2024,5,3)])

    def test_source_manifest_and_changed_snapshot(self):
        source=self.root/'source'; source.mkdir(); (source/'item.py').write_text('original')
        (source/'manifest.json').write_text(json.dumps(dict(sha256={'item.py':runner.sha(source/'item.py')})))
        runner.verify_source(source); (source/'item.py').write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'Frozen source changed'): runner.verify_source(source)

    def test_arguments_preserve_auto_overlap_and_all_enrichment(self):
        args=runner.arguments(self.root,self.root/'source',self.root/'dataset',self.run)
        self.assertNotIn('--overlap',args); self.assertNotIn('--months',args)
        self.assertFalse(any('guard' in arg or 'rss-limit' in arg for arg in args))
        for flag,_ in runner.resource_paths(self.root): self.assertIn(flag,args)
        self.assertIn('--profile-manifest-path',args); self.assertIn('--file-hit-manifest-path',args)
        self.assertEqual(args[args.index('--rules-yaml')+1],str(self.root/'source'/runner.RULES))

    def test_existing_artifact_is_never_overwritten(self):
        path=self.root/'result.json'; runner.save(path,dict(original=True))
        with self.assertRaises(FileExistsError): runner.save(path,dict(original=False))
        self.assertEqual(json.loads(path.read_text()),dict(original=True))

    def test_full_ubuntu_audit_on_tiny_real_sidecar(self):
        sys.path.insert(0,str(SCRIPT.parent)); self.addCleanup(sys.path.remove,str(SCRIPT.parent))
        from audit_final_datasets import audit
        dataset=self.fixture()
        data=pd.read_parquet(dataset/'part.parquet')
        data['datetime']=pd.to_datetime(['2024-05-01T00:00:00Z']*3)
        data['parser']='filestat'; data['filename']='/unrelated.txt'; data['message']='ordinary file'
        data['ip_address']=''; data['http_request']=''; data['http_request_user_agent']=''
        data.to_parquet(dataset/'part.parquet',index=False)
        runner.validate(self.con,dataset,self.run,[(2024,5,3)])
        self.con.from_parquet(str(self.run/'sidecar/*.parquet')).create_view('saved_side')
        self.con.execute('CREATE OR REPLACE VIEW side AS SELECT *,map([\'test\'],[1.0]) AS chronosift_signals FROM saved_side')
        source=self.root/'source'; source.mkdir(); gt=self.root/'groundtruth.txt'; gt.write_text('fixture ledger')
        runner.save(source/'groundtruth_ubuntu.json',dict(source=str(gt),sha256=runner.sha(gt),rows=[
            dict(event_id='GT-TEST',event_description='Synthetic audit fixture',anchor_ids=[11])]))
        runner.save(source/'baseline_runs.json',dict(ubuntu=str(self.run)))
        audit(self.con,dataset,self.run,source,'ubuntu')
        done=json.loads((self.run/'audit/complete.json').read_text())
        self.assertEqual(done['anchors'],1); self.assertEqual(done['cohorts'],11)
        matrix=json.loads((self.run/'audit/groundtruth_matrix.json').read_text())
        self.assertEqual(matrix[0]['scores'],[5.])
        self.assertIn('GT-TEST',(self.run/'audit/ASSESSMENT.md').read_text())

    def test_final_policy_automatic_overlap_writes_both_months(self):
        import chronoSIFT_v2_31 as c
        metadata=self.root/'rules.yar'
        metadata.write_text('rule TEST_WEBSHELL_Weak {\nmeta:\n score = 70\n quality = 85\ncondition:\n false\n}\n')
        wt=SCRIPT.parent.parent
        engine=c.ChronoSiftEngine.from_yaml(wt/'rules'/runner.RULES,wt/'rules'/runner.WEIGHTS,yara_metadata_path=str(metadata))
        self.assertEqual(engine.minimum_partition_overlap(),pd.Timedelta('199h'))
        data=pd.DataFrame([
            dict(chronosift_row_id=800,parser='filestat',filename='/var/www/html/admin_shell.php',timestamp_desc='Creation Time',yara_match=['TEST_WEBSHELL_Weak']),
            dict(chronosift_row_id=801,parser='apache_access',http_request='GET /admin_shell.php HTTP/1.1',http_response_code=200)],
            index=pd.DatetimeIndex(['2024-06-30T23:59:00Z','2024-07-01T00:01:00Z'],name='datetime'))
        data['hostname']='fixture-host'; base=self.root/'month-input'
        for (year,month),part in data.groupby([data.index.year,data.index.month]):
            path=base/f'year={year}'/f'month={month}'; path.mkdir(parents=True)
            part.to_parquet(path/'part.parquet')
        output=self.root/'month-output'
        engine.process_parquet_dataset_partitioned(str(base),str(output),output_mode='sidecar',materialise_event_columns=True)
        result=self.con.execute('SELECT chronosift_row_id,chronosift_score,evidence_web_identity,chronosift_signals FROM read_parquet(?,hive_partitioning=true,union_by_name=true) ORDER BY chronosift_row_id',[str(output/'**/*.parquet')]).fetchall()
        self.assertEqual([row[0] for row in result],[800,801])
        self.assertEqual(result[1][2],'/var/www/html/admin_shell.php')
        self.assertGreaterEqual(result[1][1],15)
        self.assertIn('webshell_activity',result[1][3])

    def test_arrow_native_yara_arrays_are_individual_names(self):
        import numpy as np
        import chronoSIFT_v2_31 as c
        for values,names in [(['RULE_A','RULE_B',None],['RULE_A','RULE_B']),([],[]),([None],[])]:
            cell=np.array(values,dtype=object)
            self.assertEqual(c.extract_yara_rule_names(cell),names)
            self.assertEqual(c.normalise_yara_match_count(cell),len(names))

if __name__=='__main__': unittest.main()
