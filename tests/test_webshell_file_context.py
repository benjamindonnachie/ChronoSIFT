"""Bounded created-file context through public APIs and generic policy IO."""
from copy import deepcopy
from dataclasses import replace
import json,logging
from pathlib import Path
import tempfile,unittest
import duckdb,pandas as pd,yaml
import chronoSIFT_v2_31 as c
ROOT=Path(c.__file__).resolve().parent
START=pd.Timestamp('2024-06-30T23:38:00Z')
META='''rule TEST_WEBSHELL_Generic
{
 meta:
  score = 70
  quality = 0
 condition:
  false
}
'''

def file(path='/var/www/html/console.php',kind='Creation Time',hit=True):
 d=dict(parser='filestat',filename=path,timestamp_desc=kind)
 if hit:d['yara_match']=['TEST_WEBSHELL_Generic']
 return d

def request(path='/console.php',status=200):
 return dict(parser='text/apache_access',http_request=f'POST {path} HTTP/1.1',http_response_code=status,ip_address='203.0.113.80')

def frame(rows):
 return pd.DataFrame([dict(chronosift_row_id=810+i,hostname='fixture',**r) for i,(_,r) in enumerate(rows)],index=pd.DatetimeIndex([START+pd.Timedelta(t) for t,_ in rows],name='datetime'))

def signals(row):return row.get('chronosift_signals') or {}

class WebshellFileContextTest(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.metadata=Path(cls.temp.name)/'fixture.yar';cls.metadata.write_text(META)
  cls.rules=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v27.yaml').read_text());cls.weights=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v23.yaml').read_text())
  cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)
  cls.engine=c.ChronoSiftEngine(cls.rules,cls.weights,yara_metadata_path=str(cls.metadata))
 @classmethod
 def tearDownClass(cls):logging.getLogger().setLevel(cls.level);cls.temp.cleanup()
 def run_rows(self,rows):
  out=self.engine.apply(frame(rows),apply_profiling=False)
  for _,r in out.iterrows():self.assertAlmostEqual(r.chronosift_score,min(50,sum(e['score_contribution'] for e in (r.get('chronosift_explain') or []))))
  return out
 def test_late_request_retains_file_context_without_lowering_yara_gate(self):
  r=self.run_rows([('0s',file()),('1h',request())]).iloc[-1]
  self.assertIn('webshell_created_file_context',signals(r));self.assertIn('webshell_activity',signals(r))
  self.assertNotIn('web_confirmed_webshell_access',signals(r));self.assertNotIn('referenced_file_yara_hit',signals(r))
  e=next(e for e in r.chronosift_explain if e['rule_id']=='WEBSHELL_CREATED_FILE_ACTIVITY');self.assertEqual(e['evidence']['artifact_timestamp'],START.isoformat())
  self.assertEqual(e['evidence']['file_identity'],'/var/www/html/console.php');self.assertEqual(e['score_contribution'],0)
 def test_shell_named_late_request_keeps_fifteen_point_context(self):
  # Reproduce the observed1-point fallback after the old30-minute window.
  path='/var/www/html/contact/hackable/uploads/shell.php'
  r=self.run_rows([('0s',file(path)),('40m',request('/contact/hackable/uploads/shell.php?feature=shell'))]).iloc[-1]
  self.assertNotIn('webshell_activity_recent',signals(r))
  self.assertIn('webshell_created_file_context',signals(r))
  owners=[e for e in r.chronosift_explain if e['rule_id']=='WEBSHELL_ACTIVITY']
  self.assertEqual(len(owners),1)
  self.assertEqual(owners[0]['score_contribution'],15)
  self.assertEqual(r.chronosift_score,16)
 def test_short_and_long_routes_have_one_owner(self):
  r=self.run_rows([('0s',file()),('1m',request())]).iloc[-1]
  self.assertIn('webshell_activity_recent',signals(r));self.assertIn('webshell_created_file_context',signals(r))
  owners=[e for e in r.chronosift_explain if e['rule_id']=='WEBSHELL_ACTIVITY'];self.assertEqual(len(owners),1);self.assertEqual(owners[0]['score_contribution'],15)
 def test_fixed_expiry_does_not_refresh_from_requests(self):
  out=self.run_rows([('0s',file()),('6d',request()),('7d',request()),('7d1s',request())])
  for _,r in out.iloc[1:3].iterrows():self.assertIn('webshell_created_file_context',signals(r))
  self.assertNotIn('webshell_activity',signals(out.iloc[-1]))
 def test_name_ordinary_creation_and_access_metadata_do_not_seed(self):
  for artifact in [file(hit=False),file(kind='Last Access Time'),file(kind='Content Modification Time')]:
   r=self.run_rows([('0s',artifact),('1h',request())]).iloc[-1];self.assertNotIn('webshell_activity',signals(r))
 def test_status_missing_failure_redirect_and_nonintegral_fail_closed(self):
  for status in [None,404,500,302,200.5,'bad']:
   with self.subTest(status=status):self.assertNotIn('webshell_activity',signals(self.run_rows([('0s',file()),('1h',request(status=status))]).iloc[-1]))
  for status in [200,201,204,299,200.0]:self.assertIn('webshell_activity',signals(self.run_rows([('0s',file()),('1h',request(status=status))]).iloc[-1]))
 def test_path_and_case_boundaries(self):
  for target in ['/other.php','/Console.php']:
   r=self.run_rows([('0s',file()),('0s',file('/var/www/html'+target,hit=False)),('1h',request(target))]).iloc[-1];self.assertNotIn('webshell_activity',signals(r))
 def test_ambiguous_document_root_mapping_fails_closed(self):
  r=self.run_rows([('0s',file()),('0s',file('/srv/www/console.php')),('1h',request())]).iloc[-1];self.assertNotIn('webshell_activity',signals(r))
 def test_deletion_invalidates_and_later_qualified_creation_reseeds(self):
  out=self.run_rows([('0s',file()),('1h',request()),('2h',file(kind='Deletion Time',hit=False)),('3h',request()),('4h',file()),('5h',request())])
  self.assertIn('webshell_activity',signals(out.iloc[1]));self.assertIn('evidence_web_file_deleted',signals(out.iloc[2]));self.assertNotIn('webshell_activity',signals(out.iloc[3]));self.assertIn('webshell_activity',signals(out.iloc[-1]))
 def test_same_timestamp_deletion_fails_closed(self):
  r=self.run_rows([('0s',file()),('1h',file(kind='Deletion Time',hit=False)),('1h',request())]).iloc[-1];self.assertNotIn('webshell_activity',signals(r))
 def test_other_file_deletion_does_not_reset(self):
  r=self.run_rows([('0s',file()),('1h',file('/var/www/html/other.php',kind='Deletion Time',hit=False)),('2h',request())]).iloc[-1];self.assertIn('webshell_activity',signals(r))
 def test_preinstalled_classified_source_code_does_not_require_upload(self):
  # The deliberately installed file still contains web-shell capability.
  # Classification and matching activity, not malicious installation intent,
  # determine eligibility. An ordinary script without that category stays clear.
  for path in ['/var/www/html/source/handler.php','/var/www/html/library.php']:
   target=path.removeprefix('/var/www/html')
   r=self.run_rows([('0s',file(path)),('1d',request(target))]).iloc[-1]
   self.assertIn('webshell_activity',signals(r))
   self.assertNotIn('web_confirmed_webshell_access',signals(r))
   self.assertEqual(self.rules['detector_policy']['detectors']['webshell_created_file_activity']['evidence_type'],'contextual')
   r=self.run_rows([('0s',file(path,hit=False)),('1d',request(target))]).iloc[-1]
   self.assertNotIn('webshell_activity',signals(r))
 def test_short_window_also_respects_deletion_and_case(self):
  out=self.run_rows([('0s',file()),('1m',file(kind='Deletion Time',hit=False)),('2m',request())]);self.assertNotIn('webshell_activity',signals(out.iloc[-1]))
  r=self.run_rows([('0s',file()),('0s',file('/var/www/html/Console.php',hit=False)),('2m',request('/Console.php'))]).iloc[-1];self.assertNotIn('webshell_activity',signals(r))
 def test_generic_controls_validate_and_join_io(self):
  p=self.engine.detector_policy.definition('webshell_created_file_activity');self.assertIn('chronosift_web_status_code',c._detector_definition_required_fields(p))
  for edit,regex in [(lambda d:d['key'].update(case_sensitive='true'),'case_sensitive'),(lambda d:d.update(reset_signals=['unknown_reset']),'known producer'),(lambda d:d['target']['where']['integral_range'].update(minimum=True),'integer'),(lambda d:d['target']['where']['integral_range'].update(maximum_exclusive=200),'below')]:
   doc=deepcopy(self.rules);edit(doc['detector_policy']['detectors']['webshell_created_file_activity'])
   with self.assertRaisesRegex(ValueError,regex):c.ChronoSiftEngine(doc,self.weights,yara_metadata_path=str(self.metadata))
 def test_compact_candidates_include_reset_only_row(self):
  defs=self.engine.detector_policy.definitions(stage='temporal',enabled_only=True)
  needed={n for d in defs for n in (*getattr(d.payload,'source_signals',()),*getattr(d.payload,'target_signals',()),*getattr(d.payload,'reset_signals',()))}
  self.assertIn('evidence_web_file_deleted',needed)
  df=frame([('0s',file())]);self.assertTrue(self.engine._temporal_candidate_base_mask(df,{0:{'evidence_web_file_deleted':1}}).iloc[0])
 def test_public_partitioned_compact_and_eager_agree_at_month_boundary(self):
  rows=[('0s',file()),('40m',request()),('50m',file(kind='Deletion Time',hit=False)),('60m',request())];df=frame(rows)
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);raw=root/'raw';raw.mkdir();con=duckdb.connect();con.execute("SET TimeZone='UTC'");con.register('fixture',df.reset_index());con.execute("COPY (SELECT *,year(datetime) AS year,month(datetime) AS month FROM fixture) TO ? (FORMAT PARQUET,PARTITION_BY(year,month))",[str(raw)])
   expected=self.run_rows(rows).set_index('chronosift_row_id').chronosift_score.to_dict()
   for mode in ['sidecar','full']:
    output=root/mode;self.engine.process_parquet_dataset_partitioned(str(raw),str(output),output_mode=mode,profile_manifest={'validation':{'accepted':False}})
    got=dict(con.execute('SELECT chronosift_row_id,chronosift_score FROM read_parquet(?,union_by_name=true)',[str(output/'**/*.parquet')]).fetchall());self.assertEqual(got,expected)

if __name__=='__main__':unittest.main()
