"""Normal runner: explicit site roots, strict AV resources and native month carry."""
import csv
import hashlib
import json
import logging
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import duckdb
import pandas as pd
import yaml
import chronoSIFT_v2_31 as c
import run_chronosift_sidecar_cli as cli
from tests.test_v231_av_behaviour import H, credential_tree, write_source

ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'rules/rules_evidence_calibrated_v27.yaml';WEIGHTS=ROOT/'rules/weights_evidence_calibrated_v23.yaml'
DOCROOT='/www/html/wordpress'
FILE=DOCROOT+'/wp-content/tools/Utility.php';URL='/wp-content/tools/Utility.php'

class AVRuntimeConfigurationTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR);self.addCleanup(logging.getLogger().setLevel,level)
  self.metadata=self.root/'fixture.yar';self.metadata.write_text('rule TEST_UNUSED {\nmeta:\n score = 75\n quality = 80\ncondition:\n false\n}\n')
  self.csv=write_source(self.root/'enrichment',tree=credential_tree())
  with self.csv.open(newline='') as f:reader=csv.DictReader(f);fields=reader.fieldnames;rows=list(reader)
  for row in rows:row['av_signature']='Php.Trojan.C99Shell-2'
  with self.csv.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
 def engine(self,roots=None,strict=True):
  return c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata),web_document_roots=roots,require_av_behaviour_context=strict)
 def records(self,urls=(URL,)):
  rows=[dict(parser='filestat',filename=FILE,sha256_hash=H,timestamp_desc='Creation Time',file_entry_type='file')]
  rows.extend(dict(parser='text/apache_access',http_request=f'GET {url} HTTP/1.1',http_response_code=200,ip_address='203.0.113.9') for url in urls)
  return pd.DataFrame([dict(chronosift_row_id=900+i,hostname='fixture',**row) for i,row in enumerate(rows)],index=pd.DatetimeIndex(['2024-01-31T23:30:00Z']+['2024-02-01T00:30:00Z']*len(urls),name='datetime'))
 def apply_native_context(self,engine,data):
  source=Path(tempfile.mkdtemp(dir=self.root));c.write_time_partitioned_parquet(data,str(source),normalise=False)
  policy=engine.detector_policy
  manifest=c.build_global_referenced_file_hit_manifest(str(source),av_csv_path=str(self.csv),clamav_classifier_policy=policy.clamav_classification,yara_classifier_policy=policy.yara_classification,referenced_file_policy=policy.referenced_file_correlation,yara_metadata_path=str(self.metadata),yara_metadata_index=engine.yara_metadata_index)
  return engine.apply(data,apply_profiling=False,av_csv_path=str(self.csv),file_hit_manifest=manifest)
 def test_root_configuration_recovers_renamed_exact_file_without_weight_changes(self):
  before=hashlib.sha256(RULES.read_bytes()).hexdigest();control=self.engine();fixed=self.engine([DOCROOT])
  plain=self.apply_native_context(control,self.records());out=self.apply_native_context(fixed,self.records((URL,URL.replace('Utility','utility'),'/unrelated/c99.php')))
  self.assertNotIn('referenced_file_av_hit',plain.iloc[1].chronosift_signals)
  self.assertIn('av_webshell',out.iloc[0].chronosift_signals)
  self.assertEqual(out.iloc[1].chronosift_signals['referenced_file_av_hit'],.5)
  self.assertIn('av_behaviour_credential_access',out.iloc[1].chronosift_signals)
  self.assertIn('web_confirmed_webshell_access',out.iloc[1].chronosift_signals)
  for _,row in out.iloc[2:].iterrows():self.assertNotIn('referenced_file_av_hit',row.chronosift_signals or {})
  self.assertEqual(control.weights,fixed.weights);self.assertEqual(before,hashlib.sha256(RULES.read_bytes()).hexdigest())
 def test_ambiguous_document_roots_remain_unresolved(self):
  data=self.records();other=data.iloc[[0]].copy();other['filename']='/srv/second/wp-content/tools/Utility.php';other['chronosift_row_id']=950
  out=self.apply_native_context(self.engine([DOCROOT,'/srv/second']),pd.concat([data.iloc[[0]],other,data.iloc[[1]]]))
  self.assertNotIn('referenced_file_av_hit',out.iloc[-1].chronosift_signals or {})
 def test_invalid_configuration_fails_before_runtime(self):
  for roots in ([DOCROOT+'/../other'],['/'],DOCROOT):
   with self.assertRaises(ValueError):self.engine(roots)
  with self.assertRaisesRegex(ValueError,'boolean'):c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata),require_av_behaviour_context='true')
 def test_cli_rejects_legacy_av_before_evidence_or_output(self):
  legacy=self.root/'legacy.csv';legacy.write_text('sha256,av_hit,av_signature,av_product\n'+H+',true,Php.Trojan.C99Shell-2,ClamAV\n');output=self.root/'output'/'sidecar'
  args=['runner','missing-input',str(output),'--yara-metadata-path',str(self.metadata),'--av-csv-path',str(legacy),'--require-av-behaviour-context']
  with patch.object(sys,'argv',args),self.assertRaisesRegex(ValueError,'vt_behaviour_context'):cli.main()
  self.assertFalse(output.parent.exists())
 def test_cli_verifies_raw_reports_before_evidence_or_output(self):
  context=json.loads(next(row for row in csv.DictReader(self.csv.open()) if row['sha256']==H)['vt_behaviour_context']);report=self.csv.parent/context['endpoints'][0]['report_file'];report.write_text('{}')
  output=self.root/'output'/'sidecar';args=['runner','missing-input',str(output),'--yara-metadata-path',str(self.metadata),'--av-csv-path',str(self.csv),'--require-av-behaviour-context']
  with patch.object(sys,'argv',args),self.assertRaises(ValueError):cli.main()
  self.assertFalse(output.parent.exists())
 def test_public_runner_compact_eager_month_boundary_and_effective_policy(self):
  source=self.root/'raw';c.write_time_partitioned_parquet(self.records(),str(source),normalise=False);results=[]
  for mode in ['sidecar','full']:
   destination=self.root/mode/'sidecar';effective=self.root/mode/'effective.yaml';args=['runner',str(source),str(destination),'--output-mode',mode,'--web-document-root',DOCROOT,'--require-av-behaviour-context','--av-csv-path',str(self.csv),'--yara-metadata-path',str(self.metadata),'--effective-rules-yaml',str(effective),'--log-level','ERROR']
   with patch.object(sys,'argv',args):self.assertEqual(cli.main(),0)
   policy=yaml.safe_load(effective.read_text());self.assertTrue(policy['detector_policy']['detectors']['clamav_classification']['behaviour']['require_enriched_csv']);self.assertIn(DOCROOT,policy['detector_policy']['detectors']['referenced_file_correlation']['matching']['web_document_roots'])
   con=duckdb.connect();con.execute("SET TimeZone='UTC'");rows=con.execute('SELECT chronosift_row_id,datetime,chronosift_score,chronosift_signals FROM read_parquet(?,union_by_name=true) ORDER BY chronosift_row_id',[str(destination/'**/*.parquet')]).fetchall();con.close();self.assertEqual([r[0] for r in rows],[900,901]);self.assertEqual(rows[1][3]['referenced_file_av_hit'],.5);self.assertIn('av_behaviour_credential_access',rows[1][3]);results.append(rows)
  self.assertEqual(results[0],results[1])

if __name__=='__main__':unittest.main()
