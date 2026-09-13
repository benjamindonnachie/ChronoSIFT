"""Native identity, cached manifests, month boundaries and disabled policy."""
from dataclasses import replace
import json
import logging
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import yaml
import chronoSIFT_v2_31 as c
import av_behaviour as av
from configure_web_roots import configure_web_roots
from tests.test_v231_av_behaviour import H, J, RULES, WEIGHTS, credential_tree, write_source, frame
from tests.test_v231_behaviour_policy import file, http


class NativeAVBehaviourTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)
        self.addCleanup(logging.getLogger().setLevel,self.level)
        self.metadata=self.root/'fixture.yar';self.metadata.write_text('rule TEST_UNUSED { condition: false }\n')
        self.csv=write_source(self.root/'enrichment',tree=credential_tree())
        rules=configure_web_roots(yaml.safe_load(RULES.read_text()),['/srv/site','/srv/other'])
        self.rules=self.root/'rules.yaml';self.rules.write_text(yaml.safe_dump(rules,sort_keys=False))
        self.engine=c.ChronoSiftEngine.from_yaml(self.rules,WEIGHTS,yara_metadata_path=str(self.metadata))
        self.engine.profiling_policy=replace(self.engine.profiling_policy,enabled=False)
        self.data=frame([file('/srv/site/Utility.exe',sha256_hash=H),
                         file('/srv/site/NoProfile.exe',sha256_hash=J),
                         http('/Utility.exe','GET',200),http('/utility.exe','GET',200)])
        self.data.index=pd.DatetimeIndex(['2024-01-31T23:30:00Z']*2+['2024-02-01T00:30:00Z']*2,name='datetime')
        self.input=self.root/'input';c.write_time_partitioned_parquet(self.data,str(self.input),normalise=False)

    def manifest(self):
        policy=self.engine.detector_policy
        return c.build_global_referenced_file_hit_manifest(str(self.input),av_csv_path=str(self.csv),
            clamav_classifier_policy=policy.clamav_classification,yara_classifier_policy=policy.yara_classification,
            referenced_file_policy=policy.referenced_file_correlation,yara_metadata_path=str(self.metadata),yara_metadata_index={})

    def propagate(self,manifest,row):
        row['chronosift_web_is_event']=True
        signals,explain={},{}
        self.engine._apply_referenced_file_hit_signals_sparse(frame([row]),signals,explain,manifest)
        return signals.get(0,{}),explain.get(0,[])

    def test_manifest_roundtrip_exact_path_and_case(self):
        manifest=self.manifest();destination=self.root/'cache.json'
        self.assertEqual(manifest['av_behaviour']['paths']['/srv/site/Utility.exe'],[H])
        self.assertNotIn(J,manifest['av_behaviour']['profiles'])
        c.save_file_hit_manifest(manifest,str(destination));loaded=c.load_file_hit_manifest(str(destination))
        self.assertEqual(manifest['av_behaviour'],loaded['av_behaviour'])
        positive,explain=self.propagate(loaded,http('/Utility.exe','GET',200))
        negative,_=self.propagate(loaded,http('/utility.exe','GET',200))
        self.assertEqual(positive['av_behaviour_credential_access'],0.75)
        self.assertNotIn('av_behaviour_credential_access',negative)
        record=next(x for x in explain if x['rule_id']=='AV_BEHAVIOUR_CREDENTIAL_ACCESS')
        self.assertEqual(record['confidence'],'medium')
        self.assertEqual(record['evidence']['capability_confidence'],'high')

    def test_exact_upload_hash(self):
        manifest=self.manifest();row=http('/receive','POST',200)
        policy=self.engine.detector_policy.referenced_file_correlation
        row[policy.upload_hashes_field]=H
        row[policy.upload_names_field]='NoProfile.exe'
        signals,explain=self.propagate(manifest,row)
        self.assertEqual(signals['av_behaviour_credential_access'],1)
        self.assertEqual(next(x for x in explain if x['rule_id']=='AV_BEHAVIOUR_CREDENTIAL_ACCESS')['evidence']['match_scope'],'upload_hash')

    def test_exact_execution_reference_and_no_basename_profile(self):
        manifest=self.manifest()
        for message,expected in [('/srv/site/Utility.exe',True),('./Utility.exe',False),('/srv/site/utility.exe',False)]:
            signals,_=self.propagate(manifest,dict(parser='example:execution',filename='/logs/test',message=message))
            self.assertEqual(bool(signals.get('av_behaviour_credential_access')),expected)

    def test_cached_profile_rejects_policy_and_hash_corruption(self):
        manifest=self.manifest();payload=manifest['av_behaviour']
        payload['profiles'][H]['sha256']=J
        with self.assertRaisesRegex(ValueError,'hash mismatch'):
            self.propagate(manifest,http('/Utility.exe','GET',200))

    def test_disabled_behaviour_preserves_base(self):
        raw=yaml.safe_load(self.rules.read_text())
        raw['detector_policy']['detectors']['clamav_classification']['behaviour']['enabled']=False
        self.rules.write_text(yaml.safe_dump(raw,sort_keys=False))
        engine=c.ChronoSiftEngine.from_yaml(self.rules,WEIGHTS,yara_metadata_path=str(self.metadata))
        data=frame([dict(parser='filestat',sha256_hash=H,filename='/evidence/renamed.bin',timestamp_desc='Last Access Time')])
        out=engine.apply_atomic(data,apply_profiling=False,av_csv_path=str(self.csv))
        self.assertEqual(list(out.chronosift_score),[32])
        self.assertEqual(engine._av_behaviour_catalog,{})

    def test_disabled_classifier_does_not_read_or_emit_behaviour(self):
        raw=yaml.safe_load(self.rules.read_text())
        raw['detector_policy']['detectors']['clamav_classification']['enabled']=False
        self.rules.write_text(yaml.safe_dump(raw,sort_keys=False))
        engine=c.ChronoSiftEngine.from_yaml(self.rules,WEIGHTS,yara_metadata_path=str(self.metadata))
        data=frame([dict(parser='filestat',sha256_hash=H,filename='/evidence/renamed.bin',timestamp_desc='Last Access Time')])
        out=engine.apply_atomic(data,apply_profiling=False,av_csv_path=str(self.csv))
        self.assertFalse(any(k.startswith('av_behaviour_') for k in out.attrs['chronosift_sparse']['signal_map'].get(0,{})))

    def test_native_two_month_compact_and_eager_parity(self):
        outputs=[];cache=self.root/'file-hits.json'
        c.save_file_hit_manifest({'schema_version':8},str(cache))
        original=dict(zip(self.data.chronosift_row_id,self.data.index.as_unit('ns').astype('int64')))
        for compact in (False,True):
            engine=c.ChronoSiftEngine.from_yaml(self.rules,WEIGHTS,yara_metadata_path=str(self.metadata))
            engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
            engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
            target=self.root/str(compact)
            reports=engine.process_parquet_dataset_partitioned(str(self.input),str(target),output_mode='sidecar',
                materialise_event_columns=True,av_csv_path=str(self.csv),file_hit_manifest_path=str(cache))
            self.assertEqual(sum(x['rows_written'] for x in reports),4)
            out=c.load_plaso_parquet_dataset(str(target)).sort_values('chronosift_row_id')
            self.assertEqual(list(out.chronosift_row_id),list(original))
            self.assertFalse(any(x.startswith('vt_') for x in out.columns))
            for ts,row in out.iterrows():
                self.assertEqual(ts.value,original[int(row.chronosift_row_id)])
                raw=row.get('chronosift_explain')
                explanations=[] if raw is None or raw is pd.NA else [json.loads(x) if isinstance(x,str) else x for x in raw]
                self.assertAlmostEqual(min(50,sum(x.get('score_contribution',0) for x in explanations)),row.chronosift_score)
            self.assertEqual(out.iloc[0].chronosift_signals['av_behaviour_credential_access'],1)
            self.assertEqual(out.iloc[2].chronosift_signals['av_behaviour_credential_access'],0.75)
            bad=out.iloc[3].chronosift_signals
            self.assertTrue(bad is None or bad is pd.NA or not bad.get('av_behaviour_credential_access'))
            for field,empty in [('chronosift_signals',dict),('chronosift_explain',list)]:
                out[field]=out[field].map(lambda x:empty() if x is None or x is pd.NA else x)
            outputs.append(out)
        pd.testing.assert_frame_equal(outputs[0],outputs[1],check_dtype=False,check_exact=True)
        manifest=c.load_file_hit_manifest(str(cache))
        self.assertEqual(manifest['schema_version'],c.REFERENCED_FILE_HIT_MANIFEST_SCHEMA_VERSION)
        self.assertTrue(manifest['av_behaviour']['profiles'])


if __name__=='__main__':unittest.main()
