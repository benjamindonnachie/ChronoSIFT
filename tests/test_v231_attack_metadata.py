"""F02 attribution is producer-qualified, offline, explicit and scoring-neutral."""
import copy
from dataclasses import replace
import hashlib
import json
import logging
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

import attack_metadata as attack
import av_behaviour as av
import chronoSIFT_v2_31 as c
from benchmarks.build_attack_metadata_policy import build, matrix
from configure_web_roots import configure_web_roots
from tests.test_v231_av_behaviour import H, WEIGHTS, credential_tree, write_source, frame
from tests.test_v231_behaviour_policy import file, http, sudo, ftp

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT/'rules/rules_evidence_calibrated_v24.yaml'


def strip_annotations(value):
    result=copy.deepcopy(value)
    result.pop('attack_metadata',None)
    for _,raw,*_ in attack.iter_producers(result):
        for key in attack.ANNOTATION_KEYS:raw.pop(key,None)
    return result


def explanations(value):
    if value is None or value is pd.NA:
        return []
    return [json.loads(x) if isinstance(x,str) else x for x in value]


class AttackMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=yaml.safe_load(RULES.read_text())
        cls.registry=attack.AttackMetadata(cls.doc)
        cls.temp=tempfile.TemporaryDirectory()
        cls.metadata=Path(cls.temp.name)/'fixture.yar'
        cls.metadata.write_text('rule TEST_UNUSED { condition: false }\n')
        cls.level=logging.getLogger().level;logging.getLogger().setLevel(logging.ERROR)
        cls.engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(cls.metadata))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup();logging.getLogger().setLevel(cls.level)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def producer(self, rule_id, doc=None):
        return next((ref,raw) for ref,raw,*_ in attack.iter_producers(doc or self.doc)
                    if raw.get('rule_id',raw.get('id'))==rule_id)

    def test_policy_is_scoring_identical(self):
        previous=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v23.yaml').read_text())
        self.assertEqual(strip_annotations(self.doc),previous)
        self.assertEqual(hashlib.sha256(WEIGHTS.read_bytes()).hexdigest(),
                         'd0c910d7a030c89a5f8745b6a6eb91a99071bcfe1ba125636d907b65123a49b8')

    def test_review_and_matrix_are_deterministic(self):
        self.assertEqual(build(ROOT),self.doc)
        self.assertEqual(matrix(self.doc),(ROOT/'docs/ATTACK_MATRIX_V24.md').read_text())
        self.assertEqual(len(self.registry.entries),285)
        self.assertIn('not validated detection coverage',matrix(self.doc))

    def test_legacy_policy_remains_unannotated(self):
        legacy=attack.AttackMetadata(strip_annotations(self.doc))
        self.assertFalse(legacy.enabled)
        self.assertEqual(legacy.run_metadata(),{})
        value={'rule_id':'example','confidence':'high'};legacy.annotate(value)
        self.assertEqual(value,{'rule_id':'example','confidence':'high'})

    def test_bad_annotation_shapes_rejected(self):
        base=dict(attack_ids=['T1059'],attack_basis='observed_behaviour',attack_note='command')
        for update in [dict(attack_ids='T1059'),dict(attack_ids=['T999']),
                       dict(attack_ids=['T1059','T1059']),dict(attack_basis=[]),
                       dict(attack_source=[]),dict(attack_source='guess'),dict(attack_note=''),
                       dict(attack_ids=[]),dict(attack_basis='unmapped'),
                       dict(attack_source='matched_external')]:
            with self.subTest(update=update),self.assertRaises(ValueError):
                attack.parse_annotation({**base,**update},'test')
        for key in ('attack_ids','attack_basis','attack_note'):
            bad=dict(base);bad.pop(key)
            with self.assertRaises(ValueError):attack.parse_annotation(bad,'test')

    def test_missing_catalogue_or_missing_review_fails(self):
        bad=copy.deepcopy(self.doc);bad.pop('attack_metadata')
        with self.assertRaisesRegex(ValueError,'require an attack_metadata'):
            attack.AttackMetadata(bad)
        bad=copy.deepcopy(self.doc)
        raw=bad['rules'][0]
        for key in attack.ANNOTATION_KEYS:raw.pop(key,None)
        with self.assertRaisesRegex(ValueError,'explicitly unmapped'):
            attack.AttackMetadata(bad)

    def test_checksum_and_unknown_policy_id_fail(self):
        bad=copy.deepcopy(self.doc);bad['attack_metadata']['catalogue_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'checksum mismatch'):attack.AttackMetadata(bad)
        bad=copy.deepcopy(self.doc);_,raw=self.producer('WINDOWS_PSEXEC_EXECUTION',bad)
        raw['attack_ids']=['T9999']
        with self.assertRaisesRegex(ValueError,'unknown Enterprise'):attack.AttackMetadata(bad)

    def test_retired_policy_requires_explicit_used_exception(self):
        bad=copy.deepcopy(self.doc);_,raw=self.producer('WINDOWS_PSEXEC_EXECUTION',bad)
        raw['attack_ids']=['T1562.001']
        with self.assertRaisesRegex(ValueError,'retired ID'):attack.AttackMetadata(bad)
        bad['attack_metadata']['legacy_ids']={'T1562.001':'Historical comparison, not current canonical ID.'}
        self.assertTrue(attack.AttackMetadata(bad).enabled)
        raw['attack_ids']=['T1059']
        with self.assertRaisesRegex(ValueError,'unused legacy'):attack.AttackMetadata(bad)

    def test_producer_reference_not_signal_alias(self):
        ref,raw=self.producer('WINDOWS_PSEXEC_EXECUTION')
        item=dict(rule_id=raw['rule_id'],attack_ref=ref,signal='unrelated_alias',confidence='medium')
        self.registry.annotate(item)
        self.assertEqual(item['attack_ids'],raw['attack_ids'])
        self.assertEqual(item['confidence'],'medium')
        item['rule_id']='SOME_OTHER_PRODUCER'
        with self.assertRaisesRegex(ValueError,'does not match'):self.registry.annotate(item)
        item['attack_ref']='missing'
        with self.assertRaisesRegex(ValueError,'Unknown ATT'):self.registry.annotate(item)

    def test_external_ids_keep_raw_provenance_and_diagnostics(self):
        ref,raw=self.producer('AV_BEHAVIOUR_CREDENTIAL_ACCESS')
        evidence=dict(attack_ids=['T1555.003','T1562.001','T9999'],source={'report_sha256':'a'*64})
        item=dict(rule_id=raw['rule_id'],attack_ref=ref,evidence=evidence,confidence='high',score_contribution=8)
        before=copy.deepcopy(evidence);self.registry.annotate(item)
        self.assertEqual(item['attack_ids'],['T1555.003'])
        self.assertEqual(item['attack_reported_ids'],sorted(before['attack_ids']))
        self.assertEqual(len(item['attack_diagnostics']),2)
        self.assertEqual(item['attack_basis'],'artefact_capability')
        self.assertEqual(item['evidence'],before)
        self.assertEqual((item['confidence'],item['score_contribution']),('high',8))
        item.pop('evidence')
        with self.assertRaisesRegex(ValueError,'matched profile evidence'):self.registry.annotate(item)

    def test_unmapped_luhn_still_has_separate_pci_rationale(self):
        for name in ('LUHN_SENSITIVE_DATA_HIT','REFERENCED_FILE_LUHN_HIT','WINDOWS_SENSITIVE_CONTENT_ACCESS'):
            ref,raw=self.producer(name)
            self.assertEqual(raw['attack_ids'],[])
            self.assertEqual(attack.parse_annotation(raw,ref),'')
            self.assertIn('PCI DSS',raw['attack_note'])
            self.assertIn('3.5.1',raw['attack_note'])

    def test_run_metadata_written_once_and_includes_external_names(self):
        self.registry.write_run_metadata(self.root)
        path=self.root/'_chronosift_attack_metadata.json';first=path.read_bytes()
        self.registry.write_run_metadata(self.root);self.assertEqual(first,path.read_bytes())
        data=json.loads(first)
        self.assertIn('T1555.003',data['techniques'])
        self.assertIn('mapping_sha256',data)
        path.write_text('{}')
        with self.assertRaisesRegex(ValueError,'Conflicting'):self.registry.write_run_metadata(self.root)

    def test_typed_parsers_consume_all_mapped_producers(self):
        self.registry.validate_typed_refs(self.engine.detector_policy,self.engine.rules,self.engine.temporal_rules)
        with self.assertRaisesRegex(ValueError,'producer/parser mismatch'):
            self.registry.validate_typed_refs(self.engine.rules)

    def test_actual_av_matching_not_category_union_and_arrow_roundtrip(self):
        csv=write_source(self.root/'enrichment',tree=credential_tree())
        engine=c.ChronoSiftEngine.from_yaml(RULES,WEIGHTS,yara_metadata_path=str(self.metadata))
        engine._av_behaviour_catalog=av.load_catalog(csv,engine.detector_policy.clamav_classification.behaviour)
        signals,explain={},{}
        data=frame([dict(filename='/evidence/renamed.bin',sha256_hash=H,av_hit=True,av_signature='Win.Malware.Example-1-0')])
        engine._inject_av_signal_sparse(data,signals,explain)
        engine._materialise_sparse_event_columns(data,signals,explain)
        item=next(x for x in explanations(data.iloc[0].chronosift_explain) if x['rule_id']=='AV_BEHAVIOUR_CREDENTIAL_ACCESS')
        self.assertEqual(item['attack_ids'],['T1555.003'])
        self.assertEqual(item['attack_basis'],'artefact_capability')
        self.assertEqual(engine._score_signals(signals[0]),40)
        path=self.root/'nested.parquet';pq.write_table(pa.Table.from_pylist([item]),path)
        self.assertEqual(pq.read_table(path).to_pylist(),[item])
        self.assertNotIn('attack_metadata',data.attrs)

    def test_native_two_month_and_compact_history_score_parity(self):
        csv=write_source(self.root/'enrichment',tree=credential_tree())
        data=frame([file('/srv/site/Utility.exe',sha256_hash=H),http('/Utility.exe','GET',200),
                    file('/tmp/archive.tgz',luhn_hit=True),ftp(direction='o',outcome='i'),sudo()])
        data.index=pd.DatetimeIndex(['2024-01-31T23:30:00.000000123Z']+
                                  ['2024-02-01T00:30:00.000000123Z']*4,name='datetime')
        source=self.root/'input';c.write_time_partitioned_parquet(data,str(source),normalise=False)
        outputs=[];mapped=[]
        for version,compact in [(23,True),(24,True),(24,False)]:
            policy=configure_web_roots(yaml.safe_load((ROOT/f'rules/rules_evidence_calibrated_v{version}.yaml').read_text()),['/srv/site'])
            rules=self.root/f'policy-{version}-{compact}.yaml';rules.write_text(yaml.safe_dump(policy,sort_keys=False))
            engine=c.ChronoSiftEngine.from_yaml(rules,WEIGHTS,yara_metadata_path=str(self.metadata))
            engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
            engine.partition_execution_policy={**engine.partition_execution_policy,'compact_history':compact}
            target=self.root/f'out-{version}-{compact}'
            reports=engine.process_parquet_dataset_partitioned(str(source),str(target),output_mode='sidecar',
                materialise_event_columns=True,av_csv_path=str(csv))
            self.assertEqual(sum(x['rows_written'] for x in reports),len(data))
            self.assertEqual((target/'_chronosift_attack_metadata.json').exists(),version==24)
            out=c.load_plaso_parquet_dataset(str(target)).sort_values('chronosift_row_id')
            core=[];mapped_count=0
            for ts,row in out.iterrows():
                ex=explanations(row.get('chronosift_explain'))
                mapped_count+=sum('attack_ref' in x for x in ex)
                core.append((ts.isoformat(),int(row.chronosift_row_id),row.chronosift_score,
                             row.chronosift_signals,[(x['rule_id'],x.get('confidence'),x.get('score_contribution'),x.get('signals')) for x in ex]))
            outputs.append(core);mapped.append(mapped_count)
        self.assertEqual(outputs[0],outputs[1]);self.assertEqual(outputs[1],outputs[2])
        self.assertEqual(mapped[0],0);self.assertGreater(mapped[1],0);self.assertEqual(mapped[1],mapped[2])


if __name__=='__main__':unittest.main()
