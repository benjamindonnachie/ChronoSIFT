"""Generic AV-positive metadata, independent identities, sparse/native controls."""
import copy
import csv
import io
import json
import logging
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
import yaml
import chronoSIFT_v2_31 as c
import av_behaviour as av

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT/'rules/rules_evidence_calibrated_v23.yaml'
WEIGHTS = ROOT/'rules/weights_evidence_calibrated_v21.yaml'
H = 'A'*64
J = 'B'*64


def frame(records):
    result = pd.DataFrame(records)
    result.index = pd.DatetimeIndex(['2024-01-31T23:30:00Z']*len(records), name='datetime')
    result['chronosift_row_id'] = range(100, 100+len(records))
    return result


def credential_tree(*, severity='HIGH', duplicate=False, parent_only=False):
    tech = dict(id='T1555.003', name='Credentials from Web Browsers')
    if not parent_only:
        tech['signatures'] = [dict(description='read browser password credentials', severity=severity)]
    tactics = [dict(id='TA0006', techniques=[tech])]
    if duplicate:
        tactics.append(dict(id='TA0009', techniques=[tech]))
    return {'Example analysis': {'tactics': tactics}}


def write_source(root, *, tree=None, summary=None, duplicate=False, sha=H, positive=True):
    root.mkdir(parents=True, exist_ok=True)
    entries = []
    for endpoint, data in [('behaviour_mitre_trees', tree or {}), ('behaviour_summary', summary)]:
        name = f'{sha}.{endpoint}.json'
        raw = json.dumps({'data': data}).encode()
        (root/name).write_bytes(raw)
        entries.append(dict(hash=sha.lower(), endpoint=endpoint, status='no_summary_returned' if data is None else 'available',
                            report_file=name, report_sha256=av.digest(raw)))
    context = json.dumps(dict(schema_version=1, sha256=sha.lower(), endpoints=entries))
    fields = ['sha256', 'av_signature', 'av_hit', 'av_product', 'vt_behaviour_context']
    row = [sha, 'Win.Malware.Example-1-0', str(positive), 'ExampleAV', context]
    target = root/'av.csv'
    with target.open('w', newline='') as handle:
        writer = csv.writer(handle); writer.writerow(fields); writer.writerow(['# Test section','','','',''])
        writer.writerow(row)
        if duplicate:
            writer.writerow(row)
    return target


class AVBehaviourTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.level = logging.getLogger().level; logging.getLogger().setLevel(logging.ERROR)
        cls.shared = tempfile.TemporaryDirectory()
        cls.metadata = Path(cls.shared.name)/'fixture.yar'
        cls.metadata.write_text('rule TEST_UNUSED { condition: false }\n')
        cls.engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(cls.metadata))
        cls.policy = cls.engine.detector_policy.clamav_classification.behaviour

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup(); logging.getLogger().setLevel(cls.level)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        av._CATALOG_CACHE.clear()
        self.engine._av_behaviour_catalog = {}

    def load(self, **kwargs):
        file = write_source(self.root, **kwargs)
        self.engine._av_behaviour_catalog = av.load_catalog(file, self.policy)
        return file

    def score(self, *, sha=H, hit=True, signature='Win.Malware.Example-1-0'):
        signals, explains = {}, {}
        data = frame([dict(filename='/evidence/renamed.bin', sha256_hash=sha, av_hit=hit, av_signature=signature)])
        self.engine._inject_av_signal_sparse(data, signals, explains)
        return self.engine._score_signals(signals.get(0, {})), signals.get(0, {}), explains.get(0, [])

    def test_specific_credential_av_presence(self):
        self.load(tree=credential_tree())
        score, signals, explanations = self.score()
        self.assertEqual(score,40)
        finding = next(x for x in explanations if x['rule_id']=='AV_BEHAVIOUR_CREDENTIAL_ACCESS')
        self.assertEqual(finding['confidence'],'high')
        self.assertEqual(finding['evidence']['attack_ids'],['T1555.003'])
        self.assertNotIn('av_ransomware',signals)

    def test_generic_tags_add_small_bounded_support(self):
        self.load(summary={'tags':['DETECT_DEBUG_ENVIRONMENT','OBFUSCATED','LONG_SLEEPS']*20})
        self.assertEqual(self.score()[0],33.5)
        self.assertEqual(self.score()[1]['av_behaviour_evasion'],0.5)

    def test_missing_summary_preserves_av_only(self):
        self.load()
        self.assertEqual(self.score()[0],32)

    def test_parent_technique_alone_is_not_a_finding(self):
        self.load(tree=credential_tree(parent_only=True))
        self.assertEqual(self.score()[0],32)

    def test_capa_info_still_supports_credential_capability(self):
        self.load(tree=credential_tree(severity='INFO'))
        self.assertEqual(self.score()[0],38)

    def test_duplicate_rows_tactics_and_signatures_do_not_raise_strength(self):
        self.load(tree=credential_tree(duplicate=True),duplicate=True,
                  summary={'mitre_attack_techniques':[dict(id='T1555.003',signature_description='read browser password credentials',severity='IMPACT_SEVERITY_HIGH')]*10})
        self.assertEqual(len(self.engine._av_behaviour_catalog),1)
        self.assertEqual(self.score()[0],40)

    def test_hash_not_filename_binds_presence(self):
        self.load(tree=credential_tree())
        self.assertEqual(self.score(sha=J)[0],32)
        self.assertEqual(self.score(sha=H.lower())[0],40)
        self.assertEqual(self.score(hit=False)[0],0)

    def test_negative_catalog_rows_do_not_supply_profiles(self):
        self.load(tree=credential_tree(),positive=False)
        self.assertEqual(self.score()[0],32)

    def test_no_family_name_ransomware_shortcut(self):
        self.load(tree=credential_tree())
        score, signals, _ = self.score(signature='Win.Malware.CrazyUtility-1-0')
        self.assertEqual(score,40); self.assertNotIn('av_ransomware',signals)

    def test_sigma_requires_values_not_high_title(self):
        self.load(summary={'sigma_analysis_results':[dict(rule_title='Critical credential theft and persistence',rule_level='critical',match_context=[])]})
        self.assertEqual(self.score()[0],32)

    def test_sigma_registry_event_admitted_and_deduplicated(self):
        event={'values':{'EventType':'SetValue','TargetObject':r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Example','Details':r'C:\Users\X\AppData\Local\renamed.exe'}}
        self.load(summary={'tags':['PERSISTENCE'], 'sigma_analysis_results':[dict(rule_level='medium',match_context=[event])]*5})
        self.assertEqual(self.score()[0],37)

    def test_ordinary_registry_setting_not_persistence(self):
        self.load(summary={'sigma_analysis_results':[dict(rule_level='high',match_context=[{'values':{'EventType':'SetValue','TargetObject':r'HKCU\Software\Example\Colour','Details':'Blue'}}])]})
        self.assertEqual(self.score()[0],32)

    def test_group_cap_and_repeated_injection(self):
        tree=credential_tree()
        tree['Example analysis']['tactics'][0]['techniques'].extend([
            dict(id='T1486',signatures=[dict(description='encrypt documents and files',severity='HIGH')]),
            dict(id='T1547.001',signatures=[dict(description='modify autorun registry',severity='HIGH')])])
        self.load(tree=tree,summary={'tags':['OBFUSCATED']})
        score, signals, explains=self.score()
        self.assertEqual(score,46)
        for _ in range(3):
            av.merge_into_row(self.policy,self.engine._av_behaviour_catalog.values(),signals,explains,self.engine.weights,scope='hash')
        self.assertEqual(self.engine._score_signals(signals),46)
        self.assertEqual(len([x for x in explains if x['rule_id'].startswith('AV_BEHAVIOUR_')]),4)

    def test_csv_join_never_materialises_transport_json(self):
        file=self.load(tree=credential_tree())
        data=frame([dict(sha256_hash=H,filename='/a'),dict(sha256_hash=J,filename='/b')])
        result=self.engine._apply_hash_enrichment_csv(data,str(file))
        self.assertIs(result,data)
        self.assertFalse(any(name.startswith('vt_') for name in result.columns))
        self.assertEqual(list(result.chronosift_row_id),[100,101])
        self.assertEqual(result.index[0],result.index[1])

    def test_duplicate_row_ids_still_rejected(self):
        file=self.load()
        data=frame([dict(sha256_hash=H)]*2);data['chronosift_row_id']=1
        with self.assertRaisesRegex(ValueError,'unique'):
            self.engine._apply_hash_enrichment_csv(data,str(file))

    def test_invalid_json_and_identity_fail(self):
        file=self.load()
        file.write_text(file.read_text().replace('schema_version','bad_schema'))
        with self.assertRaisesRegex(ValueError,'schema'):
            av.load_catalog(file,self.policy)

    def test_raw_report_digest_mismatch_fails(self):
        file=write_source(self.root,tree=credential_tree())
        (self.root/f'{H}.behaviour_mitre_trees.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'digest mismatch'):
            av.load_catalog(file,self.policy)

    def test_paths_cannot_escape_catalog_root(self):
        with self.assertRaisesRegex(ValueError,'inside'):
            av._read_report(self.root,'../report.json','f'*64)

    def test_conflicting_duplicate_metadata_fails(self):
        file=write_source(self.root,duplicate=True)
        rows=list(csv.reader(io.StringIO(file.read_text())))
        context=json.loads(rows[-1][-1]);context['extra']='conflict';rows[-1][-1]=json.dumps(context)
        with file.open('w',newline='') as handle:csv.writer(handle).writerows(rows)
        with self.assertRaisesRegex(ValueError,'Conflicting'):
            av.load_catalog(file,self.policy)

    def test_content_cache_detects_same_stat_replacement(self):
        file=self.load(tree=credential_tree(severity='HIGH'))
        first=av.load_catalog(file,self.policy)
        stat=file.stat();text=file.read_text();file.write_text(text.replace('ExampleAV','ExampleXX'))
        os.utime(file,ns=(stat.st_atime_ns,stat.st_mtime_ns))
        second=av.load_catalog(file,self.policy)
        self.assertIsNot(first,second)
        self.assertNotEqual(first[H]['source']['csv_sha256'],second[H]['source']['csv_sha256'])

    def test_catalog_parsed_once_for_unchanged_input(self):
        file=self.load(tree=credential_tree())
        with patch.object(av,'_read_report',side_effect=AssertionError('reparsed')):
            self.assertIs(av.load_catalog(file,self.policy),self.engine._av_behaviour_catalog)

    def test_plain_av_and_required_enrichment_policy(self):
        file=self.root/'plain.csv';file.write_text('sha256,av_hit\n'+H+',True\n')
        self.assertEqual(av.load_catalog(file,self.policy),{})
        raw=yaml.safe_load(RULES.read_text())['detector_policy']['detectors']['clamav_classification']['behaviour']
        raw['require_enriched_csv']=True
        policy=av.parse_policy(raw,lambda x,p:c._parse_policy_emission(x,p,include_explanation=True))
        with self.assertRaisesRegex(ValueError,'missing'):
            av.load_catalog(file,policy)

    def test_invalid_policy_and_unknown_weights_fail(self):
        original=yaml.safe_load(RULES.read_text())
        for change in ['unknown','regex','confidence','weight']:
            raw=copy.deepcopy(original);weights=yaml.safe_load(WEIGHTS.read_text())
            policy=raw['detector_policy']['detectors']['clamav_classification']['behaviour']
            if change=='unknown':policy['extra']=True
            elif change=='regex':policy['rules'][0]['conditions'][-1]['pattern']='['
            elif change=='confidence':policy['confidence'][0]['strength']=float('nan')
            else:weights['weights'].pop('av_behaviour_credential_access')
            rulefile=self.root/'rules.yaml';weightfile=self.root/'weights.yaml'
            rulefile.write_text(yaml.safe_dump(raw,sort_keys=False));weightfile.write_text(yaml.safe_dump(weights,sort_keys=False))
            with self.subTest(change=change),self.assertRaises((ValueError,re.error)):
                c.ChronoSiftEngine.from_yaml(rulefile,weightfile,yara_metadata_path=str(self.metadata))

    def test_full_pipeline_accounting_and_source_reset(self):
        file=self.load(tree=credential_tree())
        data=frame([dict(parser='filestat',filename='/a',sha256_hash=H,timestamp_desc='Last Access Time')]*2)
        out=self.engine.apply_atomic(data,apply_profiling=False,av_csv_path=str(file))
        self.assertEqual(list(out.chronosift_score),[40,40])
        out=self.engine.apply_contextual(out,apply_profiling=False)
        for score,explain in zip(out.chronosift_score,out.chronosift_explain):
            self.assertAlmostEqual(sum(x.get('score_contribution',0) for x in explain),score)
        clean=frame([dict(parser='filestat',filename='/a',sha256_hash=H,av_hit=True,av_signature='Win.Malware.Example-1-0',timestamp_desc='Last Access Time')])
        clean=self.engine.apply_atomic(clean,apply_profiling=False)
        self.assertEqual(list(clean.chronosift_score),[32])


if __name__=='__main__':
    unittest.main()
