"""Published v1 interface must match actual parsing, not just a handwritten list."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

import chronoSIFT_v2_31 as c
from benchmarks import build_detector_contract as contract
from run_chronosift_sidecar_cli import build_arg_parser

ROOT=Path(__file__).resolve().parents[1]


class DetectorContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.published=json.loads((ROOT/'docs/detector-policy-v1.json').read_text())
        cls.rules=c._load_unique_yaml_mapping(ROOT/'rules'/cls.published['example_policy'],'rules')
        args=build_arg_parser().parse_args(['input','output'])
        cls.weights=c._load_unique_yaml_mapping(Path(args.weights_yaml),'weights')

    def parse(self,rules):return c._parse_detector_policy(rules,self.weights)

    def test_published_json_and_markdown_are_exact(self):
        for path,expected in contract.outputs().items():self.assertEqual(path.read_text(),expected,str(path))
        self.assertEqual(self.published['kind'],'published_interface_not_runtime_policy')

    def test_current_counts_and_four_extension_families(self):
        self.assertEqual(len(self.published['required_detectors']),35)
        self.assertEqual(len(self.published['example_additional_detectors']),10)
        self.assertEqual(len(self.parse(self.rules).detectors),45)
        self.assertEqual(self.published['additional_executor_families'],{
            'signal_gate':{'stages':['atomic','contextual']},
            'signal_sequence':{'stages':['temporal']},
            'signal_projection':{'stages':['contextual','temporal']},
            'qualified_artifact_command':{'stages':['contextual']}})

    def test_every_required_id_is_really_required(self):
        for ident in self.published['required_detectors']:
            with self.subTest(ident=ident):
                rules=deepcopy(self.rules);rules['detector_policy']['detectors'].pop(ident)
                with self.assertRaisesRegex(ValueError,'missing required key.*'+ident):self.parse(rules)

    def test_every_required_id_cannot_be_renamed(self):
        for ident in self.published['required_detectors']:
            with self.subTest(ident=ident):
                rules=deepcopy(self.rules);defs=rules['detector_policy']['detectors']
                defs['renamed_'+ident]=defs.pop(ident)
                with self.assertRaisesRegex(ValueError,'missing required key.*'+ident):self.parse(rules)

    def test_every_required_binding_rejects_different_executor(self):
        for ident,item in self.published['required_detectors'].items():
            with self.subTest(ident=ident):
                rules=deepcopy(self.rules)
                rules['detector_policy']['detectors'][ident]['executor']='signal_sequence' if item['executor']!='signal_sequence' else 'signal_gate'
                with self.assertRaisesRegex(ValueError,ident+'.executor'):self.parse(rules)

    def test_every_required_binding_rejects_different_stage(self):
        for ident,item in self.published['required_detectors'].items():
            with self.subTest(ident=ident):
                rules=deepcopy(self.rules)
                rules['detector_policy']['detectors'][ident]['stage']='atomic' if item['stage']!='atomic' else 'temporal'
                with self.assertRaisesRegex(ValueError,ident+'.stage'):self.parse(rules)

    def test_disable_retains_schema_and_suppresses_definition(self):
        rules=deepcopy(self.rules);raw=rules['detector_policy']['detectors']['mft_timestomping'];raw['enabled']=False
        parsed=self.parse(rules)
        self.assertFalse(parsed.mft_timestomping.enabled)
        self.assertNotIn('mft_timestomping',{d.detector_id for d in parsed.definitions(enabled_only=True)})
        raw.pop('executor')
        with self.assertRaisesRegex(ValueError,'mft_timestomping.*missing required'):self.parse(rules)

    def test_all_current_optional_ids_can_be_renamed_without_engine_branch(self):
        observed=set()
        for ident,item in self.published['example_additional_detectors'].items():
            with self.subTest(ident=ident):
                rules=deepcopy(self.rules);defs=rules['detector_policy']['detectors'];new='contract_example_'+ident
                defs[new]=defs.pop(ident);parsed=self.parse(rules)
                definition=parsed.definition(new)
                self.assertEqual(definition.executor,item['executor']);self.assertEqual(definition.stage,item['stage'])
                observed.add(definition.executor)
        self.assertEqual(observed,set(self.published['additional_executor_families']))

    def test_reserved_implementation_cannot_be_added_under_new_id(self):
        for ident in ('mft_timestomping','direct_attack_semantics','repeated_scheduled_execution','contextual_signal_adjustments'):
            with self.subTest(ident=ident):
                rules=deepcopy(self.rules);defs=rules['detector_policy']['detectors']
                defs['contract_reserved_copy']=deepcopy(defs[ident])
                with self.assertRaisesRegex(ValueError,'additional detectors must use'):self.parse(rules)

    def test_arbitrary_python_import_path_is_not_an_executor(self):
        rules=deepcopy(self.rules)
        rules['detector_policy']['detectors']['contract_custom']={'executor':'os.system','stage':'contextual','enabled':True}
        with self.assertRaisesRegex(ValueError,'additional detectors must use'):self.parse(rules)


if __name__=='__main__':unittest.main()
