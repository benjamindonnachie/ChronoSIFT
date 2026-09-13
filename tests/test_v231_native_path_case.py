"""Native web identities: POSIX case, Windows syntax, cache and row integrity."""
from dataclasses import replace
import json
import logging
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import yaml
import chronoSIFT_v2_31 as c
from configure_web_roots import configure_web_roots
from tests.test_v231_behaviour_policy import file, http
from tests.test_v231_linux_account_context import frame

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'rules/rules_evidence_calibrated_v22.yaml'
WEIGHTS = ROOT / 'rules/weights_evidence_calibrated_v20.yaml'


class NativePathCaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.metadata = Path(cls.temp.name) / 'fixture.yar'
        cls.metadata.write_text('rule TEST_WEBSHELL_Strong {\nmeta:\n score = 75\n quality = 85\ncondition:\n false\n}\n')
        cls.engine = c.ChronoSiftEngine.from_yaml(RULES, WEIGHTS, yara_metadata_path=str(cls.metadata))
        cls.level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
        logging.getLogger().setLevel(cls.level)

    def manifest(self, paths, *, roots=('/srv/tenant', 'site/root'), hashed=False):
        hit_map = {path: {tag} for path, tag in paths}
        identities = {path: {'paths': {path}, 'hit_types': {tag},
            'av_categories': {'malware'} if tag == 'av' else set(),
            'yara_categories': {'webshell'} if tag == 'yara' else set()}
            for path, tag in paths}
        policy = self.engine.detector_policy
        return c._finalise_referenced_file_hit_manifest(
            hit_map, {}, {path for path, tag in paths if tag == 'yara'},
            replace(policy.referenced_file_correlation, document_roots=tuple(roots)), identities,
            {'F' * 64: {paths[0][0]}} if hashed else {},
            hash_source_hit_map={'F' * 64: {'av'}} if hashed else {},
            hash_source_identity_map={'F' * 64: {'hit_types': {'av'}, 'av_categories': {'malware'}}} if hashed else {},
            strong_yara_hashes=set(), strong_yara_hash_identity_map={},
            clamav_policy_digest=policy.clamav_classification.policy_digest,
            yara_policy_digest=policy.yara_classification.policy_digest,
            source_digest='case-fixture')

    def propagate(self, manifest, target, *, upload=None, sha256=None):
        row = http(target, 'POST' if upload is not None or sha256 else 'GET', 200)
        row['chronosift_web_is_event'] = True
        if upload is not None:
            row[self.engine.detector_policy.referenced_file_correlation.upload_names_field] = upload
        if sha256:
            row[self.engine.detector_policy.referenced_file_correlation.upload_hashes_field] = sha256
        signals, explanations = {}, {}
        self.engine._apply_referenced_file_hit_signals_sparse(
            frame([('0s', row)]), signals, explanations, manifest)
        return signals.get(0, {}), explanations.get(0, [])

    def test_posix_root_case_and_component_boundaries(self):
        for path, roots, expected in [
            ('/srv/tenant/Utility.php', ['/srv/tenant'], ('/Utility.php',)),
            ('/srv/Tenant/Utility.php', ['/srv/tenant'], ()),
            ('/srv/tenant-old/Utility.php', ['/srv/tenant'], ()),
            ('/mount/site/root/Utility.php', ['site/root'], ('/Utility.php',)),
            ('/mount/site/root-old/Utility.php', ['site/root'], ()),
            ('/mount/Site/root/Utility.php', ['site/root'], ()),
        ]:
            with self.subTest(path=path):
                self.assertEqual(c._web_path_aliases_for_filesystem_path(path, roots), expected)

    def test_windows_syntax_roots_are_case_insensitive(self):
        for path in ['C:/SITE/ROOT/Utility.php', r'C:\SITE\ROOT\Utility.php',
                     r'NTFS:\SITE\ROOT\Utility.php', r'\\server\share\SITE\ROOT\Utility.php',
                     r'\SITE\ROOT\Utility.php']:
            with self.subTest(path=path):
                self.assertTrue(c._web_filesystem_path_is_case_insensitive(path))
                self.assertEqual(c._web_path_aliases_for_filesystem_path(path, ['site/root']), ('/Utility.php',))
        self.assertEqual(c._web_path_aliases_for_filesystem_path('C:/STRASSE/Utility.php', ['straße']), ('/Utility.php',))

    def test_unknown_posix_path_not_windows_by_directory_name(self):
        for path in ['/inetpub/wwwroot/Utility.php', '/site/root/Utility.php', 'site/root/Utility.php']:
            self.assertFalse(c._web_filesystem_path_is_case_insensitive(path))

    def test_manifest_keeps_distinct_posix_case_identities(self):
        manifest = self.manifest([('/srv/tenant/Utility.php', 'av'), ('/srv/tenant/utility.php', 'luhn')])
        self.assertEqual(manifest['web_path_map'], {'/Utility.php': {'av'}, '/utility.php': {'luhn'}})
        self.assertEqual(manifest['web_basename_map'], {'Utility.php': {'av'}, 'utility.php': {'luhn'}})
        for target, tag, absent in [('/Utility.php', 'av', 'luhn'), ('/utility.php', 'luhn', 'av')]:
            signals, _ = self.propagate(manifest, target)
            self.assertTrue(signals.get('referenced_file_' + tag + '_hit'))
            self.assertFalse(signals.get('referenced_file_' + absent + '_hit'))

    def test_request_case_and_percent_decoding(self):
        manifest = self.manifest([('/srv/tenant/Utility.php', 'av')])
        for target, matched in [('/Utility.php', True), ('/%55tility.php?x=1', True),
                                ('/utility.php', False), ('/UTILITY.PHP', False)]:
            with self.subTest(target=target):
                signals, _ = self.propagate(manifest, target)
                self.assertEqual(bool(signals.get('referenced_file_av_hit')), matched)

    def test_windows_manifest_and_lookup_preserve_case_insensitive_support(self):
        manifest = self.manifest([('C:/SITE/ROOT/Utility.php', 'av')])
        self.assertFalse(manifest['web_path_map'])
        self.assertEqual(manifest['web_casefold_path_map'], {'/utility.php': {'av'}})
        for target in ['/Utility.php', '/utility.php', '/UTILITY.PHP']:
            self.assertTrue(self.propagate(manifest, target)[0].get('referenced_file_av_hit'))

    def test_upload_normalisation_preserves_case(self):
        policy = self.engine.detector_policy.web_request_classification.upload
        for value in ['Utility.php', r'C:\fakepath\Utility.php', '%55tility.php']:
            self.assertEqual(c._normalise_upload_filename(value,
                filename_extension_admission=policy.filename_extension_admission), 'Utility.php')
        names = c._extract_http_upload_names('Content-Disposition: form-data; filename="Utility.php"',
            query_parameter_names=policy.query_parameter_names,
            filename_extension_admission=policy.filename_extension_admission)
        self.assertEqual(names, ('Utility.php',))

    def test_upload_posix_case_and_windows_folding(self):
        for path, lower_matches in [('/srv/tenant/Utility.php', False), ('C:/site/root/Utility.php', True)]:
            manifest = self.manifest([(path, 'av')])
            for name, expected in [('Utility.php', True), ('utility.php', lower_matches)]:
                with self.subTest(path=path, name=name):
                    signals, _ = self.propagate(manifest, '/receive', upload=name)
                    self.assertEqual(bool(signals.get('web_malicious_file_upload')), expected)

    def test_atomic_nameless_put_preserves_case(self):
        data = self.engine.apply_atomic(frame([('0s', http('/Utility.php', 'PUT', 201))]),
            apply_profiling=False, materialise_event_columns=True)
        self.assertEqual(data.iloc[0].chronosift_web_upload_names, 'Utility.php')

    def test_cross_root_and_cross_mode_ambiguities_do_not_union(self):
        for paths in [
            [('/srv/tenant/Utility.php', 'av'), ('/site/root/Utility.php', 'luhn')],
            [('C:/site/root/Utility.php', 'av'), ('D:/site/root/utility.php', 'luhn')],
            [('/srv/tenant/Utility.php', 'av'), ('C:/site/root/utility.php', 'luhn')],
        ]:
            with self.subTest(paths=paths):
                manifest = self.manifest(paths)
                for target in ['/Utility.php', '/utility.php', '/UTILITY.PHP']:
                    self.assertFalse(self.propagate(manifest, target)[0])
                for name in ['Utility.php', 'utility.php']:
                    self.assertFalse(self.propagate(manifest, '/receive', upload=name)[0])

    def test_ambiguous_basename_does_not_remove_exact_subdirectory_alias(self):
        manifest = self.manifest([('/srv/tenant/a/Utility.php', 'av'), ('/srv/tenant/b/Utility.php', 'luhn')])
        self.assertFalse(manifest['web_basename_map'])
        self.assertTrue(self.propagate(manifest, '/a/Utility.php')[0].get('referenced_file_av_hit'))
        self.assertTrue(self.propagate(manifest, '/b/Utility.php')[0].get('referenced_file_luhn_hit'))

    def test_exact_hash_survives_case_mismatch(self):
        manifest = self.manifest([('/srv/tenant/Utility.php', 'av')], hashed=True)
        signals, _ = self.propagate(manifest, '/receive', upload='utility.php', sha256='F' * 64)
        self.assertTrue(signals.get('web_malicious_file_upload'))

    def test_manifest_roundtrip_preserves_all_case_modes(self):
        manifest = self.manifest([('/srv/tenant/Utility.php', 'av'), ('C:/site/root/Other.php', 'luhn')])
        before = json.dumps(c._serialise_file_hit_manifest(manifest), sort_keys=True)
        restored = c._deserialise_file_hit_manifest(json.loads(before))
        self.assertEqual(manifest, restored)
        for target in ['/Utility.php', '/utility.php', '/OTHER.PHP']:
            self.assertEqual(self.propagate(manifest, target), self.propagate(restored, target))
        self.assertEqual(before, json.dumps(c._serialise_file_hit_manifest(manifest), sort_keys=True))

    def test_old_and_malformed_schema_rejected_after_json_roundtrip(self):
        manifest = self.manifest([('/srv/tenant/Utility.php', 'av')])
        for version in [7, 8.0, '8', True, None]:
            with self.subTest(version=version):
                manifest['schema_version'] = version
                restored = c._deserialise_file_hit_manifest(json.loads(json.dumps(c._serialise_file_hit_manifest(manifest))))
                with self.assertRaisesRegex(ValueError, 'schema'):
                    self.propagate(restored, '/Utility.php')

    def test_native_month_boundary_compact_and_expanded_scores_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configured = configure_web_roots(yaml.safe_load(RULES.read_text()), ['/srv/tenant'])
            rule_path = root / 'rules.yaml'
            rule_path.write_text(yaml.safe_dump(configured, sort_keys=False))
            data = frame([
                ('59m', file('/srv/tenant/Utility.php', yara_match=['TEST_WEBSHELL_Strong'])),
                ('59m', file('/srv/tenant/async-upload.php')),
                ('61m', http('/Utility.php', 'GET', 200)),
                ('61m', http('/async-upload.php', 'GET', 200)),
                ('62m', http('/utility.php', 'GET', 200)),
            ])
            c.write_time_partitioned_parquet(data, str(root / 'input'), normalise=False)
            original = dict(zip(data.chronosift_row_id, data.index.as_unit('ns').astype('int64')))
            cache = root / 'file-hits.json'
            # The first native invocation must rebuild the bad schema-7 cache;
            # the second reloads schema 8 rather than losing its case namespaces.
            c.save_file_hit_manifest({'schema_version': 7, 'web_path_map': {'/utility.php': {'av'}}}, str(cache))
            outputs = []
            for compact in (False, True):
                engine = c.ChronoSiftEngine.from_yaml(rule_path, WEIGHTS, yara_metadata_path=str(self.metadata))
                engine.profiling_policy = replace(engine.profiling_policy, enabled=False)
                engine.partition_execution_policy = {**engine.partition_execution_policy, 'compact_history': compact}
                destination = root / str(compact)
                reports = engine.process_parquet_dataset_partitioned(str(root / 'input'), str(destination),
                    output_mode='sidecar', materialise_event_columns=True, file_hit_manifest_path=str(cache))
                saved = c.load_file_hit_manifest(str(cache))
                self.assertEqual(saved['schema_version'], c.REFERENCED_FILE_HIT_MANIFEST_SCHEMA_VERSION)
                self.assertIn('/Utility.php', saved['web_path_map'])
                self.assertNotIn('/utility.php', saved['web_path_map'])
                self.assertEqual(sum(report['rows_written'] for report in reports), 5)
                out = c.load_plaso_parquet_dataset(str(destination)).sort_values('chronosift_row_id')
                self.assertEqual(out.chronosift_row_id.tolist(), list(original))
                self.assertTrue(pd.api.types.is_integer_dtype(out.chronosift_row_id.dtype))
                self.assertEqual(out.chronosift_score.tolist(), [21, 10, 27.5, 0, 0])
                for ts, row in out.iterrows():
                    self.assertEqual(ts.value, original[int(row.chronosift_row_id)])
                    raw_explanations = row.get('chronosift_explain')
                    if raw_explanations is None or raw_explanations is pd.NA:
                        raw_explanations = []
                    explanations = [json.loads(x) if isinstance(x, str) else x for x in raw_explanations]
                    self.assertAlmostEqual(min(50, sum(x.get('score_contribution', 0) for x in explanations)), row.chronosift_score)
                self.assertTrue(out.iloc[2].chronosift_signals.get('webshell_activity'))
                mismatch_signals = out.iloc[4].get('chronosift_signals')
                self.assertTrue(mismatch_signals is None or mismatch_signals is pd.NA or not mismatch_signals.get('webshell_activity'))
                for column, empty in [('chronosift_signals', dict), ('chronosift_explain', list)]:
                    out[column] = out[column].map(lambda value: empty() if value is None or value is pd.NA else value)
                outputs.append(out)
            # All-null materialised optional fields can use different Arrow
            # dtypes in compact/expanded output. Values, core IDs and times
            # must agree; physical optional-null encoding is not semantic.
            pd.testing.assert_frame_equal(outputs[0], outputs[1], check_dtype=False, check_exact=True)


if __name__ == '__main__':
    unittest.main()
