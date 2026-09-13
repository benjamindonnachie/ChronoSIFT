"""F05: current-default prose must agree with the actual CLI configuration."""
from pathlib import Path
import re
import unittest
from run_chronosift_sidecar_cli import build_arg_parser

ROOT = Path(__file__).resolve().parents[1]


class PolicyDocumentationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        args = build_arg_parser().parse_args(['input', 'output'])
        cls.rules = Path(args.rules_yaml)
        cls.weights = Path(args.weights_yaml)
        cls.versions = tuple(re.search(r'_v(\d+)\.yaml$', path.name).group(1)
                             for path in (cls.rules, cls.weights))

    def test_all_readme_current_default_claims_match_cli(self):
        claims = re.findall(r'defaults to rules v(\d+)\s*/\s*weights v(\d+)',
                            (ROOT / 'README.md').read_text())
        self.assertGreaterEqual(len(claims), 2)
        self.assertTrue(all(pair == self.versions for pair in claims), claims)

    def test_rules_readme_names_the_actual_default_files(self):
        match = re.search(r'The isolated candidate runner defaults to `([^`]+)`\s+and `([^`]+)`',
                          (ROOT / 'rules/README.md').read_text())
        self.assertIsNotNone(match)
        self.assertEqual(match.groups(), (self.rules.name, self.weights.name))
        self.assertTrue(self.rules.is_file())
        self.assertTrue(self.weights.is_file())

    def test_changelog_includes_current_and_previously_missing_generations(self):
        text = (ROOT / 'CHANGELOG.md').read_text().split('## Unreleased', 1)[1]
        pairs = re.findall(r'^- Rules v(\d+) / (?:unchanged )?weights v(\d+)\b', text, re.M)
        self.assertIn(self.versions, pairs)
        self.assertIn(('22', '20'), pairs)
        self.assertIn(('23', '21'), pairs)

    def test_policy_notes_do_not_claim_stale_current_defaults(self):
        # Historical policies/examples are intentional. Only explicit default
        # declarations or "current runner selects" assertions must track CLI.
        pattern = re.compile(r'(?:defaults?\s+(?:to|are)|current\s+isolated\s+runner\s+selects)'
                             r'\s+(?:rules\s+)?v(\d+)\s*/\s*(?:weights\s+)?v(\d+)', re.I)
        for path in sorted((ROOT / 'docs').glob('*.md')):
            for pair in pattern.findall(path.read_text()):
                with self.subTest(document=path.name, pair=pair):
                    self.assertEqual(pair, self.versions)
