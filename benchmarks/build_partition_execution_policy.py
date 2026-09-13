"""Emit an apply_patch document for execution-only v18; preserve v17 verbatim.

The allowlist is an explicit admission contract, not an inferred OS classifier.
Any unknown/mixed parser or structured Windows identity column keeps all rules.
No scoring rule, weight, address, filename or ground-truth label is changed.
"""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'rules/rules_evidence_calibrated_v18.yaml'


def build():
    original = (ROOT / 'rules/rules_evidence_calibrated_v17.yaml').read_text()
    rules = yaml.safe_load(original)
    linux = r'(?:systemd_journal|text/(?:apache_access|apt_history|dpkg|syslog_traditional)|utmp)'
    windows_rules = [rule['id'] for rule in rules['temporal_rules'] if rule['id'].startswith('WINDOWS_')]
    # These names are generic, but BOTH producers explicitly require
    # windows_program_execution. Trace prerequisites, not rule-name prefixes.
    windows_rules += ['QUALIFIED_MALWARE_PATH_USE', 'QUALIFIED_MALWARE_EXACT_HASH_USE']
    # Structured Windows input and pre-normalised identity overrides invalidate
    # the proof even if the column happens to contain only null values.
    absent = ['event_identifier', 'event_id', 'provider_name', 'source_name', 'xml_string',
              'user_sid', 'subject_user_name', 'subject_domain_name', 'target_user_name',
              'target_domain_name', 'member_name', 'group_name', 'chronosift_signals']
    absent += [item['name'] for item in rules['normalisation']
               if item['name'].startswith(('win_', 'identity_'))]
    fields = rules['canonicalisation']['windows_authentication']['fields']
    absent += [item['output_field'] for item in fields if item['output_field'] != 'command_line']
    policy = dict(partition_execution=dict(
        feature_overlap='24h', compact_history=True,
        applicability_groups=[dict(id='windows_temporal_history', temporal_rule_ids=windows_rules,
            parser_field='parser', all_parsers_match=r'(?:' + linux + r'|filestat|pe|olecf/olecf_default)',
            at_least_one_parser_matches=linux, absent_columns=sorted(set(absent)),
            forbidden_field_patterns={'data_type': r'(?i)^windows[:/]'} )]))
    header = ('# v18 changes partition execution only; scoring definitions below are byte-preserved v17.\n'
              '# Short feature windows can change frame-local baselines; see docs/PARTITION_EXECUTION.md.\n')
    return header + yaml.safe_dump(policy, sort_keys=False, width=120) + '\n' + original


if __name__ == '__main__':
    assert not TARGET.exists(), 'Versioned policies must not be overwritten'
    print('*** Begin Patch\n*** Add File: ' + str(TARGET))
    print('\n'.join('+' + line for line in build().splitlines()))
    print('*** End Patch')
