"""Build v23/v21: AV-positive behavioural capabilities with bounded support.

YAML owns every admission decision, confidence band, contribution and ATT&CK
mapping. Hashes, vendor family labels and challenge filenames are never rules.
"""
import argparse
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def build(root=ROOT):
    r = yaml.safe_load((root/'rules/rules_evidence_calibrated_v22.yaml').read_text())
    w = yaml.safe_load((root/'rules/weights_evidence_calibrated_v20.yaml').read_text())
    d = r['detector_policy']['detectors']
    classifier = d['clamav_classification']
    # Generic Razy labels encompass unrelated capabilities. Family substring
    # alone is not encryption evidence (T1486); preserve raw AV category.
    classifier['family_overrides'] = [x for x in classifier['family_overrides'] if x['contains'] != 'razy']
    definitions = {
        'credential_access': (8, ['T1555.003', 'T1555.004', 'T1003'], 'Credential-access capability supported by AV and external behavioural evidence'),
        'persistence': (5, ['T1547.001'], 'Persistence capability supported by AV and external behavioural evidence'),
        'evasion': (3, ['T1497.001', 'T1497.003', 'T1622', 'T1027'], 'Evasion-related capability or supporting tags in an AV-positive artifact'),
        'destructive': (10, ['T1486', 'T1561'], 'Destructive or encryption capability supported by AV and external behavioural evidence'),
        'exfiltration': (7, ['T1041', 'T1048'], 'Data-exfiltration capability supported by AV and external behavioural evidence'),
        'webshell': (8, ['T1505.003'], 'Web-shell capability supported by AV and external behavioural evidence'),
    }
    capabilities = {}
    for name, (points, techniques, description) in definitions.items():
        signal = 'av_behaviour_' + name
        capabilities[name] = dict(attack_ids=techniques, emission=dict(name=signal, value=1,
            rule_id=signal.upper(), description=description+'; presence/reference is not observed outcome', confidence='medium'))
        w['weights'][signal] = points
    rules = []
    def rule(name, source, capability, support, *conditions):
        rules.append(dict(id=name, source=source, capability=capability, support=support, conditions=list(conditions), attack_ids=[]))
    def member(field, values):
        return dict(field=field, op='in', values=values)
    def regex(field, pattern):
        return dict(field=field, op='regex', pattern=pattern)
    specific = {
        'credential_access': (['T1555', 'T1555.003', 'T1555.004', 'T1003', 'T1003.001', 'T1003.002'],
            r'(?i)(?:credential|password|browser.*(?:userdata|login)|(?:dump|access|read).*lsass)'),
        'persistence': (['T1547.001'], r'(?i)(?:runonce|autorun|auto.?start|startup|registry.*run)'),
        'evasion': (['T1497.001', 'T1497.003', 'T1622', 'T1027', 'T1027.002'], r'(?i)(?:debug|virtual|anti.?vm|obfuscat|pack(?:ed|ing|er)|sandbox)'),
        'destructive': (['T1486', 'T1561', 'T1561.001', 'T1561.002'], r'(?i)(?:encrypt.*(?:file|document|disk)|(?:wipe|overwrite|destroy).*(?:disk|boot|file)|ransom)'),
        'exfiltration': (['T1041', 'T1048', 'T1048.001', 'T1048.002', 'T1048.003'], r'(?i)(?:exfiltrat|(?:upload|send).*(?:file|document|collected|stolen|data))'),
        'webshell': (['T1505.003'], r'(?i)(?:web.?shell|remote.*(?:command|shell))'),
    }
    for name, (techniques, pattern) in specific.items():
        conditions = (member('technique', techniques), regex('description', pattern))
        rule(name+'_mitre', 'mitre', name, 'capability', *conditions)
        rule(name+'_specific_signature', 'mitre', name, 'specific_signature',
            *conditions, member('severity', ['HIGH', 'CRITICAL']))
    # CAPA rules represent capabilities; INFO is not a benign verdict.
    rule('credential_capa', 'signature', 'credential_access', 'capability',
        member('format', ['SIG_FORMAT_CAPA']), regex('description', r'(?i)(?:acquire|extract|dump|steal|access).*(?:credential|password)|(?:credential|password).*dump'))
    # ATT&CK T1547.001: specific registry value writes, not a Sigma title.
    rule('sigma_registry_autorun', 'sigma', 'persistence', 'sigma_event',
        member('event_type', ['SetValue']),
        regex('target_object', r'(?i)\\(?:software\\(?:wow6432node\\)?microsoft\\windows\\currentversion)\\(?:run|runonce)\\[^\\]+$'),
        dict(field='details', op='exists'))
    rules[-1]['attack_ids'] = ['T1547.001']
    # AV-positive generic tags provide low-strength support. No per-tag points.
    for tag, technique in [('DETECT_DEBUG_ENVIRONMENT', 'T1622'), ('OBFUSCATED', 'T1027'), ('LONG_SLEEPS', 'T1497.003')]:
        rule('evasion_tag_'+tag.lower(), 'tag', 'evasion', 'supporting_tag', member('tag', [tag]))
        rules[-1]['attack_ids'] = [technique]
    rule('persistence_tag', 'tag', 'persistence', 'supporting_tag', member('tag', ['PERSISTENCE']))
    classifier['behaviour'] = dict(enabled=True, require_enriched_csv=False,
        max_contribution=14, referenced_strength=0.75, max_evidence=6,
        confidence=[dict(name='high', any_support=['specific_signature', 'sigma_event'], strength=1),
                    dict(name='medium', any_support=['capability'], strength=0.75),
                    dict(name='low', any_support=['supporting_tag'], strength=0.5)],
        capabilities=capabilities, rules=rules)
    # The same capability can arrive at atomic presence or contextual reference
    # time. Do not allow retrospective catalog metadata to seed temporal carry.
    r['engine_config']['temporal_signal_policy']['ineligible_signals'].extend(
        value['emission']['name'] for value in capabilities.values())
    # T1059/T1204 and existing qualified Linux/Windows invocation pathways:
    # enrich local-use interpretation without scoring a second execution vote.
    # The new capability contributions already apply on a qualified reference.
    # Existing execution/account/schedule/context rules continue independently.
    return r, w


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    r, w = build(args.root)
    outputs = {'rules_evidence_calibrated_v23.yaml': r, 'weights_evidence_calibrated_v21.yaml': w}
    destination = args.output_dir or args.root/'rules'
    changed = []
    for name, value in outputs.items():
        text = '# Generated by benchmarks/build_av_behaviour_policy.py; policy rationale: docs/AV_BEHAVIOUR.md\n' + yaml.safe_dump(value, sort_keys=False, allow_unicode=True, width=120)
        target = destination/name
        if not target.exists() or target.read_text() != text:
            if args.output_dir is None:
                changed.append(name)
            else:
                target.write_text(text)
    print('Current' if not changed else 'Out of date: '+', '.join(changed))


if __name__ == '__main__':
    main()
