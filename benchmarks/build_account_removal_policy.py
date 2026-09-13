"""Generate rules v15 / weights v14 without modifying the preceding policy.

Account access removal has one base contribution plus a separately weighted
privileged-group increment. The existing ordered-row executor owns the merge;
no engine change or ground-truth lookup is needed.
"""
from pathlib import Path
import difflib

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = 'rules/rules_evidence_calibrated_v15.yaml'
WEIGHTS = 'rules/weights_evidence_calibrated_v14.yaml'
PRIVILEGE = 'privileged_group_access_removal'
QUALIFIERS = ('account_removal_event_evidence', 'account_removal_other_evidence')


def build_policy():
    rules = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v14.yaml').read_text())
    weights = yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v13.yaml').read_text())
    direct = rules['detector_policy']['detectors']['direct_attack_semantics']
    ordered = direct['ordered_rules']
    by_id = {rule['id']: rule for rule in ordered}
    # These EventData targets name the affected group. Never look for an admin
    # word in the subject/member/command/message to infer the group's privilege.
    direct['inputs']['removal_group'] = dict(
        resolver='first_nonempty', fields=['group_name', 'target_user_name'], normalise='lower')
    direct['evidence']['removal_group'] = dict(resolver='input', input='removal_group')

    for rule_id, signal in zip(
            ('account_disabled_or_deleted', 'other_account_access_removal'), QUALIFIERS):
        by_id[rule_id]['emission'] = signal
        direct['emissions'][signal] = dict(
            name=signal, value=1, rule_id=signal.upper(),
            description='Supporting account-removal evidence; base points are counted by one projection',
            confidence=by_id[rule_id]['confidence'])
        weights['weights'][signal] = 0

    privileged = by_id['privileged_group_removal']
    # T1531: access/permission removal can impede legitimate users and recovery.
    # https://attack.mitre.org/techniques/T1531/
    # The affected group's privilege is intentionally ADDITIVE to the base
    # behaviour. ATT&CK supplies the rationale, not the expert-set 2 + 6 weights.
    privileged['when']['all'][1] = dict(
        input='removal_group', op='equals_any',
        values=['administrators', 'domain admins', 'enterprise admins', 'remote desktop users'])
    privileged['emission'] = PRIVILEGE
    privileged['description'] = (
        'Additional severity: membership removed from a configured privileged/access-enabling group '
        '(ATT&CK T1531 candidate); additive to the account-removal base')
    privileged['evidence'] = ['event_identifier', 'removal_group', 'member_name', 'message']
    direct['emissions'][PRIVILEGE] = dict(
        name=PRIVILEGE, value=1, rule_id=PRIVILEGE.upper(),
        description=privileged['description'], confidence='medium')
    weights['weights'][PRIVILEGE] = 6

    # Keep the individual observations, but give the shared base points ONE
    # owner. A numeric disable/delete event and matching text can both be true.
    # Distinct zero-weight qualifiers also preserve their original confidence.
    ordered.insert(ordered.index(by_id['other_account_access_removal'])+1, dict(
        id='account_access_removal_base',
        when=dict(op='signal_any_positive', signals=[*QUALIFIERS, PRIVILEGE], minimum_value_exclusive=0),
        emission='account_access_removal',
        description='Base account disablement, deletion or group-membership removal; counted once across supporting rules',
        confidence='low', evidence=['event_identifier', 'removal_group', 'member_name', 'message']))
    # The existing account_access_removal weight remains exactly 2, and its
    # existing downstream name and temporal dependencies remain unchanged.
    return rules, weights


def render_policy():
    rules, weights = build_policy()
    header = (
        '# Account-removal additive policy: rules v15 / weights v14.\n'
        '# Base removal 2 + affected privileged group 6 = 8 before other context/cap.\n'
        '# Supporting evidence is zero-weight; one base projection owns its points.\n'
        '# ATT&CK T1531 https://attack.mitre.org/techniques/T1531/\n'
        '# Expert-set priorities, not ATT&CK-prescribed weights or proof of malicious intent.\n'
        '# See ../docs/ACCOUNT_REMOVAL_SCORING.md.\n')
    return {name: header+yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=120)
            for name, config in ((RULES, rules), (WEIGHTS, weights))}


def main():
    print('*** Begin Patch')
    for name, content in render_policy().items():
        path = ROOT/name
        if path.exists():
            previous = path.read_text()
            if previous == content:
                continue
            print('*** Update File: '+str(path))
            for line in list(difflib.unified_diff(previous.splitlines(), content.splitlines(), n=30, lineterm=''))[2:]:
                print('@@' if line.startswith('@@') else line)
        else:
            print('*** Add File: '+str(path))
            print('\n'.join('+'+line for line in content.splitlines()))
    print('*** End Patch')


if __name__ == '__main__':
    main()
