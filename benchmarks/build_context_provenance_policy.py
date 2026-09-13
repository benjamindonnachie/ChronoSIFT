"""Emit an apply_patch document for rules v16 / weights v15.

Policy owns identity scope, evidence admission, horizons and severity. The
engine supplies boundary-safe state, generic observation filters and joins.
No account names, case IPs, ground-truth rows or malware names are embedded.
"""
from pathlib import Path
import difflib
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = 'rules/rules_evidence_calibrated_v16.yaml'
WEIGHTS = 'rules/weights_evidence_calibrated_v15.yaml'


def regex(name, source, pattern, selector=None):
    spec = dict(name=name, method='regex_first', **{'from': source}, pattern=pattern, group=1)
    if selector:
        spec['selector'] = dict(field=selector[0], pattern=selector[1])
    return spec


def coalesce(name, *fields):
    return dict(name=name, method='coalesce', fields=list(fields), overwrite_existing=True)


def joined(name, *fields):
    return dict(name=name, method='join_fields', fields=list(fields), separator='|')


def sequence(name, key, steps, output, horizon, priority, description):
    return dict(id=name, description=description, priority=priority, key_by=[key],
                lookback=horizon, lookback_lower_bound='inclusive', emit_on='sequence_completion',
                minimum_signal_value_exclusive=0, include_supporting_rows=True,
                sequence=[dict(signal=s, min_count=1) for s in steps],
                emit=dict(signals=[dict(name=output, value=1)]), confidence='medium')


def build_policy():
    r = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v15.yaml').read_text())
    w = yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v14.yaml').read_text())
    d = r['detector_policy']['detectors']
    n = r['normalisation']
    sid = r'(?i)^(S-1-5-21-(?:\d+-){3}\d+)$'
    n += [
        coalesce('continuity_scope_raw', 'win_asset_id', 'host_name', 'hostname'),
        dict(name='continuity_scope', method='casefold', **{'from':'continuity_scope_raw'}),
        coalesce('continuity_actor_raw', 'win_identity_sid', 'actor_principal'),
        dict(name='continuity_actor', method='casefold', **{'from':'continuity_actor_raw'}),
        # join_fields is empty unless BOTH identity components are observed.
        # A known image must not create a shared anonymous-account baseline.
        joined('continuity_key', 'continuity_scope', 'continuity_actor'),
        regex('win_creator_sid', 'win_subject_sid', sid, ('win_event_id', r'^4720$')),
        regex('win_parent_auth_sid', 'win_identity_sid', sid, ('win_event_id', r'^4624$')),
        coalesce('win_creator_chain_sid_raw', 'win_creator_sid', 'win_parent_auth_sid'),
        dict(name='win_creator_chain_sid', method='casefold', **{'from':'win_creator_chain_sid_raw'}),
        dict(name='win_context_sid_folded', method='casefold', **{'from':'win_context_sid'}),
        joined('win_creator_chain_key', 'continuity_scope', 'win_creator_chain_sid'),
        joined('win_scoped_account_key', 'continuity_scope', 'win_context_sid_folded'),
        regex('win_userassist_run_count', 'message', r'(?i)\bCount:\s*(\d+)\b',
              ('parser', r'(?i)userassist')),
        # Configurable dual-use family vocabulary. Presence alone is not an
        # observation: the temporal rule ALSO requires qualified program use.
        regex('win_dual_use_tool_raw', 'win_evidence_path', r'(?i)[\\/](psexec)(?:64)?\.exe$'),
        dict(name='win_dual_use_tool', method='casefold', **{'from':'win_dual_use_tool_raw'}),
    ]

    # A shared privileged name is not a shared human identity. The image scope
    # separates local/clone accounts; Windows SIDs precede display names.
    for name in ('geographic_continuity', 'impossible_travel', 'ip_scope_continuity'):
        d[name]['inputs']['key_fields'] = ['continuity_key']
    travel = d['impossible_travel']
    travel['state']['rejected_observation_update'] = 'update_if_nearby'
    travel['emissions']['impossible_travel']['description'] = (
        'Geographic velocity anomaly for the same scoped account; concurrent operators, VPNs and GeoIP uncertainty remain possible')
    # This version explicitly permits a travel observation as provenance for
    # the bounded creator edge. The executor's eligibility guard stays strict.
    ineligible = r['engine_config']['temporal_signal_policy']['ineligible_signals']
    ineligible.remove('impossible_travel')

    # Only the weighted sensitive-path branch is changed. The forensic
    # container remains in raw evidence; ordinary filesystem/linked-file
    # observations retain their existing policy.
    d['file_lifecycle']['conditions']['row_emissions']['sensitive_file_access']['excluded_parser_prefixes'] = [
        'winreg', 'winevt', 'esedb']

    direct = d['direct_attack_semantics']
    direct['inputs']['userassist_count'] = dict(resolver='row_field', fields=['win_userassist_run_count'], normalise='lower')
    direct['evidence']['userassist_count'] = dict(resolver='input', input='userassist_count')
    use = next(rule for rule in direct['ordered_rules'] if rule['id']=='windows_program_execution')['when']
    for branch in use['any']:
        if any(term.get('input')=='parser_lower' and 'userassist' in term.get('values', [])
               for term in branch.get('all', [])):
            branch['all'].append(dict(input='userassist_count', op='regex', pattern=r'^[1-9]\d*$'))

    # https://attack.mitre.org/techniques/T1136/002/
    # Subject SID is the creator; target SID is the child. They are not aliases.
    r['rules'].append(dict(
        id='WINDOWS_ACCOUNT_CREATION_TARGET', priority=90,
        description='Structured Windows account-creation edge: creator SubjectUserSid to child TargetSid (ATT&CK T1136.002)',
        scope=dict(any=[], all=[dict(field='parser', op='contains_ci', value='winevt'),
                               dict(field='source_name', op='in_ci', value=['Microsoft-Windows-Security-Auditing'])]),
        when=dict(any=[], all=[dict(field='win_event_id', op='eq', value='4720'),
                              dict(field='win_creator_sid', op='exists'),
                              dict(field='win_identity_sid', op='exists')]),
        emit=dict(signals=[dict(name='windows_account_creation_target', value=1)],
                  evidence=[dict(field=field) for field in ('win_creator_sid','win_identity_sid','win_context_sid',
                                                          'subject_user_name','target_user_name','hostname')]),
        confidence='high'))
    w['weights']['windows_account_creation_target'] = 0

    # ATT&CK T1078 -> T1136.002 -> T1098.007: one-hop, time-directed provenance.
    # The parent's numeric score and inherited risk are NEVER source signals.
    # https://attack.mitre.org/techniques/T1098/007/
    projection_inputs = []
    for reason, source in (('travel', 'impossible_travel'), ('authentication', 'fail_then_success_user')):
        birth = f'windows_created_by_risky_{reason}_account'
        grant = f'windows_risky_creator_{reason}_privileged_account'
        action = f'windows_risky_creator_{reason}_action'
        r['temporal_rules'] += [
            sequence(birth.upper(), 'win_creator_chain_key', [source, 'windows_account_creation_target'], birth, '24h', 79,
                     'Account created by a SID with recent suspicious authentication; same operator/session not established (ATT&CK T1078/T1136.002)'),
            sequence(grant.upper(), 'win_scoped_account_key', [birth, 'windows_new_privileged_account'], grant, '1h', 78,
                     'Recently created account with risky creator provenance gains privileged membership (ATT&CK T1098.007)'),
            sequence(action.upper(), 'win_scoped_account_key', [grant, 'windows_contextual_action'], action, '7d', 77,
                     'Sensitive action by a recently privileged account with risky creator provenance; direct/profile SID context, not operator proof (ATT&CK T1078)'),
        ]
        projection_inputs += [birth, grant, action]
        for name in (birth, grant, action):
            w['weights'][name] = 0
    d['windows_creator_risk_projection'] = dict(
        stage='temporal', executor='signal_projection', enabled=True, evidence_type='contextual',
        projections=[dict(inputs=dict(signals=projection_inputs),
                          conditions=dict(match='any', minimum_value_exclusive=0),
                          strength='maximum_matched_times_emission_value',
                          emissions=[dict(name='windows_risky_creator_context', value=1,
                                          rule_id='WINDOWS_RISKY_CREATOR_CONTEXT',
                                          description='Bounded creator-risk contribution counted once across authentication evidence; additive to new privilege, not a copied parent score',
                                          confidence='medium')])],
        evidence=dict(derived_from=dict(resolver='matched_signals')))
    w['weights']['windows_risky_creator_context'] = 8

    # https://attack.mitre.org/techniques/T1569/002/
    # First QUALIFYING execution in available 7-day per-account history, not
    # first-ever use or first presence. PsExec and PsExec64 share one family.
    r['temporal_rules'].append(dict(
        id='WINDOWS_FIRST_OBSERVED_DUAL_USE_EXECUTION', priority=76,
        description='First qualifying use of a configured dual-use tool family in available seven-day scoped-account history; not first-ever use (ATT&CK T1569.002)',
        key_by=['win_scoped_account_key'], lookback='7d', lookback_lower_bound='inclusive',
        emit_on='condition_match', minimum_signal_value_exclusive=0,
        condition=dict(kind='first_seen_value', field='win_dual_use_tool', empty_value_behavior='ignore',
                       first_observation_behavior='emit', reference_selection='rolling_window',
                       signals_any=['windows_program_execution']),
        emit=dict(signals=[dict(name='windows_first_observed_dual_use_execution', value=1)]), confidence='low'))
    w['weights']['windows_first_observed_dual_use_execution'] = 4
    return r, w


def render_policy():
    rules, weights = build_policy()
    header = (
        '# Context provenance policy: rules v16 / weights v15.\n'
        '# Scoped travel, container-safe sensitivity, bounded creator risk +8, qualifying tool novelty +4.\n'
        '# Account evidence is not operator/session proof; risk is not copied recursively.\n'
        '# ATT&CK T1078 https://attack.mitre.org/techniques/T1078/\n'
        '# ATT&CK T1136.002 https://attack.mitre.org/techniques/T1136/002/\n'
        '# ATT&CK T1098.007 https://attack.mitre.org/techniques/T1098/007/\n'
        '# ATT&CK T1569.002 https://attack.mitre.org/techniques/T1569/002/\n'
        '# Expert-set weights; see ../docs/CONTEXT_PROVENANCE.md.\n')
    return {name: header + yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=120)
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
