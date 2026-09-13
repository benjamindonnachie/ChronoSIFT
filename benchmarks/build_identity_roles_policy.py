"""Emit rules v17 as an apply_patch document; weights v15 are unchanged.

Event IDs, provider qualification, role precedence and uncertainty policy live
here/in generated YAML, not in the generic engine. No ground-truth identities.
"""
from pathlib import Path
import difflib
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = 'rules/rules_evidence_calibrated_v17.yaml'
SECURITY = r'(?i)^winevt[^|]*\|Microsoft-Windows-Security-Auditing\|'
AUTH = SECURITY + r'(?:4624|4625|4634|4776)$'
MANAGEMENT = SECURITY + r'(?:472[0-9]|473[0-9]|474[0-3]|475[4-8]|476[47]|478[01])$'
MEMBERSHIP = SECURITY + r'(?:4728|4729|4732|4733|4756|4757)$'
GROUP = SECURITY + r'(?:472[789]|473[0-57]|475[4-8])$'
REMOVAL = SECURITY + r'(?:4725|4726|4729|4733|4757)$'
RDP = r'(?i)^winevt[^|]*\|Microsoft-Windows-TerminalServices-RemoteConnectionManager\|1149$'
# Other providers reusing an ID cannot inherit these identity semantics.
ANY_1149 = r'(?i)^winevt[^|]*\|[^|]+\|1149$'


def branch(pattern, *fields):
    if pattern == ANY_1149:
        return dict(field='win_event_id', pattern=r'^1149$', fields=list(fields))
    return dict(field='identity_event_key', pattern=pattern, fields=list(fields))


def select(name, cases, default=()):
    return dict(name=name, method='select_coalesce', cases=cases, default_fields=list(default))


def joined(name, *fields, separator='\\'):
    return dict(name=name, method='join_fields', fields=list(fields), separator=separator)


def coalesce(name, *fields):
    return dict(name=name, method='coalesce', fields=list(fields), overwrite_existing=True)


def build_policy():
    rules = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v16.yaml').read_text())
    fields = rules['canonicalisation']['windows_authentication']['fields']
    # Explicit UserData leaf aliases; consumed only by the provider/ID-qualified
    # branches below. System/Security UserID remains a reporting identity.
    for name, aliases in [('identity_rdp_user', ['Param1']), ('identity_rdp_domain', ['Param2'])]:
        fields.append(dict(id=name, output_field=name, event_data_aliases=aliases, system_source='none'))
    n = rules['normalisation']
    event = next(item for item in n if item['name']=='win_event_id')
    n.remove(event)
    role_fields = [
        event,
        coalesce('identity_event_provider', 'provider_name', 'source_name'),
        joined('identity_event_key', 'parser', 'identity_event_provider', 'win_event_id', separator='|'),
        joined('identity_target_qualified', 'target_domain_name', 'target_user_name'),
        joined('identity_subject_qualified', 'subject_domain_name', 'subject_user_name'),
        joined('identity_rdp_qualified', 'identity_rdp_domain', 'identity_rdp_user'),
        dict(name='identity_target_sid_valid', method='regex_first', **{'from':'win_target_sid'},
             pattern=r'(?i)^(S-1-(?!0-0$)\d+(?:-\d+)+)$', group=1),
        select('identity_reporting_sid', [dict(field='parser', pattern=r'(?i)^winevt', fields=['user_sid'])]),
        select('identity_authenticated_account', [
            branch(RDP, 'identity_rdp_qualified', 'identity_rdp_user'),
            branch(AUTH, 'identity_target_qualified', 'target_user_name', 'win_target_sid')]),
        select('identity_authenticated_sid', [branch(AUTH, 'identity_target_sid_valid')]),
        select('identity_acting_account', [branch(MANAGEMENT, 'identity_subject_qualified', 'subject_user_name', 'win_subject_sid')]),
        select('identity_acting_sid', [branch(MANAGEMENT, 'win_subject_sid')]),
        select('identity_affected_account', [branch(MEMBERSHIP, 'member_name', 'win_member_sid'),
            branch(GROUP), branch(MANAGEMENT, 'identity_target_qualified', 'target_user_name', 'win_target_sid')]),
        select('identity_affected_sid', [branch(MEMBERSHIP, 'win_member_sid'),
            branch(GROUP), branch(MANAGEMENT, 'win_target_sid')]),
        select('identity_affected_group', [branch(GROUP, 'group_name', 'target_user_name')]),
        select('identity_affected_group_sid', [branch(GROUP, 'win_target_sid')]),
        # Domain-less display names are useful evidence but not safe cross-event
        # account identities. No SID inference or nearest-session association.
        select('identity_auth_continuity', [branch(RDP, 'identity_rdp_qualified'),
            branch(AUTH, 'identity_target_sid_valid', 'identity_target_qualified')]),
    ]
    actor_index = next(i for i,item in enumerate(n) if item['name']=='actor_user')
    n[actor_index:actor_index] = role_fields
    for name in ('actor_user', 'actor_principal'):
        i = next(i for i,item in enumerate(n) if item['name']==name)
        old = n[i]
        # Existing privilege vocabulary and name-based failure sequences consume
        # usernames, not domain-prefixed display strings. Preserve that contract
        # while correcting the role; qualified values remain separate evidence.
        n[i] = select(name, [branch(RDP, 'identity_rdp_user'),
            branch(ANY_1149), branch(AUTH, 'target_user_name', 'identity_authenticated_sid'),
            branch(MANAGEMENT, 'subject_user_name', 'identity_acting_sid')], old['fields'])
    i = next(i for i,item in enumerate(n) if item['name']=='continuity_actor_raw')
    n[i] = select('continuity_actor_raw', [branch(RDP, 'identity_auth_continuity'),
        branch(ANY_1149), branch(AUTH, 'identity_auth_continuity')], n[i]['fields'])
    i = next(i for i,item in enumerate(n) if item['name']=='win_direct_sid')
    # Creation/grant are deliberately keyed to the child for the existing
    # lifecycle sequence. Removal/disable/delete context instead belongs to the
    # actor, never to the account losing access. No new scoring dimension.
    n[i] = select('win_direct_sid', [branch(REMOVAL, 'identity_acting_sid'),
        branch(ANY_1149)], n[i]['fields'])

    role_names = ['identity_reporting_sid', 'identity_authenticated_account', 'identity_authenticated_sid',
        'identity_acting_account', 'identity_acting_sid', 'identity_affected_account',
        'identity_affected_sid', 'identity_affected_group', 'identity_affected_group_sid']
    for rule in rules['rules']:
        if rule['id'] in ('RDP_PRE_AUTH_WINDOWS_1149', 'WINDOWS_ACCOUNT_CREATION_TARGET'):
            rule['emit']['evidence'] += [dict(field=name) for name in role_names]
    direct = rules['detector_policy']['detectors']['direct_attack_semantics']
    for name in role_names:
        direct['inputs'][name] = dict(resolver='row_field', fields=[name], normalise='none')
        direct['evidence'][name] = dict(resolver='input', input=name)
    for rule in direct['ordered_rules']:
        if rule['id'] in ('account_disabled_or_deleted', 'privileged_group_removal',
                          'other_account_access_removal', 'account_access_removal_base'):
            rule.setdefault('evidence', []).extend(role_names)
    return rules


def render_policy():
    return '# Event-role identity policy v17; unchanged weights v15.\n' + (
        '# Reporting, authenticated, acting and affected identities remain separate.\n'
        '# Provider/event-qualified XML fields; unknown remote identities do not enter continuity.\n'
        '# ATT&CK T1078 https://attack.mitre.org/techniques/T1078/\n'
        '# ATT&CK T1531 https://attack.mitre.org/techniques/T1531/\n'
        '# See ../docs/IDENTITY_ROLES.md for source semantics and uncertainty limits.\n'
    ) + yaml.safe_dump(build_policy(), sort_keys=False, allow_unicode=True, width=120)


def main():
    path=ROOT/RULES; content=render_policy()
    print('*** Begin Patch')
    if not path.exists():
        print('*** Add File: '+str(path)); print('\n'.join('+'+line for line in content.splitlines()))
    elif path.read_text()!=content:
        print('*** Update File: '+str(path))
        for line in list(difflib.unified_diff(path.read_text().splitlines(), content.splitlines(), n=6, lineterm=''))[2:]:
            print('@@' if line.startswith('@@') else line)
    print('*** End Patch')


if __name__=='__main__': main()
