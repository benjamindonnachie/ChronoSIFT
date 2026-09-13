#!/usr/bin/env python3
"""Emit an idempotent apply_patch for v19/v16; preserve historical policies."""
from pathlib import Path
import difflib
import yaml

ROOT = Path(__file__).resolve().parents[1]


def build():
    rules = yaml.safe_load((ROOT / 'rules/rules_evidence_calibrated_v18.yaml').read_text())
    weights = yaml.safe_load((ROOT / 'rules/weights_evidence_calibrated_v15.yaml').read_text())
    norm = rules['normalisation']
    insert_at = next(i for i, n in enumerate(norm) if n['name'] == 'actor_user')
    norm[insert_at:insert_at] = [
        dict(name='linux_cron_user', method='regex_first', **{'from': 'message'},
             pattern=r'(?i)\bCROND?\b[^\n]*?\(([A-Za-z0-9._$@-]+)\)\s+CMD\s*\(', group=1,
             selector=dict(field='parser', pattern=r'^(?:systemd_journal|syslog|text/syslog_traditional)$')),
        dict(name='linux_cron_command', method='regex_first', **{'from': 'message'},
             pattern=r'(?i)\bCROND?\b[^\n]*?\([A-Za-z0-9._$@-]+\)\s+CMD\s*\(([^\n]*)\)[\x00\s]*$', group=1,
             selector=dict(field='parser', pattern=r'^(?:systemd_journal|syslog|text/syslog_traditional)$')),
        dict(name='auth_pivot_source', method='select_coalesce', cases=[
            dict(field='src_ip', pattern=r'^(?:0\.0\.0\.0$|::$|::1$|127\.)', fields=[])], default_fields=['src_ip']),
    ]
    for name in ('actor_user', 'actor_principal'):
        item = next(n for n in norm if n['name'] == name)
        item['cases'].insert(0, dict(field='linux_cron_user', pattern=r'.+', fields=['linux_cron_user']))
    ssh = rules['canonicalisation']['ssh_authentication']
    ssh['patterns'].insert(0, dict(id='plaso_successful_login',
        regex=r'(?i)\bSuccessful login of user:\s*([A-Za-z0-9._$@-]+)\s+from\s+([0-9.]+):[0-9]+\s+using authentication method:\s*([A-Za-z0-9_-]+)\s+ssh\b',
        outcome='success', groups=dict(actor_user_auth=1, source_ip=2, auth_method=3), require_message_selector=False))
    # The parser selector admits this Plaso rendering without requiring "sshd".
    ssh['selector']['message_regex'] = r'(?i)\b(?:sshd|using authentication method:\s*[A-Za-z0-9_-]+\s+ssh)\b'
    atomic = {r['id']: r for r in rules['rules']}
    atomic['SSH_SUCCESS_LINUX']['when']['any'].append(dict(field='auth_protocol', op='eq', value='ssh'))
    atomic['SSH_SUCCESS_LINUX']['when']['all'] = [dict(field='auth_outcome', op='eq', value='success')]
    atomic['SSH_SUCCESS_LINUX']['scope']['any'].append(dict(field='auth_protocol', op='eq', value='ssh'))
    atomic['PRIV_LOGIN']['scope']['any'] = [
        dict(field='auth_outcome', op='eq', value='success'),
        dict(field='message', op='regex', value=r'(?i)(?:successful login|accepted (?:password|publickey)|session opened for user)')]
    atomic['PRIV_LOGIN']['description'] = 'Privileged account authenticated successfully; a targeted account name alone is not access'
    # Require an authentication-specific context for the generic fallback.
    atomic['AUTH_FAIL_GENERIC']['scope']['any'] = [
        dict(field='auth_outcome', op='eq', value='failure'),
        dict(field='message', op='regex', value=r'(?i)(?:sshd|pam_|authentication|logon failure|failed (?:password|publickey)|invalid user)')]
    for rule in rules['temporal_rules']:
        if rule['id'] in ('AUTH_PIVOT_ACCOUNTS_FROM_SAME_SRC', 'AUTH_PIVOT_DESTINATION_FOR_SAME_USER'):
            rule['condition']['signals_any'] = ['auth_remote_success']
            rule['description'] += '; successful remote authentication observations only'
            if rule['id'] == 'AUTH_PIVOT_ACCOUNTS_FROM_SAME_SRC':
                rule['key_by'] = ['auth_pivot_source']
    detectors = rules['detector_policy']['detectors']
    direct = detectors['direct_attack_semantics']
    direct['ordered_rules'].append(dict(id='qualified_tool_file', when=dict(all=[
        dict(input='parser_lower', op='regex', pattern=r'^filestat$'),
        dict(input='yara_qualified', op='regex', pattern=r'(?:^|\|)(?:offensive_tool|malware|ransomware|apt)(?:\||$)')]),
        emission='qualified_tool_file', description='Observed file with score/quality-qualified YARA tool or malware evidence; not execution',
        confidence='medium', evidence=['linked_web_file', 'yara_qualified']))
    direct['emissions']['qualified_tool_file'] = dict(name='qualified_tool_file', value=1,
        rule_id='QUALIFIED_TOOL_FILE', confidence='medium',
        description='Observed score/quality-qualified YARA tool file; presence is not execution')
    # Existing contextual signal adjustments retain original facts in evidence
    # but revoke erroneous score inputs before temporal authentication rules.
    adjustments = detectors['contextual_signal_adjustments']
    def zero_rule(name, required, targets, description):
        return dict(id=name, when=dict(input='command', op='regex', pattern=r'(?s).*'),
            signal_conditions=dict(minimum_value_exclusive=0, required_any=required,
                                   preserved=required),
            target_signals=targets, action=dict(type='zero'),
            explanation=dict(rule_id=name.upper(), description=description, confidence='high'),
            evidence=['dampened_signals', 'command'])
    adjustments['ordered_rules'][:0] = [
        zero_rule('failed_auth_is_not_privileged_execution', ['auth_failure'],
                  ['privileged_login', 'exec_privileged_context'],
                  'Failed authentication does not establish privileged access or execution (ATT&CK T1110)'),
        zero_rule('ssh_failure_fallback_deduplication', ['ssh_fail'], ['auth_fail_generic'],
                  'SSH failure retains its protocol-specific signal; generic failure is not an additional observation'),
        zero_rule('scheduled_privilege_context_deduplication', ['privileged_scheduled_exec'], ['exec_privileged_context'],
                  'Privileged schedule already supplies the privileged invocation context'),
    ]
    # Only constrained command forms: no shell expansion, arbitrary basename
    # lookup, or nearest-event attribution. The last form is deliberately a
    # directory HINT, not proof that a malformed wrapper successfully ran.
    token = r'[A-Za-z0-9_./+-]+'
    script = r'[A-Za-z0-9_./+-]+\.(?:py|sh|pl|rb)'
    interpreter = r'(?:/usr/bin/|/bin/)?(?:python[0-9.]*|bash|sh|perl|ruby)'
    ending = r'(?:\s*&)?\s*'
    detectors['linux_qualified_tool_invocation'] = dict(
        stage='contextual', executor='qualified_artifact_command', enabled=True,
        fields=dict(path='filename', parser='parser', type='file_entry_type', scope='hostname',
                    command='linux_cron_command', row_id='chronosift_row_id', hash='sha256_hash'),
        file_parser=r'^filestat$', file_type=r'^file$',
        marker_pattern=r'(?P<root>/.+)/\.git/HEAD',
        references=dict(
            absolute_script=rf'\s*(?:nohup\s+)?{interpreter}\s+(?P<target>/{script}){ending}',
            working_directory=rf'\s*cd\s+(?P<directory>/{token})\s*&&\s*(?:nohup\s+)?{interpreter}\s+(?P<target>{script}){ending}',
            prefix_directory_hint=rf'\s*(?P<directory>/{token})/nohup\s+{interpreter}\s+(?P<target>{script}){ending}'),
        source_signals=['qualified_tool_file', 'evidence_qualified_malware_file'],
        target_signals=['scheduled_exec'], lookback='24h', unlabelled_file_scope='current_dataset',
        emissions=dict(
            exact_path=dict(name='linux_qualified_file_invocation', value=1,
                rule_id='LINUX_QUALIFIED_FILE_INVOCATION', confidence='medium',
                description='Scheduled command references an earlier qualified full-path file candidate; file version and successful payload effects unproved (ATT&CK T1053.003, T1059)'),
            repository=dict(name='linux_qualified_repository_invocation', value=1,
                rule_id='LINUX_QUALIFIED_REPOSITORY_INVOCATION', confidence='low',
                description='Scheduled command references an observed component of a marker-verified repository containing an earlier qualified tool file; not an exact target-file YARA hit or proof of successful execution (ATT&CK T1053.003, T1059)')))
    weights['weights'].update(qualified_tool_file=0, linux_qualified_file_invocation=26,
        linux_qualified_repository_invocation=18, ssh_fail=1, auth_fail_generic=1, auth_invalid_user=1)
    return rules, weights


if __name__ == '__main__':
    docs = build()
    print('*** Begin Patch')
    for name, doc in zip(('rules/rules_evidence_calibrated_v19.yaml', 'rules/weights_evidence_calibrated_v16.yaml'), docs):
        target = ROOT / name
        content = '# Generated by benchmarks/build_linux_tool_policy.py; historical policies are unchanged.\n' + yaml.safe_dump(doc, sort_keys=False, width=120)
        if target.exists():
            if target.read_text() == content:
                continue
            print(f'*** Update File: {target}')
            for line in list(difflib.unified_diff(target.read_text().splitlines(), content.splitlines(), n=3))[2:]:
                print('@@' if line.startswith('@@') else line)
        else:
            print(f'*** Add File: {target}')
            for line in content.splitlines(): print('+' + line)
    print('*** End Patch')
