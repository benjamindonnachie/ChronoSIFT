"""Build v25: source, invocation, outcome and identity gates; weights unchanged."""
from pathlib import Path
import difflib
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
LOG = r'(?i)^(?:text/syslog_traditional|syslog|systemd_journal)$'
HISTORY = r'(?i)^(?:text/)?(?:bash_history|zsh_history|zsh_extended_history|cmd_history|powershell_history)$'
NATIVE = r'(?i)^(?:winevtx?|sysmon|linux:audit|auditd)(?:$|[/_:])'
ACCOUNT = r'^\s*(?:\[(?:useradd|usermod|groupadd|groupmod|adduser|addgroup)(?:,\s*pid:\s*\d+)?\]|(?:useradd|usermod|groupadd|groupmod|adduser|addgroup)\[\d+\]:)\s*\S'
AUTH_PREFIX = r'^\s*(?:(?:\[sshd(?:,\s*pid:\s*\d+)?\]|sshd\[\d+\]:)\s*)?'
AUTH_BODY = r'(?:Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+\S+\s+from\s+\S+|Failed\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?\S+\s+from\s+\S+|Invalid user\s+\S+\s+from\s+\S+|Successful login of user:\s*\S+\s+from\s+\S+\s+using authentication method:\s*\S+\s+ssh|pam_\w+\([^)]*\):\s*(?:authentication failure|session opened for user\s+\S+))'
AUTH_RECORD = '(?i)' + AUTH_PREFIX + AUTH_BODY
USER_HOME = r'(?:/root|/home/[^/]+)'
SSH_FILES = USER_HOME + r'/\.ssh/(?:authorized_keys2?|known_hosts|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?)'
WIN_PREFIX = r'(?:(?:[a-z]|ntfs):)?'
SENSITIVE = (r'^(?:/etc/(?:passwd|shadow|gshadow|sudoers|sudoers\.d/[^/]+)|' + SSH_FILES
    + '|' + USER_HOME + r'/(?:\.(?:bash|zsh|mysql|psql)_history|\.gnupg/(?:private-keys-v1\.d/[^/]+|secring\.gpg))'
    + r'|(?i:' + WIN_PREFIX + r'/windows/(?:system32/config/(?:sam|system|security)|repair/(?:sam|system)|ntds/ntds\.dit)))$')
PASSWORD = (r'^(?:' + USER_HOME + r'/\.(?:config/(?:google-chrome|chromium)/[^/]+/Login Data|mozilla/firefox/[^/]+/(?:key4\.db|logins\.json))'
    + r'|(?i:' + WIN_PREFIX + r'/users/[^/]+/appdata/(?:local/(?:google/chrome|microsoft/edge)/user data/[^/]+/login data|roaming/mozilla/firefox/profiles/[^/]+/(?:key4\.db|logins\.json)|(?:local|roaming)/microsoft/(?:credentials/[^/]+|vault/[^/]+/[^/]+)))'
    + r'|(?:/|[A-Za-z]:/)[^\r\n]+\.(?i:kdbx))$')


def atom(field, pattern):
    return dict(field=field, op='regex', value=pattern)


def rx(field, pattern):
    return dict(input=field, op='regex', pattern=pattern)


def invocation(pattern):
    return rx('invocations', r'(?im)^(?:' + pattern + r')(?:\s|$)')


def build():
    doc = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v24.yaml').read_text())
    normal = doc['normalisation']
    by_name = {spec['name']: spec for spec in normal}
    by_name['evidence_history_command']['selector']['pattern'] = HISTORY
    # No arbitrary message/actor_cmd fallback. Native command fields and actual
    # history records establish attempts, not their outcome. Sudo denial keeps
    # its existing separate attempt route and must not become execution.
    by_name['evidence_execution_command'].update(cases=[
        dict(field='linux_sudo_detail', pattern='.+', fields=['linux_sudo_allowed_command']),
        dict(field='parser', pattern=HISTORY, fields=['command_line', 'command', 'evidence_history_command']),
        dict(field='parser', pattern=NATIVE, fields=['command_line', 'command', 'evidence_powershell_host_command']),
    ], default_fields=['linux_cron_command'])
    index = normal.index(by_name['evidence_execution_command']) + 1
    normal[index:index] = [dict(name='evidence_invocation_commands', method='command_invocations',
        **{'from': 'evidence_execution_command'}, wrappers=[
            r'(?s)^(?:sudo\s+(?:(?:-u|-g)\s+\S+\s+|-[nEHSk]\s+)*|nohup\s+|env\s+(?:[A-Za-z_]\w*=[^\s]+\s+)*)(?P<command>.+)$',
            r'(?s)^(?:[A-Za-z_]\w*=[^\s]+\s+)+(?P<command>.+)$',
        ], scripts=[
            r'(?is)^(?:sh|bash|dash|ksh|zsh)\s+-[a-z]*c\s+(?P<command>.+)$',
            r'(?is)^cmd(?:\.exe)?\s+/[ck]\s+(?P<command>.+)$',
            r'(?is)^(?:powershell|pwsh)(?:\.exe)?\s+(?:-noprofile\s+|-noninteractive\s+)*-command\s+(?P<command>.+)$',
        ])]
    normal.extend([
        dict(name='evidence_collection_command', method='regex_first', **{'from':'evidence_invocation_commands'},
            pattern=r'(?im)^(?:cp|copy|xcopy|robocopy|mv|move|copy-item|tar|zip|7z|rar|scp|rsync)(?:\.exe)?\s+[^\r\n]+$', group=0),
        dict(name='evidence_upload_reference', method='regex_first', **{'from':'evidence_invocation_commands'},
            pattern=r'''(?im)^curl(?:\.exe)?\s+[^\r\n]*?(?:--upload-file|-T)\s+("[^"\r\n]+"|'[^'\r\n]+'|[^\s]+)''', group=1),
        dict(name='evidence_account_operation_log', method='regex_first', **{'from':'message'}, pattern=ACCOUNT, group=0, selector=dict(field='parser',pattern=LOG)),
        dict(name='evidence_account_removal_log', method='regex_first', **{'from':'message'}, pattern=r'^\s*(?:\[userdel(?:,\s*pid:\s*\d+)?\]|userdel\[\d+\]:)\s*\S[^\r\n]*$', group=0, selector=dict(field='parser',pattern=LOG)),
        dict(name='evidence_auth_record', method='regex_first', **{'from':'message'}, pattern=AUTH_RECORD + r'[^\r\n]*$', group=0, selector=dict(field='parser',pattern=LOG)),
    ])
    ssh = doc['canonicalisation']['ssh_authentication']
    ssh['selector'].update(match='all', message_regex=r'(?i)^\s*(?:\[sshd(?:,\s*pid:\s*\d+)?\]|sshd\[\d+\]:|Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+|Failed\s+(?:password|publickey)\s+for\s+|Invalid user\s+\S+\s+from\s+|Successful login of user:)')
    # Keep group numbers of existing formats; anchor the previously broad body
    # search by the same provider/format gate above. No document can seed state.

    atomic = {rule['id']: rule for rule in doc['rules']}
    for name, pattern in [
        ('INTERPRETER_EXEC_LINUX', r'(?:python(?:[0-9.]+)?|perl|php[0-9.]*|ruby|bash|dash|ksh|zsh|sh)'),
        ('LOLBIN_LINUX_EXEC', r'(?:curl|wget|nc|netcat|ncat|socat|bash|sh|python(?:[0-9.]+)?|perl|php[0-9.]*|ruby|openssl|base64|tar|zip|rsync|scp|sftp)'),
        ('LOLBIN_WINDOWS_EXEC', r'(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|schtasks)(?:\.exe)?'),
    ]:
        rule = atomic[name]
        rule['scope'] = dict(any=[], all=[])
        rule['when'] = dict(any=[], all=[atom('evidence_invocation_commands', '(?im)^'+pattern+r'(?:\s|$)')])
        rule['emit']['evidence'].append(dict(field='evidence_invocation_commands'))
        rule['description'] = 'Source-qualified literal executable invocation; names in arguments or documents do not qualify; success unproved'
    # Program-use metadata may identify the executable without a command line.
    atomic['LOLBIN_WINDOWS_EXEC']['when'] = dict(any=[
        atomic['LOLBIN_WINDOWS_EXEC']['when']['all'][0],
        atom('evidence_native_execution_path', r'(?i)(?:^|[/\\])(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|schtasks)\.exe$'),
    ], all=[])
    rule = atomic['ACCOUNT_CHANGE_LINUX']
    rule['scope'] = dict(any=[], all=[])
    rule['when'] = dict(any=[atom('evidence_invocation_commands', r'(?m)^(?:useradd|usermod|groupadd|groupmod|adduser|addgroup)(?:\s|$)'),
        atom('evidence_account_operation_log', '.+')], all=[])
    rule['description'] = 'Account/group operation or attempt recorded; failed invocations are not asserted successful'
    for name in ('DATA_TRANSFER_TOOL_EXEC','DATA_TRANSFER_TOOL_EXEC_FALLBACK'):
        rule = atomic[name]
        rule['scope'] = dict(any=[], all=[])
        rule['when'] = dict(any=[], all=[atom('evidence_invocation_commands',
            r'(?im)^(?:ftp|scp|sftp|rsync|curl|wget|nc|netcat|ncat|socat|bitsadmin|certutil|powershell|pwsh)(?:\.exe)?\s+[^\r\n]*(?:https?://|ftp://|sftp://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)')])
        rule['emit']['evidence'].append(dict(field='evidence_invocation_commands'))
        rule['description'] = 'Source-qualified transfer-tool invocation with remote operand; attempt, not proof of transferred bytes'
    atomic['LARGE_ARCHIVE_CREATED']['when']['all'].append(atom('timestamp_desc',r'(?i)(?:creat|birth)'))
    atomic['LARGE_ARCHIVE_CREATED']['description'] = 'Large archive has a creation timestamp; contents and collection intent remain unproved'
    for name, outcome in [('AUTH_FAIL_GENERIC','failure'),('AUTH_SUCCESS_GENERIC','success')]:
        rule = atomic[name]
        words = r'(?i)(?:failed|failure|invalid user)' if outcome=='failure' else r'(?i)(?:accepted|successful login|session opened)'
        rule['scope'] = dict(any=[], all=[])
        rule['when'] = dict(any=[dict(field='auth_outcome',op='eq',value=outcome),atom('evidence_auth_record',words)],all=[])
        rule['description'] = 'Structured authentication outcome or source-qualified authentication record; no free-text fallback'
    for name in ('SSH_FAIL_LINUX','SSH_SUCCESS_LINUX'):
        if name in atomic:
            atomic[name]['scope'] = dict(any=[],all=[atom('auth_protocol',r'^ssh$')])

    detectors = doc['detector_policy']['detectors']
    lifecycle = detectors['file_lifecycle']
    lifecycle['classification']['path_regex'] = dict(web_root=by_name['evidence_web_file_relative']['pattern'],sensitive=SENSITIVE)
    lifecycle['conditions']['row_emissions']['database_dump_candidate']['derived_predicates'].append('web_root')
    lifecycle['emissions']['database_dump_candidate']['description'] = 'New database/dump-like file under an explicitly configured web root; potential exposure candidate, not proof of database dumping or a Luhn hit'
    lifecycle['emissions']['database_dump_candidate'].update(attack_ids=[],attack_basis='unmapped',attack_note='A web-root filename/extension supports review for possible exposure, not database collection or exfiltration. Independent content and HTTP evidence remain separate.')
    classifier = detectors['execution_context_classifier']
    classifier['inputs']['command']['fields'] = ['evidence_invocation_commands']
    classifier['classification'].update(command_match_mode='invocation_heads',
        suid_regex=r'(?m)^chmod\s+(?:(?:-R|--recursive|--verbose|--changes)\s+)*(?:0?[234567][0-7]{3}|(?:[ugoa]*[+=][rwxXst]*s[rwxXst]*)(?:,[ugoa]*[+=-][rwxXst]*)*)\s+\S')
    classifier['emissions']['new_suid_binary']['description'] = 'Literal chmod attempts to set set-user/group-ID permission bits; ownership-only changes do not qualify; success and later execution are unproved (ATT&CK T1548.001)'
    classifier['emissions']['new_suid_binary']['attack_basis'] = 'attempted_behaviour'

    persistence = detectors['persistence_configuration']
    direct = detectors['direct_attack_semantics']
    for detector in (persistence,direct):
        detector['inputs'].setdefault('parser',dict(resolver='row_field',fields=['parser'],normalise='none'))
        detector['inputs']['invocations'] = dict(resolver='row_field',fields=['evidence_invocation_commands'],normalise='none')
        detector['evidence']['invocations'] = dict(resolver='input',input='invocations',max_chars=500)
    for role, field in [('provider','provider_name'),('account_created_name','linux_account_created_name')]:
        persistence['inputs'][role] = dict(resolver='row_field',fields=[field],normalise='none')
    pr = {r['id']:r for r in persistence['ordered_rules']}
    pr['defender_standalone_message']['when'] = dict(all=[rx('parser',r'(?i)^winevt'),
        rx('provider',r'(?i)^Microsoft-Windows-Windows Defender$'),rx('event_identifier',r'^5001$')])
    pr['defender_standalone_message']['description'] = 'Defender provider records real-time protection disabled (event 5001); arbitrary phrases or filenames do not qualify'
    pr['account_created_message']['when'] = rx('account_created_name',r'.+')
    pr['account_created_message']['description'] = 'Structured Linux new-user record; an unsuccessful useradd invocation does not prove creation'
    # T1484.001: effective local/domain policy locations, not a folder called policies.
    pr['group_policy_path_change']['when']['all'][0] = rx('path_lower',r'^(?:'+WIN_PREFIX+r'/windows/(?:system32/grouppolicy(?:users)?/|sysvol/(?:sysvol/[^/]+/)?policies/)|/(?:software|hkey_local_machine/software|hklm/software)/policies/).+')
    for name, pattern in [
        ('cron_path_change',r'^/(?:etc/(?:crontab|anacrontab|cron\.(?:d|daily|hourly|monthly|weekly)/.+)|var/spool/cron/.+)$'),
        ('service_configuration_path_change',r'^(?:/(?:etc|lib|usr/lib)/systemd/system/.+|/etc/init\.d/.+|(?:/hkey_local_machine|/hklm)?/system/currentcontrolset/services/.+)$'),
        ('firewall_path_change',r'^/etc/(?:firewalld/.+|ufw/.+|sysconfig/iptables|iptables/.+)$'),
    ]:
        pr[name]['when']['all'][0] = rx('path_lower',pattern)
    pr['firewall_message_change']['when'] = dict(all=[rx('parser',LOG),rx('message',r'(?i)^\s*(?:\[(?:firewalld|iptables|ufw)(?:,\s*pid:\s*\d+)?\]|(?:firewalld|iptables|ufw)(?:\[\d+\])?:)\s*(?:firewall\s+)?(?:disabled|rule (?:added|deleted|changed))\b')])

    dr = {r['id']:r for r in direct['ordered_rules']}
    for name, pattern in [('authorized_keys_root_change',r'^/root/\.ssh/authorized_keys2?$'),
        ('authorized_keys_nonroot_change',r'^/home/[^/]+/\.ssh/authorized_keys2?$')]:
        dr[name]['when'] = dict(all=[rx('path',pattern),dr[name]['when']['all'][-1]])
    command_patterns = {
        'inhibit_recovery_command': r'(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)|bcdedit(?:\.exe)?\s+/set\s+(?:\{[^}]+\}\s+)?(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|reagentc(?:\.exe)?\s+/disable)',
        'credential_dump_command': r'(?:procdump(?:64)?(?:\.exe)?\s+[^\r\n]*\blsass(?:\.exe)?\b|rundll32(?:\.exe)?\s+[^\r\n]*comsvcs\.dll\s*,\s*MiniDump\s+\d+\s+\S+|ntdsutil(?:\.exe)?\s+[^\r\n]*\bifm\b|reg(?:\.exe)?\s+save\s+hklm[\\/](?:sam|system|security)|(?:mimikatz|pypykatz)(?:\.exe)?\s+[^\r\n]*\bsekurlsa::\S+)',
        'cleanup_command': r'(?:wevtutil(?:\.exe)?\s+cl\s+\S+|history\s+-c|rm\s+(?:-[a-z]+\s+)*(?:~?/)?\.bash_history|truncate\s+-s\s+0\s+\S+|shred\s+\S+|sdelete(?:\.exe)?\s+\S+|clear-eventlog\s+\S+)',
        'service_stop_command': r'(?:(?:sc|net)(?:\.exe)?\s+stop\s+\S+|stop-service\s+\S+|taskkill(?:\.exe)?\s+/f\s+\S+|systemctl\s+stop\s+\S+)',
    }
    for name, pattern in command_patterns.items():
        dr[name]['when'] = invocation(pattern)
        dr[name]['evidence'].append('invocations')
        dr[name]['description'] += '; source-qualified invocation/attempt, not successful completion'
    # Filenames like lsass-notes/minidump-guide are not memory-dump evidence.
    # The file role can be supplied by an upstream extractor; observed command
    # semantics above remain available without this additional metadata.
    for role in ('artifact_type','target_process_name'):
        direct['inputs'][role] = dict(resolver='row_field',fields=[role],normalise='none')
        direct['evidence'][role] = dict(resolver='input',input=role)
    dr['credential_dump_artifact']['when'] = dict(all=[rx('artifact_type',r'^process_memory_dump$'),
        rx('target_process_name',r'(?i)^(?:.*[/\\])?lsass(?:\.exe)?$'),dr['credential_dump_artifact']['when']['all'][-1]])
    dr['credential_dump_artifact']['description'] = 'Upstream-identified process memory dump targets the credential service; arbitrary filename is insufficient'
    dr['credential_dump_artifact']['evidence'] += ['artifact_type','target_process_name']
    # This existing field is file-parser-qualified and separator-normalised,
    # but not lowercased or restricted to a web root despite its historical name.
    direct['inputs']['password_path'] = dict(resolver='row_field',fields=['evidence_web_file_slashes'],normalise='none')
    dr['password_store_artifact']['when']['all'][0] = rx('password_path',PASSWORD)
    dr['password_store_artifact']['description'] = 'Recognised credential-container location/format accessed or changed; generic vault/credentials names are insufficient'
    # Require a credential path operand in a real copying/archiving invocation.
    # The exact full-path follow-on gate below supplies subsequent linkage.
    for role, field in [('collection_command','evidence_collection_command'),('upload_reference','evidence_upload_reference')]:
        direct['inputs'][role] = dict(resolver='row_field',fields=[field],normalise='none')
        direct['evidence'][role] = dict(resolver='input',input=role,max_chars=500)
    dr['password_store_copy_or_stage']['when'] = dict(any=[
        rx('collection_command',r'''(?i)(?:^|\s|["'])(?:/[^\r\n"']+\.kdbx|/(?:root|home/[^/]+)/\.(?:config/(?:google-chrome|chromium)/[^/]+/Login Data|mozilla/firefox/[^/]+/(?:key4\.db|logins\.json)))(?:["']|\s|$)'''),
        rx('upload_reference',r'''(?i)^["']?(?:/|[a-z]:[/\\])[^\r\n"']+\.kdbx["']?$''')])
    dr['password_store_copy_or_stage']['evidence'] += ['collection_command','upload_reference']
    # Preserve structured Windows removal plus actual Linux attempt/outcome.
    direct['inputs']['linux_changed_account'] = dict(resolver='row_field',fields=['evidence_account_removal_log'],normalise='none')
    dr['other_account_access_removal']['when'] = dict(any=[
        dict(all=[rx('parser',r'(?i)^winevt'),rx('event_identifier',r'^(?:4729|4733|4757)$')]),
        invocation(r'userdel\s+\S+'),rx('linux_changed_account',r'.+'),
    ])
    dr['other_account_access_removal']['description'] = 'Structured membership/account removal record or source-qualified deletion attempt; invocation alone does not prove removal'
    dr['other_account_access_removal']['evidence'].append('invocations')
    # Discovery and other command consumers use the same admitted invocation
    # field, while unrelated HTTP/application-protocol hints remain unchanged.
    direct['inputs']['discovery_command']['fields'] = ['evidence_invocation_commands']
    adjust = detectors['contextual_signal_adjustments']
    adjust['ordered_rules'] = [rule for rule in adjust['ordered_rules'] if rule['id']!='benign_backup_archive_dampening']
    for name in ('credential_dump_collection','password_store_exfil_chain'):
        chain = detectors[name]
        chain['identity_mode'] = 'full_path'
        chain['inputs']['combined_text']['fields'] = ['evidence_collection_command','evidence_upload_reference']
        chain['follow_on']['allow_unlabelled'] = False
        chain['follow_on']['any_signals'].append('exec_archive_tool')
        chain['emissions'][0]['description'] += '; later source-qualified operation explicitly references the same full file path, not a shared name fragment'
    return doc


def render():
    from benchmarks.build_attack_metadata_policy import matrix
    doc = build()
    return {'rules/rules_evidence_calibrated_v25.yaml':
        '# Generated by benchmarks/build_semantic_evidence_policy.py; historical policies preserved.\n'
        '# Source/operation/outcome/identity gates. Weights v21 unchanged. See docs/SEMANTIC_EVIDENCE.md.\n'
        + yaml.safe_dump(doc, sort_keys=False, width=120),
        'docs/ATTACK_MATRIX_V25.md': matrix(doc,25)}


if __name__=='__main__':
    import sys
    sys.path.insert(0,str(ROOT))
    print('*** Begin Patch')
    for name, content in render().items():
        path = ROOT/name
        if not path.exists():
            print('*** Add File: '+str(path)); print('\n'.join('+'+line for line in content.splitlines()))
        elif path.read_text()!=content:
            print('*** Update File: '+str(path))
            for line in list(difflib.unified_diff(path.read_text().splitlines(),content.splitlines(),n=3))[2:]:
                print('@@' if line.startswith('@@') else line)
    print('*** End Patch')
