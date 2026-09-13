"""Build v21/v19 investigator-priority policy from immutable v20/v18.

Vocabulary, admission and weights are YAML-owned. ATT&CK describes behaviour,
not a compromise verdict; no ground-truth identifiers enter this policy.
"""
from pathlib import Path
import difflib
import re
import yaml
from benchmarks.build_linux_account_policy import atom, cond, regex, sequence, LOG

ROOT = Path(__file__).resolve().parents[1]
SUDO = (r'^\s*(?:\[sudo(?:,\s*pid:\s*\d+)?\]|sudo\[\d+\]:)\s*'
        r'([^\s:;]+)\s*:\s*(.+)$')
DETAIL = (r'TTY=([^;\r\n]+?)\s*;\s*PWD=(/[^;\r\n]*)\s*;\s*'
          r'USER=([^;\s]+)\s*;\s*COMMAND=([^\r\n]+)$')
DENIED = r'(?:user NOT in sudoers|command not allowed|user NOT authorized on host|[0-9]+ incorrect password attempts?)\s*;\s*'
XFER = (r'^([0-9]+)\s+(\S+)\s+([0-9]+)\s+(/[^\r\n]+?)\s+([ab])\s+(\S+)\s+'
        r'([io])\s+([agr])\s+(\S+)\s+(ftp)\s+([01])\s+(\S+)\s+([ci])\s*$')
ARCHIVE = r'(?i)\.(?:zip|7z|rar|tar|gz|tgz|bz2|xz)$'
STAGING = r'^/(?:tmp|var/tmp|dev/shm|home|root|var/spool)/[^\r\n]+$'


def build():
    r = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v20.yaml').read_text())
    w = yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v18.yaml').read_text())
    # T1548.003 https://attack.mitre.org/techniques/T1548/003/
    # Explicit denial never supplies execution fields; actor != run-as target.
    extra = [
        regex('linux_sudo_actor', 'message', SUDO, 1, ('parser', LOG)),
        regex('linux_sudo_detail', 'message', SUDO, 2, ('parser', LOG)),
        regex('linux_sudo_allowed_detail', 'linux_sudo_detail', '^('+DETAIL+')$', 1),
        regex('linux_sudo_denied_detail', 'linux_sudo_detail', '^'+DENIED+'('+DETAIL+')$', 1),
        dict(name='linux_sudo_known_detail', method='coalesce', fields=['linux_sudo_allowed_detail','linux_sudo_denied_detail'], overwrite_existing=True),
    ]
    for name, group in [('tty',1),('pwd',2),('runas',3),('command',4)]:
        extra.append(regex('linux_sudo_'+name,'linux_sudo_known_detail','^'+DETAIL,group))
    extra += [
        regex('linux_sudo_allowed_command','linux_sudo_command',r'^(.+)$',selector=('linux_sudo_allowed_detail',r'.+')),
        regex('linux_sudo_allowed_runas','linux_sudo_runas',r'^(.+)$',selector=('linux_sudo_allowed_detail',r'.+')),
        regex('linux_sudo_executable_quoted','linux_sudo_allowed_command',r'^"([^"\r\n]+)"(?:\s|$)'),
        regex('linux_sudo_executable_bare','linux_sudo_allowed_command',r'^([^\s"\x27]+)(?:\s|$)'),
        dict(name='linux_sudo_executable',method='coalesce',fields=['linux_sudo_executable_quoted','linux_sudo_executable_bare'],overwrite_existing=True),
        dict(name='linux_sudo_path',method='posix_path_resolve',**{'from':'linux_sudo_executable'},base_field='linux_sudo_pwd'),
    ]
    r['normalisation'][0:0] = extra
    for spec in r['normalisation']:
        if spec['name'] in ('actor_user','actor_principal'):
            spec['cases'].insert(0,dict(field='linux_sudo_detail',pattern=r'.+',fields=['linux_sudo_actor']))
        if spec['name']=='evidence_execution_source':spec['fields'].insert(0,'linux_sudo_path')
        if spec['name']=='evidence_execution_path':
            # A separate coalesce below admits only parsed allowed sudo paths.
            spec['name']='evidence_native_execution_path'
        if spec['name']=='evidence_execution_command':
            defaults=spec['fields']
            spec.clear()
            spec.update(name='evidence_execution_command',method='select_coalesce',
                cases=[dict(field='linux_sudo_detail',pattern=r'.+',fields=['linux_sudo_allowed_command'])],
                default_fields=defaults)
    pos=next(i for i,x in enumerate(r['normalisation']) if x['name']=='evidence_native_execution_path')+1
    r['normalisation'].insert(pos,dict(name='evidence_execution_path',method='coalesce',fields=['linux_sudo_path','evidence_native_execution_path'],overwrite_existing=True))
    r['normalisation'] += [
        dict(name='evidence_execution_actor',method='select_coalesce',
             cases=[dict(field='linux_sudo_detail',pattern=r'.+',fields=['linux_sudo_allowed_runas'])],
             default_fields=['actor_principal','actor_user']),
        dict(name='linux_sudo_account_key',method='join_fields',fields=['linux_account_scope','linux_sudo_actor'],separator='|'),
    ]
    # Reuse the existing execution context classification, with the actual
    # allowed run-as target. A root actor dropping privileges is not escalation.
    d=r['detector_policy']['detectors']
    # T1505.003: a script explicitly classified as a web shell by AV/YARA
    # should not need a suggestive filename. Self-reference is intentionally
    # excluded by file propagation, so admit these direct category signals.
    d['webshell_artifact']['conditions']['support']['signals_any'] += ['yara_webshell','av_webshell']
    d['execution_context_classifier']['inputs']['actor']['fields']=['evidence_execution_actor']
    d['execution_context_classifier']['emissions']['privileged_context']['description']='Execution or an allowed command was recorded in a privileged context; payload effects are not established'
    facts=['linux_sudo_actor','linux_sudo_runas','linux_sudo_pwd','linux_sudo_command','linux_sudo_path','linux_sudo_allowed_detail','linux_sudo_denied_detail']
    r['rules'] += [
        atom('LINUX_SUDO_ALLOWED','Sudo allowed the recorded command; successful payload effects are not established (ATT&CK T1548.003 context)',
             [cond('linux_sudo_allowed_detail')],['linux_sudo_allowed'],facts),
        atom('LINUX_SUDO_DENIED','Explicitly denied sudo command; concerning attempt, not execution (ATT&CK T1548.003 candidate)',
             [cond('linux_sudo_denied_detail'),cond('linux_sudo_runas','eq','root')],['linux_sudo_denied'],facts),
        atom('LINUX_SUDO_PRIVILEGED_WRITABLE','Sudo allowed root command from a configured writable/staging path; investigation priority without requiring AV or payload-success proof (ATT&CK T1548.003)',
             [cond('linux_sudo_allowed_detail'),cond('linux_sudo_runas','eq','root'),cond('linux_sudo_path','regex',STAGING)],
             ['linux_sudo_privileged_writable'],facts),
        atom('LINUX_SUDO_PRIVILEGED_COMMAND','Allowed root command by an identified actor; bounded recent-account context candidate (ATT&CK T1548.003)',
             [cond('linux_sudo_allowed_detail'),cond('linux_sudo_runas','eq','root'),cond('linux_sudo_account_key')],
             ['linux_sudo_privileged_command'],facts),
    ]
    # Same actor, same host; creation-anchored and revoked by lifecycle change.
    # Use a shared key on creation and sudo rows without altering actor roles.
    r['normalisation'] += [dict(name='linux_behaviour_account_key',method='coalesce',fields=['linux_sudo_account_key','linux_account_key'],overwrite_existing=True)]
    r['temporal_rules'].append(sequence('linux_recent_account_sudo','linux_account_created','linux_sudo_privileged_command',
        'linux_behaviour_account_key','7d',72,'Allowed root command by a recently created local account; exact scoped actor, no IP or creator attribution (ATT&CK T1548.003 / T1078.003)',True))

    # Xferlog fields are protocol observations. Incoming archive is not
    # automatically exfiltration; incomplete outgoing attempts still matter.
    # T1048.003 https://attack.mitre.org/techniques/T1048/003/
    # T1105 https://attack.mitre.org/techniques/T1105/ (qualified payload only).
    r['normalisation'] += [dict(name='ftp_log_text',method='coalesce',fields=['text','message'],overwrite_existing=True)]
    ftp_fields=['duration','remote_host','bytes','path','type','action','direction','access','account','service','auth_method','auth_user','outcome']
    for group,name in enumerate(ftp_fields,1):
        r['normalisation'].append(regex('ftp_'+name,'ftp_log_text',XFER,group,('parser',r'^text/vsftpd$')))
    ftp_facts=['ftp_'+n for n in ftp_fields]
    for id,desc,conditions,signals in [
        ('FTP_TRANSFER_OBSERVED','Parsed FTP transfer record; direction and completion retained, not a compromise verdict',[],['ftp_transfer_observed']),
        ('FTP_ARCHIVE_TRANSFER','Archive transfer warrants investigator review even if incomplete; collection/transfer candidate (ATT&CK T1074.001 context)',[cond('ftp_path','regex',ARCHIVE)],['ftp_archive_transfer']),
        ('FTP_OUTGOING_ARCHIVE','Outgoing archive transfer or attempt from this server; possible unencrypted exfiltration, authorisation and sensitivity not proved (ATT&CK T1048.003 candidate)',[cond('ftp_direction','eq','o'),cond('ftp_path','regex',ARCHIVE)],['ftp_outgoing_archive']),
        ('FTP_COMPLETED_ARCHIVE','FTP reports completed archive transfer; completion supports but does not prove malicious intent',[cond('ftp_outcome','eq','c'),cond('ftp_path','regex',ARCHIVE)],['ftp_completed_archive']),
    ]:
        r['rules'].append(atom(id,desc,[cond('ftp_path'),*conditions],signals,ftp_facts,scope=r'^text/vsftpd$'))

    # T1574.006 https://attack.mitre.org/techniques/T1574/006/
    # A real system loader control path, not a challenge-specific library name.
    r['rules'].append(atom('LINUX_PRELOAD_CONTROL_CHANGE',
        'System-wide dynamic-loader preload control created or modified; high-priority hijacking candidate even without AV, contents and malicious use not established (ATT&CK T1574.006)',
        [cond('filename','eq','/etc/ld.so.preload'),cond('file_entry_type','eq','file'),
         cond('timestamp_desc','regex',r'(?i)^(?:Creation|Content Modification|Modification|Metadata Modification) Time$')],
        ['linux_preload_control_change'],['filename','timestamp_desc','owner_identifier','mode','sha256_hash'],scope=r'^filestat$'))

    # Credential-dumping tools are T1003, not a database export because the
    # executable name contains 'dump'. Genuine export extensions remain valid.
    life=d['file_lifecycle']['classification']['derived_predicates']
    rebuilt={}
    for name,value in life.items():
        if name=='database_dump':
            rebuilt['named_dump_archive']=dict(all=['archive_extension','database_dump_basename'],any=[],none=[])
            value=dict(all=[],any=['database_dump_extension','named_dump_archive'],none=[])
        rebuilt[name]=value
    d['file_lifecycle']['classification']['derived_predicates']=rebuilt

    # Administrative code-edit request is independently useful for triage.
    # T1505.003 https://attack.mitre.org/techniques/T1505/003/ candidate only;
    # POST/redirect does not establish authentication, saved content or a shell.
    direct=d['direct_attack_semantics']
    def pred(name,op,value):return dict(input=name,op=op,**({'pattern':value} if op=='regex' else {'values':value}))
    def direct_rule(name,conditions,description):
        direct['ordered_rules'].append(dict(id=name,when=dict(all=conditions),emission=name,description=description,
            confidence='medium',evidence=['web_target','web_method','web_status','linked_web_file']))
        direct['emissions'][name]=dict(name=name,value=1,rule_id=name.upper(),description=description,confidence='medium')
    direct_rule('web_admin_code_edit_attempt',[
        pred('web_method','equals_any',['post']),
        pred('web_target','regex',r'(?i)^/(?:[^/?#]+/)*wp-admin/(?:theme|plugin)-editor\.php(?:\?|$)')],
        'Administrative web-code edit POST warrants review, including rejected attempts; not proof of saved content or web-shell deployment (ATT&CK T1505.003 candidate)')
    w['weights'].update(linux_sudo_allowed=0,linux_sudo_denied=8,linux_sudo_privileged_writable=14,
        linux_sudo_privileged_command=0,linux_recent_account_sudo=12,
        ftp_transfer_observed=2,ftp_archive_transfer=10,ftp_outgoing_archive=8,ftp_completed_archive=3,
        linux_preload_control_change=24,web_admin_code_edit_attempt=12)
    return r,w


def render():
    header=('# Generated by benchmarks/build_behaviour_policy.py; historical policy preserved.\n'
        '# Human-review priority is distinct from proof of compromise.\n'
        '# ATT&CK links, exact weights and outcome limits: docs/BEHAVIOURAL_SCORING.md.\n')
    return {name:header+yaml.safe_dump(doc,sort_keys=False,width=120) for name,doc in zip(
        ('rules/rules_evidence_calibrated_v21.yaml','rules/weights_evidence_calibrated_v19.yaml'),build())}


if __name__=='__main__':
    print('*** Begin Patch')
    for name,content in render().items():
        p=ROOT/name
        if not p.exists():
            print('*** Add File: '+str(p));print('\n'.join('+'+s for s in content.splitlines()))
        elif p.read_text()!=content:
            print('*** Update File: '+str(p))
            for line in list(difflib.unified_diff(p.read_text().splitlines(),content.splitlines(),n=3))[2:]:
                print('@@' if line.startswith('@@') else line)
    print('*** End Patch')
