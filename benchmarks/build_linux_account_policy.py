"""Generate v20/v18: SUID artefact severity and bounded Linux account context.

No ground-truth accounts, IPs, hashes or filenames. Presence is not execution;
same-host chronology is not an observed creator/session relationship.
"""
from pathlib import Path
import difflib
import re
import yaml

ROOT=Path(__file__).resolve().parents[1]
LOG=r'^(?:text/syslog_traditional|syslog|systemd_journal)$'
NAME=r'[A-Za-z_][A-Za-z0-9_.@$-]*'
PREFIX=r'(?:\[useradd,\s*pid:\s*\d+\]|\buseradd\[\d+\]:)\s*new user:\s*name='
BIRTH=PREFIX+rf'({NAME}),\s*UID=(\d+),\s*GID=\d+,'
CHANGE=rf'(?:\[(?:userdel|usermod),\s*pid:\s*\d+\]|\b(?:userdel|usermod)\[\d+\]:)\s*(?:delete user|change user(?: name)?)\s+[\x27\x22]({NAME})[\x27\x22]'

def regex(name, source, pattern, group=1, selector=None):
    d=dict(name=name,method='regex_first',**{'from':source},pattern=pattern,group=group)
    if selector: d['selector']=dict(field=selector[0],pattern=selector[1])
    return d

def atom(id, description, conditions, signals, fields, scope=LOG, confidence='medium'):
    return dict(id=id,description=description,priority=91,
        scope=dict(any=[],all=[dict(field='parser',op='regex',value=scope)]),
        when=dict(any=[],all=conditions),emit=dict(signals=[dict(name=s,value=1) for s in signals],
        evidence=[dict(field=f) for f in fields]),confidence=confidence)

def cond(field,op='exists',value=None):
    return dict(field=field,op=op,**({'value':value} if value is not None else {}))

def sequence(name,source,target,key,lookback,priority,description,reset=False):
    r=dict(id=name.upper(),description=description,priority=priority,key_by=[key],
        lookback=lookback,lookback_lower_bound='inclusive',emit_on='sequence_completion',
        minimum_signal_value_exclusive=0,include_supporting_rows=True,
        sequence=[dict(signal=s,min_count=1) for s in (source,target)],
        emit=dict(signals=[dict(name=name,value=1)]),confidence='medium')
    if reset:r['reset_signals']=['linux_account_created','linux_account_lifecycle_reset']
    return r

def build():
    r=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v19.yaml').read_text())
    w=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v17.yaml').read_text())
    privileged=next(x for x in r['rules'] if x['id']=='PRIV_LOGIN')['when']['any'][0]['value']
    ssh_actor=r['canonicalisation']['ssh_authentication']['outputs']['actor_user_auth']
    # Separate affected-account fields; never replace actor_user with the child.
    r['normalisation'] += [
        regex('linux_account_created_name','message',BIRTH,selector=('parser',LOG)),
        regex('linux_account_created_uid','message',BIRTH,group=2,selector=('parser',LOG)),
        regex('linux_account_changed_name','message',CHANGE,selector=('parser',LOG)),
        regex('linux_auth_account',ssh_actor,rf'^({NAME})$',selector=('auth_protocol',r'^ssh$')),
        dict(name='linux_account_target',method='coalesce',fields=['linux_account_created_name','linux_account_changed_name','linux_auth_account'],overwrite_existing=True),
        regex('linux_account_scope','continuity_scope',r'^(.+)$',selector=('parser',LOG)),
        dict(name='linux_account_key',method='join_fields',fields=['linux_account_scope','linux_account_target'],separator='|'),
        dict(name='linux_suid_bit',method='bitmask_any',**{'from':'mode'},mask=0o4000,number_format='strict_integer'),
        dict(name='linux_executable_bit',method='bitmask_any',**{'from':'mode'},mask=0o111,number_format='strict_integer'),
    ]
    facts=['message','linux_account_created_name','linux_account_created_uid','linux_account_changed_name',
           'linux_auth_account','linux_account_scope','linux_account_key',ssh_actor,'src_ip']
    r['rules'] += [
        atom('LINUX_ROOT_SUID_STAGING_FILE',
            'Root-owned SUID executable observed in a configured staging location; privilege-capable presence, not execution (ATT&CK T1548.001)',
            [cond('file_entry_type','eq','file'),cond('owner_identifier','regex',r'^0(?:\.0+)?$'),
             cond('linux_suid_bit','eq','1'),cond('linux_executable_bit','eq','1'),
             cond('filename','regex',r'^/(?:tmp|var/tmp|dev/shm|var/spool|home|root)/[^\x00]+$')],
            ['linux_root_suid_staging_file'],['filename','mode','owner_identifier','file_entry_type','sha256_hash','timestamp_desc'],scope=r'^filestat$'),
        atom('LINUX_ACCOUNT_CREATED','Structured useradd completion identifies affected local account; creator not recorded (ATT&CK T1136.001)',
             [cond('linux_account_created_name'),cond('linux_account_created_uid')],['linux_account_created'],facts,confidence='high'),
        atom('LINUX_UID0_ACCOUNT_CREATED','Explicit creation of a UID-0 account; additive privilege severity above generic account change (ATT&CK T1136.001)',
             [cond('linux_account_created_name'),cond('linux_account_created_uid','eq','0')],['linux_uid0_account_created'],facts,confidence='high'),
        atom('LINUX_UID0_ALIAS_CREATED','UID-0 account outside configured privileged-name vocabulary; bounded later authentication candidate',
             [cond('linux_account_created_name'),cond('linux_account_created_uid','eq','0'),
              cond('linux_account_created_name','regex',r'(?i)^(?!(?:'+ '|'.join(re.escape(x) for x in privileged)+r')$).+$')],['linux_uid0_alias_created'],facts,confidence='high'),
        atom('LINUX_ACCOUNT_LIFECYCLE_RESET','Observed deletion or modification revokes prior name-keyed account context; no inferred current UID',
             [cond('linux_account_changed_name')],['linux_account_lifecycle_reset'],facts,confidence='high'),
        atom('LINUX_ACCOUNT_REMOTE_SUCCESS','Successful SSH authentication of a named account in a known host scope (ATT&CK T1078.003)',
             [cond('linux_auth_account'),cond('linux_account_key'),cond('auth_protocol','eq','ssh'),cond('auth_outcome','eq','success')],
             ['linux_account_remote_success'],facts,confidence='high'),
        atom('LINUX_PRIVILEGED_REMOTE_SUCCESS','Successful SSH access by a configured privileged account; host context only, not proof of a creating operator',
             [cond('linux_auth_account','in_ci',privileged),cond('linux_account_key'),cond('auth_protocol','eq','ssh'),cond('auth_outcome','eq','success')],
             ['linux_privileged_remote_success'],facts),
    ]
    r['temporal_rules'] += [
        sequence('linux_created_after_privileged_access','linux_privileged_remote_success','linux_account_created','linux_account_scope','1h',75,
            'Local account created within one hour after privileged SSH access on the same host; weak host-level association, creator/session/IP not attributed (ATT&CK T1136.001)'),
        sequence('linux_recent_account_use','linux_account_created','linux_account_remote_success','linux_account_key','7d',74,
            'Successful SSH use within seven days of observed local account creation; fixed creation-anchored window, not refreshed by use (ATT&CK T1078.003)',True),
        sequence('linux_recent_uid0_alias_login','linux_uid0_alias_created','linux_account_remote_success','linux_account_key','7d',74,
            'Successful SSH use of a recently observed UID-0 alias; adds the existing privileged-login and privileged-context equivalent, not operator attribution (ATT&CK T1078.003)',True),
        sequence('linux_recent_privileged_creation_use','linux_created_after_privileged_access','linux_account_remote_success','linux_account_key','7d',73,
            'Successful use of a recently created account carrying weak same-host privileged-access context; not creator-risk inheritance, no recursive or refreshed taint (ATT&CK T1078.003)',True),
    ]
    w['weights'].update(linux_root_suid_staging_file=24,linux_uid0_account_created=18,
        linux_recent_account_use=12,linux_recent_uid0_alias_login=11,
        linux_created_after_privileged_access=6,linux_recent_privileged_creation_use=6,
        linux_account_created=0,linux_uid0_alias_created=0,linux_account_lifecycle_reset=0,
        linux_account_remote_success=0,linux_privileged_remote_success=0)
    return r,w

def render():
    header=('# Generated by benchmarks/build_linux_account_policy.py; historical policy is preserved.\n'
        '# T1548.001 https://attack.mitre.org/techniques/T1548/001/ — presence is not execution.\n'
        '# T1136.001 https://attack.mitre.org/techniques/T1136/001/ — affected account is not creator.\n'
        '# T1078.003 https://attack.mitre.org/techniques/T1078/003/ — bounded local account use.\n'
        '# Exact weights and weak host-association limits: docs/LINUX_ACCOUNT_SCORING.md.\n')
    return {name:header+yaml.safe_dump(doc,sort_keys=False,width=120) for name,doc in zip(
        ('rules/rules_evidence_calibrated_v20.yaml','rules/weights_evidence_calibrated_v18.yaml'),build())}

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
