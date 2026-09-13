"""Emit an apply_patch document for the versioned Windows policy candidate.

Mechanical YAML transformation only; stdout is applied with apply_patch.
The prior policy pair remains immutable. See docs/WINDOWS_SCORING_DESIGN.md.
"""
from pathlib import Path
import difflib
import yaml

ROOT = Path(__file__).resolve().parents[1]
r = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v12.yaml').read_text())
w = yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v11.yaml').read_text())
d = r['detector_policy']['detectors']

def regex(name, source, pattern, selector=None):
    entry = dict(name=name, method='regex_first', **{'from':source}, pattern=pattern, group=1)
    if selector:
        entry['selector'] = dict(field=selector[0], pattern=selector[1])
    return entry

def coalesce(name, *fields, overwrite=False):
    return dict(name=name, method='coalesce', fields=list(fields), **({'overwrite_existing':True} if overwrite else {}))

def lookup(name, source, key, value):
    return dict(name=name, method='identity_lookup', **{'from':source}, key_field=key, value_field=value)

win = r['canonicalisation']['windows_authentication']
for name, aliases in {
    'win_target_sid':['TargetUserSid','TargetSid'],
    'win_member_sid':['MemberSid'],
    'win_subject_sid':['SubjectUserSid'],
    'win_task_user':['UserContext'],
    'win_task_name':['TaskName'],
    'win_action_name':['ActionName','ProcessPath','ApiCallerName'],
}.items():
    win['fields'].append(dict(id=name, output_field=name, event_data_aliases=aliases, system_source='none'))

r['normalisation'] += [
    regex('win_event_id', 'event_identifier', r'^\s*(\d+)(?:\.0+)?\s*$', ('parser',r'(?i)^winevt')),
    regex('win_task_account', 'win_task_user', r'(?:^|\\)([^\\]+)$'),
    regex('win_message_executable', 'message', r'(?i)(\\{1,2}Device\\{1,2}HarddiskVolume\d+\\[^\r\n\]\x27\x22]+?\.exe)', ('parser',r'(?i)^(winevt|winreg/bam|esedb/srum)')),
    coalesce('win_evidence_path','application','path','new_process_name','win_action_name','win_message_executable','filename','display_name'),
    regex('win_profile_account','win_evidence_path',r'(?i)[\\/]+Users[\\/]+([^\\/]+)[\\/]'),
    # Null/unknown SIDs from failed authentication are not identity seeds.
    # https://attack.mitre.org/techniques/T1078/ — account identity, not operator.
    regex('win_identity_sid','win_target_sid',r'(?i)^(S-1-5-21-(?:\d+-){3}\d+)$'),
    lookup('win_task_sid','win_task_account','target_user_name','win_identity_sid'),
    lookup('win_profile_sid','win_profile_account','target_user_name','win_identity_sid'),
    coalesce('win_direct_sid','win_member_sid','win_target_sid','win_subject_sid','user_identifier','win_task_sid',overwrite=True),
    coalesce('win_context_sid','win_direct_sid','win_profile_sid',overwrite=True),
    regex('win_asset_id','pathspec',r'(?i)"location"\s*:\s*"([^\x22]+\.(?:E01|raw|dd|img|vmdk))"'),
    regex('win_login_ip','ip_address',r'^(.+)$',('win_event_id',r'^(4624|1149)$')),
    # Entire volume-relative path, never basename matching. This is a
    # candidate alias, not proof of the device-to-volume mapping.
    regex('win_exec_relative_path','win_evidence_path',r'(?i)^\\+Device\\+HarddiskVolume\d+(\\.+)$',('parser',r'(?i)^(winevt|winreg/bam|esedb/srum)')),
    # Explicit executed-file hash contract, never the hash of BAM/SRUM/EVTX.
    regex('win_av_file_hash','sha256_hash',r'(?i)^([0-9a-f]{64})$',('av_hit',r'(?i)^(true|1(?:\.0)?)$')),
    lookup('win_executed_av_hash','chronosift_executed_sha256','win_av_file_hash','win_av_file_hash'),
]

# Keep event identifiers in the evidence untouched; ordered rules use a
# separate canonical numeric-text field. Atomic numeric comparisons already
# accept numbers. Source/provider checks prevent unrelated event-ID collisions.
for detector in ('persistence_configuration','direct_attack_semantics'):
    d[detector]['inputs']['event_identifier']['fields'] = ['win_event_id']
p = d['persistence_configuration']
for row in p['ordered_rules']:
    if row['id'] == 'defender_registry_value_change':
        row['when'] = {'all':[
            {'input':'parser_lower','op':'starts_with_any','values':['winreg']},
            {'input':'message_lower','op':'regex','pattern':r'(?i)\b(?:disableantispyware|disablerealtimemonitoring)\s*[:=]\s*(?:\[reg_dword(?:_le)?\]\s*)?(?:0x0*1|1)(?![0-9a-f])'},
        ]}
        row['description'] = 'Defender disabling value 1 observed; registry timestamp does not identify the actor (ATT&CK T1685)'
        row['confidence'] = 'medium'
    if row['id'] in ('account_created_event','privileged_group_addition'):
        row['when'] = {'all':[row['when'], {'input':'parser_lower','op':'starts_with_any','values':['winevt']}]}

direct = d['direct_attack_semantics']
for name, field in {
    'win_source':'source_name','win_path':'win_evidence_path',
    'win_sid':'win_context_sid','win_direct_sid':'win_direct_sid',
    'win_task':'win_task_name','win_type':'data_type','win_event':'win_event_id',
    'win_filesystem':'file_system_type',
    'win_executed_av_hash':'win_executed_av_hash',
    'content_type':'chronosift_sensitive_content_type','content_verified':'chronosift_sensitive_content_verified',
    'transfer_direction':'chronosift_transfer_direction','transfer_outcome':'chronosift_transfer_outcome',
    'transfer_bytes':'chronosift_transfer_bytes',
}.items():
    direct['inputs'][name] = dict(resolver='row_field',fields=[field],normalise='lower')
    direct['evidence'][name] = dict(resolver='input',input=name)

def pred(name, op, values):
    return dict(input=name,op=op,**({'pattern':values} if op=='regex' else {'values':values}))

def signals(*names):
    return dict(op='signal_any_positive', signals=list(names), minimum_value_exclusive=0)

def add(name, when, description, confidence='medium', emission=None):
    signal = emission or name
    direct['ordered_rules'].append(dict(id=name,when=when,emission=signal,description=description,
        confidence=confidence,evidence=['win_path','win_sid','win_direct_sid','win_task','message','win_event']))
    direct['emissions'][signal] = dict(name=signal,value=1,rule_id=signal.upper(),description=description,confidence=confidence)

windows = {'any':[pred('parser_lower','regex',r'^(?:winevt|winreg|esedb/srum|mft|usnjrnl)'),
    {'all':[pred('parser_lower','equals_any',['filestat']),{'any':[
        pred('win_path','regex',r'(?i)^(?:[a-z]:)?\\'),pred('win_filesystem','equals_any',['ntfs','fat','fat32'])]}]}]}
execution = {'any':[
    pred('win_type','equals_any',['windows:srum:application_usage','windows:registry:bam']),
    {'all':[pred('parser_lower','contains_any',['userassist']),pred('timestamp_desc','regex',r'(?i)execut|run')]},
    {'all':[pred('win_source','equals_any',['microsoft-windows-kernel-power']),pred('win_event','equals_any',['187'])]},
    {'all':[pred('win_source','equals_any',['microsoft-windows-security-auditing']),pred('win_event','equals_any',['4688'])]},
]}
created = {'any':[pred('timestamp_kind','equals_any',['create']),pred('message','contains_any',['USN_REASON_FILE_CREATE'])]}
add('windows_program_execution',execution,'Windows execution/use artefact observed; does not establish successful payload effects')
add('windows_psexec_execution',{'all':[execution,pred('win_path','regex',r'(?i)[\\/]psexec(?:64)?\.exe$')]},
    'PsExec use observed; remote target execution requires further evidence (ATT&CK T1569.002/T1021.002)')
add('windows_task_registered',{'all':[{'not':signals('persistence_scheduled_task')},{'any':[
    {'all':[pred('win_source','equals_any',['microsoft-windows-taskscheduler']),pred('win_event','equals_any',['106'])]},
    {'all':[pred('win_source','equals_any',['microsoft-windows-security-auditing']),pred('win_event','equals_any',['4698'])]},
]}]},'Windows task registration observed, not successful task action (ATT&CK T1053.005)')
add('windows_task_action_attempt',{'all':[
    pred('win_source','equals_any',['microsoft-windows-taskscheduler']),pred('win_event','equals_any',['200','201','203']),
    pred('message','regex',r'(?i)[\\/]psexec(?:64)?\.exe'),
]},'Scheduled PsExec action attempt/result; success is not inferred from event 201 (ATT&CK T1053.005/T1569.002)')
add('windows_archive_created',{'all':[windows,created,pred('win_path','regex',r'(?i)\.(?:zip|7z|rar|cab)$')]},
    'Archive creation observed, including USN FILE_CREATE; a basename is not used for identity or author attribution (ATT&CK T1560 candidate)')
add('windows_ftp_activity',{'all':[windows,pred('combined_text','regex',r'(?i)ftp://(?:[^\s/@]+@)?[^\s/]+|\\+FTP\\+Accounts\\+[^\\\]\r\n]+')]},
    'FTP destination activity or account cache observed; navigation/cache is not proof of upload (ATT&CK T1048.003 candidate)')
add('windows_ftp_upload_attempt',{'all':[windows,
    {'any':[pred('combined_text','regex',r'(?i)\bftp(?:\.exe)?(?:\b|://)'),pred('win_source','contains_any',['ftp'])]},
    pred('combined_text','regex',r'(?i)\b(?:m?put|stor|stou|appe)\s+\S+|\bupload(?:ing|ed)?\s+(?:failed|failure|denied|aborted|started|attempt|to|of)\b')]},
    'FTP outbound upload command/attempt observed; failed or unknown completion remains concerning (ATT&CK T1048.003 candidate)')
add('windows_note_created',{'all':[windows,created,pred('win_path','regex',r'(?i)(?:^|[\\/])[^\\/]*(?:readme|decrypt|ransom|recover)[^\\/]*\.(?:txt|html?|hta)$')]},
    'New note-like file; no ransom content or encryption asserted without corroboration (ATT&CK T1486 candidate)')
add('windows_unattributed_note_created',{'all':[signals('windows_note_created'),{'not':dict(input='win_sid',op='nonempty')}]},
    'New note-like file without attributable SID/profile; eligible only for weaker same-image corroboration')
strong_execution = {'all':[execution,pred('win_executed_av_hash','regex',r'^[0-9a-f]{64}$')]}
add('windows_malware_execution',strong_execution,
    'Observed program use has explicit executed-file SHA256 linked to AV evidence; payload effects remain separate (ATT&CK execution; T1486 context)',confidence='high')
add('windows_malware_execution_candidate',{'all':[execution,signals('referenced_file_av_hit'),{'not':strong_execution}]},
    'Observed program use references an AV-positive path candidate; volume mapping and version-at-execution are unproved (ATT&CK execution; T1486 context)')
add('windows_ransomware_presence',{'all':[windows,signals('av_ransomware','yara_ransomware')]},
    'Ransomware-classified artefact present; execution and impact remain separate (ATT&CK T1486 context)')
add('windows_log_cleared',{'all':[pred('win_source','equals_any',['microsoft-windows-eventlog']),pred('win_event','equals_any',['104','1102'])]},
    'Windows event-log clearing recorded; intent and actor remain separate (ATT&CK T1685.005)')

# Explicit upstream content/transfer observations, not filename inference or
# case-ledger injection. A verified content annotation applies to THIS file.
sensitive = {'all':[pred('content_verified','equals_any',['true','1']),pred('content_type','equals_any',['plaintext_credentials','payment_card_data'])]}
add('windows_sensitive_content_access',{'all':[windows,sensitive,pred('timestamp_kind','equals_any',['access'])]},
    'Access timestamp on file with upstream verified sensitive content; reader identity and transfer remain separate (ATT&CK T1552.001)',confidence='medium')
add('windows_observed_sensitive_upload',{'all':[windows,sensitive,
    pred('transfer_direction','equals_any',['outbound']),pred('transfer_outcome','equals_any',['success']),
    pred('transfer_bytes','regex',r'^[0-9]*[1-9][0-9]*(?:\.0+)?$')]},
    'Upstream file-linked sensitive outbound transfer recorded successful with positive bytes; not inferred from FTP navigation (ATT&CK T1048 candidate)',confidence='high')

# Scope recovery-disable command semantics: merely invoking bcdedit /set or
# mentioning a backup catalog is not recovery inhibition.
for row in direct['ordered_rules']:
    if row['id']=='inhibit_recovery_command':
        row['when'] = pred('combined_text','regex',r'(?i)\b(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)|bcdedit(?:\.exe)?\s+/set\s+(?:\{[^}]+\}\s+)?(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|reagentc(?:\.exe)?\s+/disable)\b')
        row['description'] = 'Recovery-inhibiting command observed; command success is separate (ATT&CK T1490)'
        row['confidence'] = 'medium'

high = ['defender_disabled','inhibit_system_recovery','windows_log_cleared','persistence_scheduled_task','windows_task_registered',
        'windows_psexec_execution','windows_task_action_attempt','windows_archive_created','windows_ftp_activity','windows_ftp_upload_attempt',
        'windows_malware_execution','windows_malware_execution_candidate','windows_ransomware_presence','group_policy_modified',
        'windows_sensitive_content_access','windows_observed_sensitive_upload']
add('windows_contextual_action',{'all':[windows,signals(*high)]},'Windows action eligible for bounded account context')
add('windows_host_contextual_action',{'all':[windows,{'not':dict(input='win_sid',op='nonempty')},signals('defender_disabled','windows_archive_created','windows_task_registered','windows_task_action_attempt')]},
    'Security, archive or task action eligible for weaker same-image context without actor attribution')

# Reference matching retains the whole rooted path. The filename/base-name
# alone cannot activate this branch. Explanation explicitly limits attribution.
d['referenced_file_correlation']['inputs']['execution_path_fields'] += ['application','path','win_action_name','win_message_executable','win_exec_relative_path']

def sequence(name, key, sources, output, duration, description, value=1, priority=99):
    return dict(id=name,description=description,priority=priority,key_by=key,lookback=duration,
        lookback_lower_bound='inclusive',emit_on='sequence_completion',minimum_signal_value_exclusive=0,
        include_supporting_rows=True,
        sequence=[dict(signal=s,min_count=1) for s in sources],
        emit=dict(signals=[dict(name=output,value=value)]),confidence='medium')

new_temporal = [
    dict(id='WINDOWS_ACCOUNT_NEW_SOURCE',description='Source absent from available seven-day successful-logon history for this SID; initial history may be incomplete',
         priority=120,key_by=['win_context_sid'],lookback='7d',lookback_lower_bound='inclusive',emit_on='condition_match',
         minimum_signal_value_exclusive=0,condition=dict(kind='first_seen_value',field='win_login_ip',empty_value_behavior='ignore',
             first_observation_behavior='emit',reference_selection='rolling_window'),emit=dict(signals=[dict(name='windows_account_new_source',value=1)]),confidence='low'),
    sequence('WINDOWS_RECENT_NEW_SOURCE_ACTION',['win_context_sid'],['windows_account_new_source','windows_contextual_action'],
        'windows_recent_new_source_action','6h','Action by same SID/profile after a newly observed successful-logon source; not proof same live session or operator (ATT&CK T1078)',priority=107),
    sequence('WINDOWS_CREATED_THEN_PRIVILEGED',['win_context_sid'],['account_created','privileged_account_created'],
        'windows_new_privileged_account','1h','Account creation then privileged membership for same SID (ATT&CK T1136/T1098.007)',priority=110),
    sequence('WINDOWS_RECENT_PRIVILEGED_ACTION',['win_context_sid'],['windows_new_privileged_account','windows_contextual_action'],
        'windows_recent_privileged_action','7d','Action has recent privileged-account context by SID or unambiguous profile owner; not necessarily same operator/session (ATT&CK T1078)',priority=108),
    sequence('WINDOWS_RECENT_PRIVILEGED_HOST_ACTION',['win_asset_id'],['windows_new_privileged_account','windows_host_contextual_action'],
        'windows_recent_privileged_host_action','7d','Same-image security/archive/task action follows recent privileged-account creation; no direct actor attribution (ATT&CK T1685/T1560/T1053.005)',value=.5,priority=108),
    sequence('WINDOWS_ARCHIVE_FTP',['win_context_sid'],['windows_archive_created','windows_ftp_activity'],
        'windows_archive_ftp_context','3d','Archive creation then FTP activity for same account/profile; possible staged transfer, upload unproved (ATT&CK T1074/T1560/T1048.003)',priority=105),
    sequence('WINDOWS_ARCHIVE_FTP_HOST',['win_asset_id'],['windows_archive_created','windows_ftp_activity'],
        'windows_archive_ftp_host_context','3d','Archive creation then FTP activity on same evidence image; weaker possible staging context, file/author linkage and completion unproved (ATT&CK T1074/T1560/T1048.003)',value=.5,priority=105),
    sequence('WINDOWS_SENSITIVE_FTP',['win_context_sid'],['windows_sensitive_content_access','windows_ftp_activity'],
        'windows_sensitive_ftp_context','3d','Verified sensitive-file access then account/profile FTP activity; particular file upload remains unproved (ATT&CK T1552.001/T1048.003 candidate)',priority=105),
    sequence('WINDOWS_RANSOM_NOTE_CONTEXT',['win_context_sid'],['windows_ransomware_presence','windows_note_created'],
        'windows_ransom_note_context','7d','Note-like creation follows ransomware-classified artefact for same account/profile; content and impact unproved (ATT&CK T1486)',priority=105),
    sequence('WINDOWS_RANSOM_NOTE_HOST_CONTEXT',['win_asset_id'],['windows_ransomware_presence','windows_unattributed_note_created'],
        'windows_ransom_note_host_context','12h','Unattributed note-like creation follows ransomware-classified artefact on same image within12h; no author, note content, family or encryption proof (ATT&CK T1486 candidate)',priority=105),
]
r['temporal_rules'] = new_temporal + r['temporal_rules']
for tr in r['temporal_rules']:
    if tr['id']=='FAIL_THEN_SUCCESS_USER':
        tr['key_by'] = ['actor_principal','src_ip']
        tr['description'] = 'Remote failures followed by success for same principal AND source IP; do not transfer attacker failures onto another client'

d['windows_privileged_context_projection'] = dict(stage='temporal',executor='signal_projection',enabled=True,evidence_type='contextual',
    projections=[dict(inputs=dict(signals=['windows_recent_privileged_action','windows_recent_privileged_host_action']),
        conditions=dict(match='any',minimum_value_exclusive=0),strength='maximum_matched_times_emission_value',
        emissions=[dict(name='windows_privileged_activity_context',value=1,rule_id='WINDOWS_PRIVILEGED_ACTIVITY_CONTEXT',
            description='Bounded privileged-account context counted once: direct/profile SID versus weaker same-asset impairment context',confidence='medium')])],
    evidence=dict(derived_from=dict(resolver='matched_signals')))
d['windows_archive_ftp_projection'] = dict(stage='temporal',executor='signal_projection',enabled=True,evidence_type='contextual',
    projections=[dict(inputs=dict(signals=['windows_archive_ftp_context','windows_archive_ftp_host_context']),
        conditions=dict(match='any',minimum_value_exclusive=0),strength='maximum_matched_times_emission_value',
        emissions=[dict(name='windows_archive_ftp_evidence',value=1,rule_id='WINDOWS_ARCHIVE_FTP_EVIDENCE',
            description='Possible staged FTP transfer counted once, stronger same-account/profile link or weaker same-image association; completion not required',confidence='medium')])],
    evidence=dict(derived_from=dict(resolver='matched_signals')))

w['weights'].update(windows_program_execution=4,windows_psexec_execution=8,windows_task_action_attempt=8,windows_task_registered=12,
    windows_archive_created=8,windows_ftp_activity=4,windows_note_created=0,windows_malware_execution=38,
    windows_ransomware_presence=5,windows_log_cleared=18,windows_contextual_action=0,
    windows_new_privileged_account=6,windows_recent_privileged_action=0,windows_recent_privileged_host_action=0,windows_host_contextual_action=0,
    windows_privileged_activity_context=12,windows_archive_ftp_context=0,windows_archive_ftp_host_context=0,windows_archive_ftp_evidence=16,windows_ransom_note_context=24,
    windows_unattributed_note_created=0,windows_ransom_note_host_context=16,
    defender_disabled=18,persistence_scheduled_task=12,privileged_account_created=12,inhibit_system_recovery=18,
    impossible_travel=4,boundary_crossing=2,new_country=4,new_asn=2)
w['weights'].update(windows_malware_execution_candidate=26,windows_account_new_source=0,windows_recent_new_source_action=4,
    windows_sensitive_content_access=14,windows_sensitive_ftp_context=8,windows_observed_sensitive_upload=36,
    windows_ftp_upload_attempt=20,windows_malware_execution=42)

headers = {
 'rules/rules_evidence_calibrated_v13.yaml': '# Windows evidence/context candidate v13; weights v12.\n# ATT&CK rationale, evidence limits and regression expectations:\n# ../docs/WINDOWS_SCORING_DESIGN.md\n# T1136.002 https://attack.mitre.org/techniques/T1136/002/\n# T1098.007 https://attack.mitre.org/techniques/T1098/007/\n# T1685 https://attack.mitre.org/techniques/T1685/\n# T1053.005 https://attack.mitre.org/techniques/T1053/005/\n# T1569.002 https://attack.mitre.org/techniques/T1569/002/\n# T1048.003 https://attack.mitre.org/techniques/T1048/003/\n# T1486 https://attack.mitre.org/techniques/T1486/\n# References describe behaviour; labels do not add duplicate score.\n',
 'rules/weights_evidence_calibrated_v12.yaml': '# Windows weights v12, paired with rules v13.\n# Expert-set event priorities, not probabilities or MITRE-prescribed weights.\n# Malware-linked use outranks generic auth/geography; attempts retain evidence.\n# Direct/profile and host context share one maximum-strength contribution.\n# See ../docs/WINDOWS_SCORING_DESIGN.md for ATT&CK rationale and limitations.\n',
}
print('*** Begin Patch')
for name, config in zip(headers,(r,w)):
    content=headers[name]+yaml.safe_dump(config,sort_keys=False,allow_unicode=True,width=120)
    if (ROOT/name).exists():
        previous=(ROOT/name).read_text()
        if previous==content:
            continue
        print('*** Update File: '+str(ROOT/name))
        # Include the owning rule ID around repeated YAML predicate shapes;
        # three-line hunks can otherwise match a neighbouring rule.
        for line in list(difflib.unified_diff(previous.splitlines(),content.splitlines(),n=30,lineterm=''))[2:]:
            print('@@' if line.startswith('@@') else line)
    else:
        print('*** Add File: '+str(ROOT/name))
        print('\n'.join('+'+line for line in content.splitlines()))
print('*** End Patch')
