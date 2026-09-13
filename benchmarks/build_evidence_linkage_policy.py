"""Emit scoped apply_patch changes for rules v14 / weights v13.

The v13/v12 inputs stay immutable. No ground-truth names, addresses or hashes
are detector inputs. See docs/DATASET_IMPROVEMENTS.md for evidence boundaries.
"""
from pathlib import Path
import difflib
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
r = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v13.yaml').read_text())
w = yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v12.yaml').read_text())
d = r['detector_policy']['detectors']
d['yara_classification']['metadata']['on_incomplete_rule'] = 'fail'
d['web_request_classification']['matching']['allowed_url_schemes'] = ['http','https']
for name,aliases in {
    'evidence_gpo_access_mask':['AccessMask'],
    'evidence_gpo_object':['ObjectName','ObjectDN'],
    'evidence_gpo_class':['ObjectClass','ObjectType'],
    'evidence_gpo_detail':['AdditionalInfo'],
}.items():
    r['canonicalisation']['windows_authentication']['fields'].append(dict(id=name,output_field=name,event_data_aliases=aliases,system_source='none'))

def rx(name, source, pattern, selector=None, stage='pre'):
    entry = dict(name=name,method='regex_first',**{'from':source},pattern=pattern,group=1,stage=stage)
    if selector: entry['selector'] = dict(field=selector[0],pattern=selector[1])
    return entry

def coal(name,*fields,stage='pre'):
    return dict(name=name,method='coalesce',fields=list(fields),overwrite_existing=True,stage=stage)

def lookup(name,source,key,value,case_sensitive=False,stage='pre'):
    return dict(name=name,method='identity_lookup',**{'from':source},key_field=key,value_field=value,case_sensitive=case_sensitive,stage=stage)

def pred(name,op,value):
    return dict(input=name,op=op,**({'pattern':value} if op=='regex' else {'values':value}))

def sig(*names):
    return dict(op='signal_any_positive',signals=list(names),minimum_value_exclusive=0)

# Actual execution fields precede containers. UserAssist's value records a
# program; NTUSER.DAT is the evidence container, not that program's location.
extra = [
    rx('evidence_userassist_path','message',r'(?i)(?:UEME_RUNPATH:|Value name:\s*)([a-z]:\\[^\r\n]+?\.exe)(?:\s+Count:|\s*$)',('parser',r'(?i)userassist')),
    # Classic PowerShell EVTX stores an explicit HostApplication command in
    # unnamed XML EventData. Retain this actual command, not arbitrary log text.
    # ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
    rx('evidence_powershell_host_command','xml_string',r'HostApplication=([^\r\n]+?)(?:\\r\\n|\r?\n|</Data>)',('source_name',r'(?i)^(?:Microsoft-Windows-)?PowerShell$')),
    rx('evidence_powershell_host_path','evidence_powershell_host_command',r'(?i)^\s*"?([^"\r\n]*?\.exe)(?:"|\s|$)'),
    coal('evidence_execution_source','new_process_name','image_path','application','win_action_name','win_message_executable','evidence_userassist_path','evidence_powershell_host_path'),
    rx('evidence_execution_path','evidence_execution_source',r'^(.+)$',('parser',r'(?i)^(?:winevt|winreg/(?:bam|userassist)|esedb/srum|sysmon|linux:audit|auditd)')),
    rx('evidence_history_command','message',r'^(.+)$',('parser',r'(?i)(?:bash_history|zsh_history|powershell|cmd_history|auditd)')),
    coal('evidence_execution_command','command_line','command','evidence_history_command','evidence_powershell_host_command'),
]
r['normalisation'] += extra
# Domain-qualified task identities take precedence over an unqualified alias.
# Profile ownership remains a weaker, explicitly named contextual route.
identity = [
    dict(name='evidence_target_principal',method='join_fields',fields=['target_domain_name','target_user_name'],separator='\\'),
    lookup('evidence_task_domain_sid','win_task_user','evidence_target_principal','win_identity_sid'),
    dict(name='evidence_gpo_mutating_access',method='bitmask_any',**{'from':'evidence_gpo_access_mask'},mask=0x1|0x2|0x8|0x20|0x40|0x10000|0x40000|0x80000|0x40000000|0x10000000),
]
direct_pos=next(i for i,spec in enumerate(r['normalisation']) if spec['name']=='win_direct_sid')
r['normalisation'][direct_pos:direct_pos]=identity
for spec in r['normalisation']:
    if spec['name']=='win_direct_sid':
        spec['fields'].insert(spec['fields'].index('win_task_sid'),'evidence_task_domain_sid')
# A qualified task name from a represented different domain must not fall
# back to a same-spelled account in another domain. Unqualified task records
# can still use the existing ambiguity-rejecting local alias.
for spec in r['normalisation']:
    if spec['name']=='win_task_account':
        spec['pattern']=r'^([^\\]+)$'
# The existing Windows path-context field is also used by non-execution file
# rules, so improve its precedence without erasing file observations.
for spec in r['normalisation']:
    if spec['name']=='win_evidence_path':
        spec['fields'] = ['evidence_userassist_path',*spec['fields']]
        spec['overwrite_existing'] = True
# Resolve UserAssist before Windows coalescing in both normalisation passes.
ua = next(x for x in r['normalisation'] if x['name']=='evidence_userassist_path')
r['normalisation'].remove(ua)
r['normalisation'].insert(0,ua)
d['execution_context_classifier']['inputs']['path']['fields'] = ['evidence_execution_path']
d['execution_context_classifier']['inputs']['command']['fields'] = ['evidence_execution_command']
# The command tokenizer retains executable suffixes. Source-name mentions no
# longer provide an accidental bare "PowerShell" match on Windows records.
d['execution_context_classifier']['classification']['command_names']['shell'] += ['powershell.exe','pwsh.exe']
d['referenced_file_correlation']['inputs']['execution_path_fields'].insert(0,'evidence_execution_path')

# Unambiguous, case-sensitive web path -> full observed filesystem path.
# Canonical URL paths are available only after HTTP materialisation. Alias
# ambiguity across document roots fails closed; basename joins are forbidden.
roots=d['referenced_file_correlation']['matching']['web_document_roots']
root_patterns=[]
for root in roots:
    root=root.replace('\\','/').rstrip('/')
    root_patterns.append(re.escape(root) if root.startswith('/') else r'(?i:(?:(?:[a-zA-Z]|NTFS):)?/'+re.escape(root)+')')
root_pattern=r'^(?:'+ '|'.join(root_patterns)+r')(/.+)$'
windows_root_pattern=r'(?i)^(?:'+ '|'.join(pattern for root,pattern in zip(roots,root_patterns) if not root.startswith('/'))+r')/'
r['normalisation'] += [
    coal('evidence_asset','hostname','win_asset_id',stage='post_web'),
    rx('evidence_web_file_path','filename',r'^(.+)$',('parser',r'(?i)^(?:filestat|mft)$'),stage='post_web'),
    dict(name='evidence_web_file_slashes',method='path_separators',**{'from':'evidence_web_file_path'},stage='post_web'),
    rx('evidence_web_file_relative','evidence_web_file_slashes',root_pattern,stage='post_web'),
    dict(name='evidence_web_file_url',method='canonical_web_path',**{'from':'evidence_web_file_relative'},stage='post_web'),
    coal('evidence_web_lookup','evidence_web_file_url','chronosift_web_endpoint',stage='post_web'),
    lookup('evidence_web_exact_identity','evidence_web_lookup','evidence_web_file_url','evidence_web_file_path',True,'post_web'),
    # Case-insensitive fallback is seeded ONLY by configured Windows roots.
    # Linux paths retain exact matching; raw full file identity is preserved.
    rx('evidence_web_windows_url','evidence_web_file_url',r'^(.+)$',('evidence_web_file_slashes',windows_root_pattern),stage='post_web'),
    lookup('evidence_web_windows_identity','evidence_web_lookup','evidence_web_windows_url','evidence_web_file_path',False,'post_web'),
    coal('evidence_web_identity','evidence_web_exact_identity','evidence_web_windows_identity',stage='post_web'),
]

# Whole rooted Windows path aliases, scoped to this evidence dataset/frame.
# Multiple observed hashes at a path revoke its alias. Device-volume stripping
# remains a candidate mapping; an executed-file hash is separately explicit.
r['normalisation'] += [
    rx('evidence_payload_file_path','filename',r'(?i)^(?:(?:[a-z]:|ntfs:)|\\+device\\+harddiskvolume\d+)?(\\.+)$',('parser',r'(?i)^(?:filestat|mft)$')),
    rx('evidence_payload_exec_path','evidence_execution_path',r'(?i)^(?:(?:[a-z]:|ntfs:)|\\+device\\+harddiskvolume\d+)?(\\.+)$'),
    rx('evidence_payload_file_hash','sha256_hash',r'(?i)^([0-9a-f]{64})$',('evidence_payload_file_path',r'.+')),
    coal('evidence_payload_lookup','evidence_payload_file_path','evidence_payload_exec_path'),
    lookup('evidence_payload_path_hash','evidence_payload_lookup','evidence_payload_file_path','evidence_payload_file_hash'),
    coal('evidence_payload_identity','chronosift_executed_sha256','evidence_payload_path_hash'),
    rx('evidence_av_payload_path','evidence_payload_file_path',r'^(.+)$',('av_hit',r'(?i)^(?:true|1(?:\.0)?)$')),
    lookup('evidence_execution_av_path_hash','evidence_payload_exec_path','evidence_av_payload_path','evidence_payload_file_hash'),
]

direct=d['direct_attack_semantics']
for name,field in {
    'linked_web_file':'evidence_web_identity','web_method':'chronosift_web_method',
    'web_target':'chronosift_web_request_target','web_status':'chronosift_web_status_code',
    'execution_command':'evidence_execution_command','xml':'xml_string',
    'yara_qualified':'chronosift_yara_qualified_categories',
    'gpo_access':'evidence_gpo_mutating_access','gpo_object':'evidence_gpo_object','gpo_class':'evidence_gpo_class','gpo_detail':'evidence_gpo_detail',
    'payload_identity':'evidence_payload_identity','execution_av_path_hash':'evidence_execution_av_path_hash',
    'executed_hash':'chronosift_executed_sha256',
}.items():
    direct['inputs'][name]=dict(resolver='row_field',fields=[field],normalise='lower')
    direct['evidence'][name]=dict(resolver='input',input=name)

def add(name,when,description,weight=0,confidence='medium'):
    direct['ordered_rules'].append(dict(id=name,when=when,emission=name,description=description,confidence=confidence,
        evidence=['linked_web_file','web_target','win_path','win_sid','message','win_event']))
    direct['emissions'][name]=dict(name=name,value=1,rule_id=name.upper(),description=description,confidence=confidence)
    w['weights'][name]=weight

linked={'input':'linked_web_file','op':'nonempty'}
request={'all':[linked,pred('web_method','equals_any',['get','post','head','put','patch'])]}
created={'any':[pred('timestamp_kind','equals_any',['create']),pred('message','contains_any',['USN_REASON_FILE_CREATE'])]}
add('evidence_web_linked_request',request,'HTTP request maps to one observed full file path; access does not establish command success')
add('evidence_linked_suspicious_request',{'all':[request,sig('web_exploitation_hint','web_confirmed_webshell_access')]},
    'Suspicious request is linked to one observed web file; neither shell execution nor request success is assumed')
add('evidence_web_file_created',{'all':[linked,created]},'Newly created web file with unambiguous configured document-root identity')
add('evidence_hostile_web_request',{'all':[pred('web_method','equals_any',['get','post','put','patch']),sig('web_sqli_attempt','web_confirmed_webshell_access')]},
    'Prior attack-syntax or qualified web-shell request by this client; success and human identity remain separate')
add('evidence_database_delete',{'all':[
    pred('parser_lower','regex',r'^(?:filestat|mft|usnjrnl)'),pred('timestamp_kind','equals_any',['delete']),
    pred('path_lower','regex',r'(?i)/(?:var/lib/(?:mysql|mariadb|postgresql)|mysql/data)/.+\.(?:ibd|frm|myd|myi|db)$')]},
    'Database storage-file deletion observed; maintenance versus destructive intent remains unresolved (ATT&CK T1485 candidate)',8)
add('evidence_database_destructive_command',pred('execution_command','regex',r'(?is)\b(?:drop\s+(?:database|table)|truncate\s+table)\s+(?:`[^`]+`|[a-z_][\w.-]*)'),
    'Database-destructive command attempt in execution/history evidence; success is separate (ATT&CK T1485)',24)
add('evidence_gpo_directory_change',{'all':[
    pred('win_source','equals_any',['microsoft-windows-security-auditing']),pred('win_event','equals_any',['5136','5137','5141']),
    pred('xml','regex',r'(?i)(?:groupPolicyContainer|CN=Policies,CN=System)')]},
    'Directory-service change to a group-policy object; changed value and actor retained (ATT&CK T1484.001)',16)
add('evidence_gpo_change_operation',{'all':[
    pred('win_source','equals_any',['microsoft-windows-security-auditing']),pred('win_event','equals_any',['4662']),
    pred('gpo_access','equals_any',['1']),{'any':[
        pred('gpo_class','regex',r'(?i)groupPolicyContainer|f30e3bc2-9ff0-11d1-b603-0000f80367c1'),
        pred('gpo_object','regex',r'(?i)CN=Policies,CN=System'),pred('gpo_detail','regex',r'(?i)CN=Policies,CN=System')]}]},
    'GPO-related directory operation used create/delete/write-capable access; attempted change merits attention, particular modified setting and success remain separate (ATT&CK T1484.001)',12)
add('evidence_qualified_malware_file',{'all':[
    pred('parser_lower','regex',r'^(?:filestat|mft)$'),{'input':'payload_identity','op':'nonempty'},
    {'any':[sig('av_malware','av_ransomware'),pred('yara_qualified','regex',r'(?:^|\|)(?:malware|ransomware|apt)(?:\||$)')]}]},
    'AV or score/quality-qualified YARA malware artefact with observed file identity; presence alone is not execution')
add('evidence_exact_hash_program_use',{'all':[sig('windows_program_execution'),pred('executed_hash','regex',r'^[0-9a-f]{64}$')]},
    'Program-use record supplies the explicit executed-file hash; container hashes do not qualify')
for rule in direct['ordered_rules']:
    if rule['id']=='windows_malware_execution_candidate':
        rule['when']['all'].append({'input':'execution_av_path_hash','op':'nonempty'})
        rule['description']='Program use resolves its own complete path to one AV-backed observed hash; ambiguous path versions reject linkage and volume mapping remains a candidate'

# Replace broad global co-occurrence with an exact unambiguous web-file key.
# A below-gate YARA web-shell artefact can supply contextual evidence but does
# not gain a fabricated qualified identity/category or claim of execution.
d['webshell_activity']['key']={'scope':'field','field':'evidence_web_identity'}
d['webshell_activity']['target']['any_signals']=['evidence_web_linked_request']
d['webshell_activity']['emissions'][0]['description']='Request to the same unambiguously mapped web-shell-like file observed within the configured window; request is not proof of command execution (ATT&CK T1505.003 candidate)'
d['webshell_activity']['evidence']['file_identity']={'resolver':'target_field','field':'evidence_web_identity'}

def sequence(name,key,sources,output,duration,description,weight,priority=95):
    w['weights'][output]=weight
    return dict(id=name,description=description,priority=priority,key_by=key,lookback=duration,
        lookback_lower_bound='inclusive',emit_on='sequence_completion',minimum_signal_value_exclusive=0,
        include_supporting_rows=True,sequence=[dict(signal=s,min_count=1) for s in sources],
        emit=dict(signals=[dict(name=output,value=1)]),confidence='medium')

r['temporal_rules'] += [
    sequence('QUALIFIED_MALWARE_PATH_USE',['evidence_payload_identity'],['evidence_qualified_malware_file','windows_program_execution'],
        'windows_qualified_malware_use','7d','Program use follows qualified AV/YARA evidence for the same unambiguous full-path file candidate; volume/version-at-execution unproved (ATT&CK execution)',0),
    sequence('QUALIFIED_MALWARE_EXACT_HASH_USE',['evidence_payload_identity'],['evidence_qualified_malware_file','evidence_exact_hash_program_use'],
        'windows_qualified_exact_malware_use','7d','Explicit executed-file hash matches earlier AV or qualified YARA malware evidence; payload effects remain separate (ATT&CK execution)',0),
    sequence('RECENT_CREATED_SENSITIVE_WEB_DOWNLOAD',['evidence_web_identity'],['evidence_web_file_created','web_sensitive_file_download'],
        'web_recent_file_sensitive_download','30m','Successful sensitive download follows creation of the same full web file; creation is a distinct staging dimension (ATT&CK T1074.001)',4),
    sequence('HOSTILE_CLIENT_SENSITIVE_WEB_DOWNLOAD',['chronosift_web_history_asset','chronosift_web_source_ip'],['evidence_hostile_web_request','web_sensitive_file_download'],
        'web_hostile_client_sensitive_download','2h','Sensitive download follows attack evidence from the same client/asset; NAT and operator identity remain uncertain (ATT&CK T1190/T1048 context)',4),
]
# This uses direct-stage linked request evidence. A typed temporal sequence
# cannot consume another sequence from the same executor phase.
d['web_content_followon'] = yaml.safe_load(yaml.safe_dump(d['webshell_activity']))
d['web_content_followon'].update(key={'scope':'field','field':'evidence_asset'})
d['web_content_followon']['source']['any_signals']=['evidence_linked_suspicious_request']
d['web_content_followon']['target']['any_signals']=['web_content_modification']
d['web_content_followon']['emissions']=[dict(name='web_content_change_after_shell',value=1,rule_id='WEB_CONTENT_CHANGE_AFTER_SHELL',
    description='Web content modification follows a file-linked suspicious request on the same asset; possible defacement, not verified authorship or content (ATT&CK T1491 candidate)',confidence='low')]
w['weights']['web_content_change_after_shell']=8
direct['emissions']['windows_malware_execution_candidate']['value']=26/42
for rule in r['temporal_rules']:
    if rule['id']=='QUALIFIED_MALWARE_PATH_USE': rule['emit']['signals'][0]['value']=26/42
for detector_name,inputs,output,weight in [
    ('windows_malware_use_projection',['windows_malware_execution_candidate','windows_qualified_malware_use','windows_malware_execution','windows_qualified_exact_malware_use'],'windows_malware_use_priority',42),
]:
    d[detector_name]=dict(stage='temporal',executor='signal_projection',enabled=True,evidence_type='contextual',
        projections=[dict(inputs=dict(signals=inputs),conditions=dict(match='any',minimum_value_exclusive=0),strength='maximum_matched_times_emission_value',
            emissions=[dict(name=output,value=1,rule_id=output.upper(),description='Qualified malware-use evidence counted once across AV/YARA routes; executed hash and path candidate remain distinct',confidence='medium')])],
        evidence=dict(derived_from=dict(resolver='matched_signals')))
    for signal in inputs: w['weights'][signal]=0
    w['weights'][output]=weight
# Direct Windows context can consume new supported policy changes without
# assigning the operator from the nearest logon.
for rule in direct['ordered_rules']:
    if rule['id']=='windows_contextual_action':
        rule['when']['all'][1]['signals'] += ['evidence_gpo_directory_change','evidence_gpo_change_operation']
for name in ('evidence_gpo_directory_change','evidence_gpo_change_operation'):
    gpo = next(rule for rule in direct['ordered_rules'] if rule['id']==name)
    direct['ordered_rules'].remove(gpo)
    direct['ordered_rules'].insert(next(i for i,rule in enumerate(direct['ordered_rules']) if rule['id']=='windows_contextual_action'),gpo)

headers={
    'rules/rules_evidence_calibrated_v14.yaml':'# Evidence linkage v14; weights v13. Policy vocabulary and MITRE rationale:\n# ../docs/DATASET_IMPROVEMENTS.md\n# T1505.003 https://attack.mitre.org/techniques/T1505/003/\n# T1484.001 https://attack.mitre.org/techniques/T1484/001/\n# T1485 https://attack.mitre.org/techniques/T1485/\n# T1491 https://attack.mitre.org/techniques/T1491/\n',
    'rules/weights_evidence_calibrated_v13.yaml':'# Evidence linkage weights v13; rules v14.\n# Expert priorities, not probabilities or weights prescribed by ATT&CK.\n# See ../docs/DATASET_IMPROVEMENTS.md.\n',
}
print('*** Begin Patch')
for name,config in zip(headers,(r,w)):
    content=headers[name]+yaml.safe_dump(config,sort_keys=False,allow_unicode=True,width=120)
    target=ROOT/name
    if target.exists():
        previous=target.read_text()
        if previous==content: continue
        print('*** Update File: '+str(target))
        for line in list(difflib.unified_diff(previous.splitlines(),content.splitlines(),n=30,lineterm=''))[2:]:
            print('@@' if line.startswith('@@') else line)
    else:
        print('*** Add File: '+str(target))
        print('\n'.join('+'+line for line in content.splitlines()))
print('*** End Patch')
