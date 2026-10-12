"""v27/v23: reuse identity/source history; score anomalies, not ordinary logons.

Historical policies remain immutable. ATT&CK T1110/T1078 describe the qualified
failure/success and account-use candidates, not all privileged authentication.
"""
from copy import deepcopy
from pathlib import Path
import difflib
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]


def build():
    doc = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v26.yaml').read_text())
    doc['profiling']['monthly'] = dict(
        enabled=True, web_enabled=True, web_training_window_days=4,
        web_minimum_complete_days=3, web_rule_id='WEB_QUIET_HOURS_AMPLIFIER',
        parser_adapters={'text/apache_access':'apache', 'text/winiis':'iis'},
        apache_request_field='http_request', iis_method_field='http_method',
        iis_target_fields=['requested_uri_stem','cs_uri_stem'],
        status_fields={'apache':['http_response_code'], 'iis':['http_status','sc_status','http_response_code']})
    doc['engine_notes']['temporal_profiling'] = (
        'Previous UTC calendar month only; filtered non-OS filesystem complete weeks, no full-dataset fallback. '
        'Separate HTTP200 web profile uses the first four consecutive observed interior UTC days; '
        'all access responses receive the validated daily multiplier. Missing/rejected profiles are neutral; expiry is the following month end.')
    detectors = doc['detector_policy']['detectors']
    execution = detectors['execution_context_classifier']
    execution['decisions']['privileged_context']['all'].append('execution_evidence')
    execution['emissions']['privileged_context']['description'] = (
        'Source-qualified execution path or command in a privileged context; authentication or an account name alone is insufficient')

    direct = detectors['direct_attack_semantics']
    # Preserve actual share evidence and explicit-credential observations. The
    # network-logon guess is now a separate, zero-weight descriptive signal.
    inference = next(r for r in direct['ordered_rules'] if r['id']=='smb_network_logon_inference')
    inference['emission'] = 'smb_network_logon_candidate'
    emission = deepcopy(direct['emissions']['smb_admin_share'])
    emission.update(name='smb_network_logon_candidate', rule_id='SMB_NETWORK_LOGON_CANDIDATE',
        description='Network authentication may use SMB; no share access, lateral movement or credential abuse is established',
        confidence='low', attack_ids=[], attack_basis='unmapped',
        attack_note='Protocol context only; retain direct administrative-share observations as the T1021.002 evidence path.')
    direct['emissions']['smb_network_logon_candidate'] = emission
    alternate = next(r for r in direct['ordered_rules'] if r['id']=='alternate_authentication_material')
    alternate['when']['all'][1]['any'][0]['signals'].remove('auth_ntlm_remote')
    alternate['description'] = 'Explicit-credential or NewCredentials logon semantics; NTLM alone does not establish alternate-material abuse'

    # Use the EXISTING first-seen executor, not another account/IP database.
    # Only source-linked failure-to-success observations qualify. This is a
    # bounded evidence episode, not promotion of a source into a trusted list.
    episode = dict(id='AUTH_FAILURE_SUCCESS_EPISODE', priority=79,
        description='First source-linked failure-to-success observation for this scoped account/source within six hours; repeated successes retain only bounded context',
        key_by=['continuity_key'], lookback='6h', lookback_lower_bound='inclusive',
        emit_on='condition_match', minimum_signal_value_exclusive=0,
        condition=dict(kind='first_seen_value',field='src_ip',empty_value_behavior='ignore',
            first_observation_behavior='emit',reference_selection='rolling_window',
            signals_any=['fail_then_success_user','fail_then_success_ip']),
        emit=dict(signals=[dict(name='auth_failure_success_episode',value=1)]),
        confidence='medium',attack_ids=['T1110'],attack_basis='contextual_inference',
        attack_note='Source-linked failure/success episode, not proof of guessed credentials; account-only failures from another client do not qualify.')
    index = next(i for i,r in enumerate(doc['temporal_rules']) if r['id']=='FAIL_THEN_SUCCESS_IP')+1
    doc['temporal_rules'].insert(index,episode)

    # Successful use completes the persistence chain. Keep this separate from
    # generic sensitive-action eligibility: ordinary provisioned-account logons
    # do not inherit privilege danger, and the account name is not the key.
    account_use=[]
    privileged_use=[]
    for route in ('travel', 'authentication'):
        template = next(r for r in doc['temporal_rules']
                        if r['id']==f'WINDOWS_RISKY_CREATOR_{route.upper()}_ACTION')
        for privileged in (False, True):
            rule=deepcopy(template)
            suffix='privileged_account_use' if privileged else 'account_use'
            name=f'windows_risky_creator_{route}_{suffix}'
            rule.update(id=name.upper(), description=(
                'Successful use of a recently created account with risky creator provenance; '
                + ('privileged membership is also established for the same scoped SID' if privileged
                   else 'privileged membership is not required')))
            rule['sequence'][0]['signal']=(
                f'windows_risky_creator_{route}_privileged_account' if privileged
                else f'windows_created_by_risky_{route}_account')
            rule['sequence'][1]['signal']='auth_success'
            rule['emit']['signals']=[dict(name=name,value=1)]
            rule['attack_ids']=['T1078']
            rule['attack_note']=(
                'Successful account use follows creation with risky creator evidence in the same '
                'asset/SID scope within seven days; no permanent trust label, recursive inheritance '
                'or proof of the same operator/session.')
            doc['temporal_rules'].append(rule)
            account_use.append(name)
            if privileged: privileged_use.append(name)
    detectors['windows_creator_risk_projection']['projections'][0]['inputs']['signals'].extend(account_use)
    detectors['windows_privileged_context_projection']['projections'][0]['inputs']['signals'].extend(privileged_use)

    # Native record identity is derived through the ordinary YAML normalisation
    # layer. A missing source or record number fails closed for strong seeds.
    doc['normalisation'].extend([
        dict(name='auth_record_number',method='regex_first',**{'from':'record_number'},
             pattern=r'^\s*(\d+)(?:\.0+)?\s*$',group=1),
        dict(name='auth_xml_record_number',method='regex_first',**{'from':'xml_string'},
             pattern=r'<EventRecordID(?:\s[^>]*)?>\s*(\d+)\s*</EventRecordID>',group=1),
        dict(name='auth_native_record_number',method='coalesce',fields=['auth_record_number','auth_xml_record_number']),
        dict(name='auth_native_log_source',method='coalesce',fields=['pathspec','source_path','source_file','filename']),
        dict(name='auth_native_record_key',method='join_fields',
             fields=['continuity_scope','identity_event_provider','auth_native_log_source','auth_native_record_number'],separator='|'),
        dict(name='auth_episode_principal_raw',method='coalesce',fields=['actor_principal']),
        dict(name='auth_episode_realm_raw',method='regex_first',**{'from':'identity_authenticated_account'},
             pattern=r'^([^\\]+)\\',group=1),
        dict(name='auth_episode_realm',method='casefold',**{'from':'auth_episode_realm_raw'}),
        dict(name='auth_episode_sid_raw',method='regex_first',**{'from':'identity_authenticated_sid'},
             pattern=r'(?i)^(S-1-(?!0-0$)\d+(?:-\d+)+)$',group=1),
        dict(name='auth_episode_sid',method='casefold',**{'from':'auth_episode_sid_raw'}),
        dict(name='auth_episode_principal',method='casefold',**{'from':'auth_episode_principal_raw'}),
        dict(name='auth_episode_account_key',method='join_fields',fields=['continuity_scope','auth_episode_principal'],separator='|'),
    ])
    def sequence(name, source, target, keys, *, priority=76, lookback='7d', count=1,
                 deduplicate=False, consume=False, all_of=(), any_of=(), attack=('T1078',)):
        rule=dict(id=name.upper(),description=(
            'Bounded account-compromise evidence; seed witnesses and subsequent use remain separate, '
            'with no assumption that every operator using the account is malicious'),
            priority=priority,key_by=list(keys),lookback=lookback,lookback_lower_bound='inclusive',
            emit_on='sequence_completion',minimum_signal_value_exclusive=0,include_supporting_rows=True,
            sequence=[dict(signal=source,min_count=count),dict(signal=target,min_count=1)],
            emit=dict(signals=[dict(name=name,value=1)]),confidence='medium',attack_ids=list(attack),
            attack_basis='contextual_inference' if attack else 'unmapped',
            attack_note='Qualified evidence is scoped to the account and asset; carry expires from the original seed, '
                        'ordinary uses do not reseed, and password changes alone do not establish remediation.')
        if deduplicate: rule['deduplicate_by']=['auth_native_record_key']
        if consume: rule['consume_on_completion']=True
        if deduplicate: rule['witness_match_fields']=['auth_episode_realm','auth_episode_sid']
        if all_of: rule['match_signals_all']=list(all_of)
        if any_of: rule['match_signals_any']=list(any_of)
        doc['temporal_rules'].append(rule)
        return rule
    seed='auth_sustained_bruteforce_success'
    strong='auth_corroborated_bruteforce_success'
    for name, corroborated in ((seed,False),(strong,True)):
        rule=sequence(name,'auth_remote_failure','auth_remote_success',
            ['auth_episode_account_key','src_ip'],priority=78,lookback='30m',count=10,
            deduplicate=True,consume=True,attack=('T1110','T1078'),
            all_of=('impossible_travel',) if corroborated else (),
            any_of=())
        rule['description']=('At least ten distinct native account/source failures followed by success within thirty minutes; '
                            'the first completion consumes the attempt episode'
                            + ('; impossible travel corroborates the sustained account/source attempt episode' if corroborated else ''))
    sequence('auth_account_compromise_context',seed,'auth_success',['continuity_key'],attack=())
    source_use=[];novel_use=[]
    for prefix, origin in (('suspected',seed),('corroborated',strong)):
        source_name=f'auth_{prefix}_compromise_source_use'
        novel_name=f'auth_{prefix}_compromise_novel_use'
        sequence(source_name,origin,'auth_success',['continuity_key','src_ip'])
        sequence(novel_name,origin,'auth_success',['continuity_key'],
                 any_of=('windows_account_new_source','new_country','new_asn'))
        source_use.append(source_name);novel_use.append(novel_name)
    sequence('auth_corroborated_compromise_sensitive_action',strong,'windows_contextual_action',['continuity_key'])
    # Creator provenance can also refer to the originating corroborated episode,
    # rather than demanding another burst immediately before account creation.
    sequence('windows_created_by_compromised_account',strong,'windows_account_creation_target',
             ['win_creator_chain_key'],priority=76,attack=('T1136',))
    sequence('windows_compromised_creator_privileged_account','windows_created_by_compromised_account',
             'windows_new_privileged_account',['win_scoped_account_key'],priority=75,lookback='1h',attack=('T1098.007',))
    for suffix,target,source in (
            ('account_use','auth_success','windows_created_by_compromised_account'),
            ('privileged_account_use','auth_success','windows_compromised_creator_privileged_account'),
            ('action','windows_contextual_action','windows_compromised_creator_privileged_account')):
        sequence(f'windows_compromised_creator_{suffix}',source,target,['win_scoped_account_key'],priority=74)
    detectors['windows_creator_risk_projection']['projections'][0]['inputs']['signals'].extend([
        'windows_created_by_compromised_account','windows_compromised_creator_privileged_account',
        'windows_compromised_creator_account_use','windows_compromised_creator_privileged_account_use',
        'windows_compromised_creator_action'])
    detectors['windows_privileged_context_projection']['projections'][0]['inputs']['signals'].append(
        'windows_compromised_creator_privileged_account_use')

    projections=[]
    def project(name, inputs, description, *, match='all', groups=(), exclude=(), attack=()):
        conditions=dict(match=match,minimum_value_exclusive=0)
        if groups: conditions['all_of_any']=[list(g) for g in groups]
        if exclude: conditions['none']=list(exclude)
        projections.append(dict(inputs=dict(signals=inputs),conditions=conditions,
            strength='maximum_matched_times_emission_value',emissions=[dict(
                name=name,value=1,rule_id=name.upper(),description=description,
                confidence='medium',attack_ids=list(attack),
                attack_basis='contextual_inference' if attack else 'unmapped',
                attack_note='Behavioural triage context, not a compromise verdict, operator attribution or country-based suspicion.')]))
    project('auth_failure_context',['fail_then_success_user','fail_then_success_ip'],
        'One bounded failure-to-success contribution regardless of overlapping account/source and source-only producers',match='any',attack=['T1110'])
    project('auth_failure_episode_priority',['auth_failure_success_episode'],
        'Additional priority at the first qualifying failure/success episode; repeated observations do not renew the full bonus',attack=['T1110'])
    project('auth_geographic_novelty',['new_country','new_asn','new_city'],
        'Country/ASN novelty counted once; when travel qualifies its stronger geography contribution replaces this one',
        match='any',exclude=['impossible_travel'])
    geography_gate=['windows_account_new_source','new_country','new_asn','auth_failure_success_episode']
    project('auth_anomalous_travel',['impossible_travel','auth_remote_success'],
        'Geographic velocity anomaly corroborated by source/geographic novelty or a fresh source-linked failure/success episode; familiar-source return alone does not qualify',groups=[geography_gate],attack=['T1078'])
    carried_takeover=['auth_corroborated_bruteforce_success','auth_corroborated_compromise_source_use',
        'auth_corroborated_compromise_novel_use','auth_corroborated_compromise_sensitive_action']
    # The existing projection schedule intentionally forbids same-phase
    # dependencies. Express fresh OR carried evidence in conjunctive groups
    # over earlier raw producers, rather than feeding one projection into another.
    takeover_groups=[[fresh,*carried_takeover] for fresh in
        ('auth_failure_success_episode','impossible_travel','auth_remote_success')]
    project('auth_takeover_candidate',['auth_failure_success_episode','impossible_travel','auth_remote_success',*carried_takeover],
        'One takeover-priority contribution from qualified fresh or corroborated carried compromise evidence',
        match='any',groups=takeover_groups,attack=['T1078'])
    project('auth_privileged_takeover',['privileged_login'],
        'Privilege increases severity of qualified fresh or carried takeover evidence; privilege alone adds no login danger',
        groups=takeover_groups,attack=['T1078'])
    project('auth_suspected_compromise_priority',['auth_suspected_compromise_source_use','auth_suspected_compromise_novel_use'],
        'Bounded suspected compromise use from a sustained native-record burst without travel corroboration',match='any',
        exclude=[*carried_takeover,'auth_failure_success_episode','fail_then_success_user','fail_then_success_ip'],attack=['T1078'])
    detectors['authentication_context_priority'] = dict(stage='temporal',executor='signal_projection',enabled=True,
        evidence_type='contextual',projections=projections,evidence=dict(derived_from=dict(resolver='matched_signals')))
    # Bounded exact-file context for a created content-classified script.
    # Preserve the short-window lead; do not lower the global YARA reference gate.
    created = deepcopy(detectors['category_qualified_webshell_artifact'])
    created['inputs']['signals'].append('evidence_web_file_created')
    created['conditions']['groups'][0]['signals'].append('evidence_web_file_created')
    created['emissions'][0].update(name='webshell_created_artifact', rule_id='WEBSHELL_CREATED_ARTIFACT',
        description='Newly created web-root script has direct AV/YARA web-shell category support; bounded file-context seed, not execution proof')
    detectors['webshell_created_artifact'] = created
    deletion = deepcopy(next(r for r in direct['ordered_rules'] if r['id']=='evidence_web_file_created'))
    deletion.update(id='evidence_web_file_deleted', emission='evidence_web_file_deleted',
        description='Observed deletion of an unambiguously mapped web file ends earlier file context')
    deletion['when']['all'][1] = dict(any=[dict(input='timestamp_kind',op='equals_any',values=['delete']),
                                         dict(input='message',op='contains_any',values=['USN_REASON_FILE_DELETE'])])
    direct['ordered_rules'].append(deletion)
    direct['emissions']['evidence_web_file_deleted'] = deepcopy(direct['emissions']['evidence_web_file_created'])
    direct['emissions']['evidence_web_file_deleted'].update(name='evidence_web_file_deleted',rule_id='EVIDENCE_WEB_FILE_DELETED',
        description=deletion['description'])
    detectors['webshell_activity']['key']['case_sensitive'] = True
    detectors['webshell_activity']['reset_signals'] = ['evidence_web_file_deleted']
    carry = deepcopy(detectors['webshell_activity'])
    carry.update(lookback='7d', reset_signals=['evidence_web_file_deleted'])
    carry['key']['case_sensitive'] = True
    carry['source']['any_signals'] = ['webshell_created_artifact']
    carry['target']['where'] = dict(match='all',integral_range=dict(field='chronosift_web_status_code',minimum=200,maximum_exclusive=300))
    carry['emissions'][0].update(rule_id='WEBSHELL_CREATED_FILE_ACTIVITY',
        description='Successful HTTP response from the same created, web-shell-classified script within the bounded file-context window; request is not proof of command execution')
    carry['evidence'].update(http_status=dict(resolver='target_field',field='chronosift_web_status_code'))
    # Raw routes remain separate; one later projection owns the existing score.
    detectors['webshell_activity']['emissions'][0].update(name='webshell_activity_recent',rule_id='WEBSHELL_ACTIVITY_RECENT')
    carry['emissions'][0]['name'] = 'webshell_created_file_context'
    detectors['webshell_created_file_activity'] = carry
    detectors['webshell_activity_priority'] = dict(stage='temporal',executor='signal_projection',enabled=True,
        evidence_type='contextual',projections=[dict(inputs=dict(signals=['webshell_activity_recent','webshell_created_file_context']),
        conditions=dict(match='any',minimum_value_exclusive=0),strength='maximum_matched_times_emission_value',
        emissions=[dict(name='webshell_activity',value=1,rule_id='WEBSHELL_ACTIVITY',
          description='File-linked web-shell request context counted once across recent-artifact and bounded created-file routes; command execution remains unproved',
          confidence='medium',attack_ids=['T1505.003'],attack_basis='contextual_inference',
          attack_note='Qualified file-linked request context supports a web-shell candidate, not proven local command execution')])],
        evidence=dict(derived_from=dict(resolver='matched_signals')))
    detectors['web_service_disruption'] = dict(stage='temporal', executor='rate_change_window',
        enabled=True, evidence_type='contextual', bucket_period='1m',
        recent_window='15m', reference_window='60m', value_field='chronosift_web_status_code',
        key=dict(fields=['hostname','chronosift_web_host','chronosift_web_endpoint'],
                 required_fields=['chronosift_web_endpoint']),
        numerator_range=dict(minimum=500, maximum_exclusive=600),
        denominator_ranges=[dict(minimum=200, maximum_exclusive=300),dict(minimum=500, maximum_exclusive=600)],
        minimum_recent_count=10, minimum_reference_count=30, minimum_numerator_count=3,
        minimum_recent_buckets=2, minimum_rate_increase=.2, emit_on='numerator',
        emissions=[dict(name='web_service_disruption', value=1, rule_id='WEB_SERVICE_DISRUPTION',
            description='Route-scoped increase in server-error response fraction relative to preceding observed traffic; retrospective service-impact context, not a client attribution',
            confidence='medium', attack_ids=[], attack_basis='unmapped',
            attack_note='Service disruption may corroborate post-breach impact; status alone does not identify an attacker or establish an ATT&CK technique.')])
    return doc


def weights():
    doc=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v22.yaml').read_text())
    w=doc['weights']
    w['web_service_disruption']=8
    for name in ('privileged_login','lateral_movement_indicator','external_remote_service',
                 'fail_then_success_user','fail_then_success_ip','new_country','new_asn','new_city',
                 'boundary_crossing','impossible_travel'):
        w[name]=0
    w.update(smb_network_logon_candidate=0,windows_account_new_source=2,
        auth_failure_success_episode=0,auth_failure_context=2,auth_failure_episode_priority=6,
        auth_geographic_novelty=4,auth_anomalous_travel=8,auth_takeover_candidate=20,
        auth_privileged_takeover=4)
    for route in ('travel', 'authentication'):
        for suffix in ('account_use', 'privileged_account_use'):
            w[f'windows_risky_creator_{route}_{suffix}']=0
    w.update(auth_suspected_compromise_priority=8,webshell_created_artifact=0,evidence_web_file_deleted=0,webshell_activity_recent=0,webshell_created_file_context=0)
    for name in ('auth_sustained_bruteforce_success','auth_corroborated_bruteforce_success',
                 'auth_account_compromise_context','auth_suspected_compromise_source_use',
                 'auth_suspected_compromise_novel_use','auth_corroborated_compromise_source_use',
                 'auth_corroborated_compromise_novel_use','auth_corroborated_compromise_sensitive_action',
                 'windows_created_by_compromised_account','windows_compromised_creator_privileged_account',
                 'windows_compromised_creator_account_use','windows_compromised_creator_privileged_account_use',
                 'windows_compromised_creator_action'):
        w[name]=0
    return doc


def render():
    from benchmarks.build_attack_metadata_policy import matrix
    doc=build()
    return {
        'rules/rules_evidence_calibrated_v27.yaml': '# Generated by benchmarks/build_authentication_context_policy.py; historical v26 unchanged.\n'+yaml.safe_dump(doc,sort_keys=False,width=120),
        'rules/weights_evidence_calibrated_v23.yaml': '# Qualified authentication priority; routine privileged/remote protocol labels are context, not independent danger.\n'+yaml.safe_dump(weights(),sort_keys=False,width=120),
        'docs/ATTACK_MATRIX_CURRENT.md':matrix(doc,27,weights_version=23),
    }


if __name__=='__main__':
    sys.path.insert(0,str(ROOT))
    print('*** Begin Patch')
    for name,content in render().items():
        path=ROOT/name
        if not path.exists():
            print('*** Add File: '+name)
            for line in content.splitlines():print('+'+line)
        elif path.read_text()!=content:
            print('*** Update File: '+name)
            diff=list(difflib.unified_diff(path.read_text().splitlines(),content.splitlines(),n=3))
            for line in diff[2:]:print('@@' if line.startswith('@@') else line)
    print('*** End Patch')
