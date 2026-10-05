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
    project('auth_takeover_candidate',['auth_failure_success_episode','impossible_travel','auth_remote_success'],
        'Source-linked failures followed by success with impossible travel: combined account-takeover candidate, not independent votes for protocol labels',attack=['T1110','T1078'])
    project('auth_privileged_takeover',['auth_failure_success_episode','impossible_travel','auth_remote_success','privileged_login'],
        'Privileged account increases severity of the qualified takeover candidate; privilege alone adds no login danger',attack=['T1078'])
    detectors['authentication_context_priority'] = dict(stage='temporal',executor='signal_projection',enabled=True,
        evidence_type='contextual',projections=projections,evidence=dict(derived_from=dict(resolver='matched_signals')))
    return doc


def weights():
    doc=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v22.yaml').read_text())
    w=doc['weights']
    for name in ('privileged_login','lateral_movement_indicator','external_remote_service',
                 'fail_then_success_user','fail_then_success_ip','new_country','new_asn','new_city',
                 'boundary_crossing','impossible_travel'):
        w[name]=0
    w.update(smb_network_logon_candidate=0,windows_account_new_source=2,
        auth_failure_success_episode=0,auth_failure_context=2,auth_failure_episode_priority=6,
        auth_geographic_novelty=4,auth_anomalous_travel=8,auth_takeover_candidate=20,
        auth_privileged_takeover=4)
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
