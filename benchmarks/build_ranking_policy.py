"""Build immutable v22/v20 ranking refinements; AV classification unchanged."""
from pathlib import Path
import difflib
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = r'(?i)^/(?:[^/]+/)*[^/]+\.(?:php|phtml|php[345]|asp|aspx|ashx|jsp|jspx|cgi|pl)$'
HINT = r'(?i)^/(?:[^/]+/)*[^/]*(?:cmd|shell|c99|r57|b374k|wso|filemanager|upload)[^/]*\.(?:php|phtml|php[345]|asp|aspx|ashx|jsp|jspx|cgi|pl)$'
INTERPRETER = (r'''(?i)(?:^|&&\s*)\s*(?:(?:/[^\s"';&|]+/)?nohup\s+)?["']?'''
               r'''(?:/[^\s"';&|]+/)?(?:python(?:[0-9.]+)?|perl|php[0-9.]*|ruby|bash|dash|ksh|zsh|sh)["']?(?:\s|$)''')


def projection(signals, name, description):
    return dict(inputs=dict(signals=signals),
        conditions=dict(match='all', minimum_value_exclusive=0),
        strength='maximum_matched_times_emission_value',
        emissions=[dict(name=name,value=1,rule_id=name.upper(),description=description,confidence='medium')])


def projector(stage, projections):
    return dict(stage=stage,executor='signal_projection',enabled=True,evidence_type='contextual',
        projections=projections,evidence=dict(derived_from=dict(resolver='matched_signals')))


def build():
    r=yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v21.yaml').read_text())
    w=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v19.yaml').read_text())
    d=r['detector_policy']['detectors']
    # T1053.003: scheduling/frequency is a fact, not payload qualification.
    # https://attack.mitre.org/techniques/T1053/003/
    interpreter=next(x for x in r['rules'] if x['id']=='INTERPRETER_EXEC_LINUX')
    interpreter['when']['any']=[x for x in interpreter['when']['any'] if x['field']!='message']
    interpreter['when']['any'].append(dict(field='linux_cron_command',op='regex',value=INTERPRETER))
    interpreter['emit']['evidence'].append(dict(field='linux_cron_command'))
    interpreter['description']='Linux interpreter invocation syntax observed; a cron CMD wrapper alone is not interpreter evidence'
    w['weights'].update(scheduled_exec=1,privileged_scheduled_exec=2,repeated_scheduled_exec=1)
    projections=[]
    # The invocation detector selects one candidate: exact path takes priority
    # over repository attribution. The routes are mutually exclusive, tested
    # below; no same-phase projection chaining or duplicate signal ownership.
    for route in ('file','repository'):
        qualified='linux_qualified_'+route+'_invocation'
        for observed,dimension,points,desc in [
            ('scheduled_exec','context',2,'Schedule invokes an evidence-qualified payload'),
            ('privileged_scheduled_exec','privilege',5,'Privileged schedule invokes an evidence-qualified payload'),
            ('repeated_scheduled_exec','repetition',6,'Repeated schedule invokes an evidence-qualified payload'),
        ]:
            name='linux_qualified_'+route+'_schedule_'+dimension
            projections.append(projection([observed,qualified],name,
                desc+'; exact-file versus weaker repository attribution remains in the source explanation, effects unproved (ATT&CK T1053.003)'))
            w['weights'][name]=points
    # Qualified invocation is populated AFTER contextual adjustments. These
    # projections run at the final temporal stage, after repetition as well.
    # Mutually exclusive route names preserve the evidence distinction.
    d['linux_qualified_schedule_priority']=projector('temporal',projections)

    # T1505.003: filename-only evidence cannot establish a web shell.
    # https://attack.mitre.org/techniques/T1505/003/
    # Preserve the old schema and historical policy; no magic token sentinel
    # and no Python parser changes to make empty lists acceptable.
    d['webshell_artifact']['enabled']=False
    d['webshell_artifact']['emissions'][0]['name']='webshell_legacy_artifact'
    d['webshell_artifact']['emissions'][0]['rule_id']='WEBSHELL_LEGACY_ARTIFACT'
    w['weights']['webshell_legacy_artifact']=0
    direct=d['direct_attack_semantics']
    direct['inputs']['web_file_relative']=dict(resolver='row_field',fields=['evidence_web_file_relative'],normalise='none')
    direct['evidence']['web_file_relative']=dict(resolver='input',input='web_file_relative')
    for name,pattern,desc in [
        ('web_script_artifact_candidate',SCRIPT,'Executable script mapped to an explicitly configured web root; structural candidate, no malicious verdict'),
        ('webshell_name_hint',HINT,'Web-root script has a suggestive basename only; weak investigator hint, not a web shell or evidence of use (ATT&CK T1505.003 candidate)'),
    ]:
        direct['ordered_rules'].append(dict(id=name,
            when=dict(input='web_file_relative',op='regex',pattern=pattern),emission=name,
            description=desc,confidence='low',evidence=['web_file_relative','path']))
        direct['emissions'][name]=dict(name=name,value=1,rule_id=name.upper(),description=desc,confidence='low')
    w['weights'].update(web_script_artifact_candidate=0,webshell_name_hint=1)
    emission=projection(['web_script_artifact_candidate'],'webshell_artifact',
        'Web-root executable script has direct AV/YARA web-shell category support; presence is not execution (ATT&CK T1505.003)')['emissions']
    d['category_qualified_webshell_artifact']=dict(stage='contextual',executor='signal_gate',enabled=True,evidence_type='contextual',
        inputs=dict(signals=['web_script_artifact_candidate','av_webshell','yara_webshell']),
        conditions=dict(match='all',minimum_value_exclusive=0,groups=[
            dict(match='all',signals=['web_script_artifact_candidate']),dict(match='any',signals=['av_webshell','yara_webshell'])]),
        emissions=emission,evidence=dict(derived_from=dict(resolver='matched_signals')))
    # Qualified HTTP access/upload semantics remain independently governed by
    # typed file correlation; generic referenced hits no longer label a script
    # a shell merely because its message mentions some other malicious file.
    adjust=d['contextual_signal_adjustments']
    adjust['ordered_rules'].append(dict(id='supported_webshell_hint_deduplication',
        when=dict(input='command',op='regex',pattern=r'(?s).*'),
        signal_conditions=dict(minimum_value_exclusive=0,required_all=['webshell_artifact']),
        target_signals=['webshell_name_hint'],action=dict(type='zero'),
        explanation=dict(rule_id='SUPPORTED_WEBSHELL_HINT_DEDUPLICATION',
            description='Category-supported web shell retains its stronger contribution; basename hint is not independent evidence',confidence='high'),
        evidence=['dampened_signals']))

    # T1543.002: changed unit metadata remains visible, but is not by itself
    # demonstrated persistence. Scope narrowly to actual Linux unit metadata;
    # never alter Windows service weights or explicit management commands.
    # https://attack.mitre.org/techniques/T1543/002/
    for name,field in [('unit_path','filename'),('unit_parser','parser')]:
        adjust['inputs'][name]=dict(resolver='row_field',fields=[field],normalise='none')
        adjust['evidence'][name]=dict(resolver='input',input=name)
    support=['av_hit','yara_hit_strength','referenced_file_av_hit','referenced_file_yara_hit',
        'evidence_qualified_malware_file','qualified_tool_file','suspicious_execution','linux_preload_control_change']
    for signal,multiplier in [('service_configuration_changed',2/7),('systemd_service_persistence',1/3)]:
        adjust['ordered_rules'].append(dict(id='bare_linux_unit_'+signal,
            when=dict(all=[dict(input='unit_parser',op='equals_any',values=['filestat']),
                dict(input='unit_path',op='regex',pattern=r'^/(?:etc|lib|usr/lib)/systemd/system/(?:[^/]+/)*[^/]+\.(?:service|socket|timer|mount|path)$')]),
            signal_conditions=dict(minimum_value_exclusive=0,forbidden_any=support),
            target_signals=[signal],action=dict(type='multiply',multiplier=multiplier),
            explanation=dict(rule_id=('BARE_LINUX_UNIT_'+signal).upper(),
                description='Linux unit metadata change without independent malware/tool support: retain low-priority change evidence, not proven persistence (ATT&CK T1543.002 candidate)',confidence='medium'),
            evidence=['unit_path','dampened_signals']))
    return r,w


def render():
    header=('# Generated by benchmarks/build_ranking_policy.py; historical policies preserved.\n'
            '# Evidence-qualified context is separate from routine observations and weak names.\n'
            '# ATT&CK rationale and limits: docs/RANKING_REFINEMENTS.md. AV classification unchanged.\n')
    return {name:header+yaml.safe_dump(doc,sort_keys=False,width=120) for name,doc in zip(
        ('rules/rules_evidence_calibrated_v22.yaml','rules/weights_evidence_calibrated_v20.yaml'),build())}


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
