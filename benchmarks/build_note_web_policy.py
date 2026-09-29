"""Build v26/v22: weak URL-name leads and content-qualified ransom notes.

External YARA rule identities are reviewed content classifiers, not evidence
filenames or dataset IOCs. Adding a future note detector is a YAML-policy edit;
the generic engine does not contain vendor/family names.
"""
from copy import deepcopy
from pathlib import Path
import difflib
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
NOTE_RULES = [
    'TRELLIX_ARC_Clop_Ransom_Note',
    'TRELLIX_ARC_Ransom_Note_Kraken_Cryptor_Ransomware',
    'TELEKOM_SECURITY_Crylock_Hta',
    'SIGNATURE_BASE_Wannacry_Ransomnote',
    'SIGNATURE_BASE_MAL_SUSP_RANSOM_Lockbit_Ransomnote_Feb24',
    'SIGNATURE_BASE_MAL_SUSP_RANSOM_Lazy_Ransomnote_Feb24',
]


def build():
    doc = yaml.safe_load((ROOT/'rules/rules_evidence_calibrated_v25.yaml').read_text())
    by_id = {rule['id']: rule for rule in doc['rules']}
    syntax = by_id['WEB_SUSPICIOUS_PATHS']
    probe = deepcopy(syntax)
    probe.update(id='WEB_SHELL_NAME_PROBE', priority=74,
        description='HTTP request for a shell-like path name only; weak probing lead, not shell presence, execution or successful exploitation')
    probe['when']['any'][0]['value'] = r'(?i)(/cmd\.php(?:[/?#\s]|$)|/shell\.php(?:[/?#\s]|$)|/webshell|/c99|/r57)'
    probe['emit']['signals'] = [dict(name='web_shell_name_probe',value=1)]
    probe['attack_note'] = 'A single path-name probe, including HTTP 404 or unknown status, is weak triage context and does not establish T1505.003 or T1190.'
    syntax['description'] = 'HTTP request contains traversal, sensitive-path access or command-parameter syntax; attempted behaviour can remain relevant on HTTP 404'
    syntax['when']['any'][0]['value'] = r'(?i)(\.php\?cmd=|\.php\?exec=|\.php\?shell=|\.{2}/|/etc/passwd)'
    doc['rules'].insert(doc['rules'].index(syntax)+1,probe)

    detectors = doc['detector_policy']['detectors']
    yara = detectors['yara_classification']
    # First-match role separation: a note tagged RANSOMWARE is not an encryptor.
    yara['classification']['ordered_rules'][0:0] = [
        dict(id='reviewed_ransom_note_content',category='ransom_note',all=[
            dict(field='rule_name',op='equals_any',values=NOTE_RULES)]),
        dict(id='explicit_ransom_note_category',category='ransom_note',all=[
            dict(field='category',op='equals_any',values=['ransom_note'])]),
        dict(id='explicit_ransom_note_type',category='ransom_note',all=[
            dict(field='tc_detection_type',op='equals_any',values=['ransom_note'])]),
    ]
    note = deepcopy(yara['categories']['ransomware'])
    note['qualification'] = dict(minimum_score=50,minimum_quality=50)
    # Full includes lower-score rules than extended. Keep the threshold explicit
    # and bounded; raw match strength remains even below category qualification.
    note['emission'].update(name='yara_ransom_note',rule_id='YARA_RANSOM_NOTE',
        description='YARA content detection identifies a ransom-note artefact; not evidence that this file is an encryptor or that encryption occurred',
        attack_ids=['T1486'],attack_basis='contextual_inference',
        attack_note='Ransom-note content supports investigation of Data Encrypted for Impact (T1486), not confirmed encryption, family attribution or local deployment.')
    yara['categories']['ransom_note'] = note
    # Deliberately not added to referenced-file malware/execution qualification:
    # reading a note must not become execution of a ransomware payload.

    impact = detectors['ransomware_impact']['branches']['ransom_note']
    impact.pop('basename_contains')
    impact.update(any_signals=['yara_ransom_note'],minimum_signal_value_exclusive=0,
        exclude_same_artifact=True,
        description='Ransomware-specific indicators co-occurred with a distinct YARA content-qualified ransom-note artefact; encryption and causation remain unproved')
    detectors['ransomware_impact']['evidence'].update(
        ransom_note_path=dict(resolver='ransom_note_path'),
        ransom_note_signals=dict(resolver='ransom_note_signals'))

    direct = detectors['direct_attack_semantics']
    row = next(r for r in direct['ordered_rules'] if r['id']=='windows_note_created')
    row['when']['all'][-1] = dict(op='signal_any_positive',signals=['yara_ransom_note'],minimum_value_exclusive=0)
    description = 'Created file has direct YARA ransom-note content evidence; creation timestamp does not establish author or encryption'
    row['description'] = description
    direct['emissions']['windows_note_created'].update(description=description,
        attack_note='Qualified ransom-note content and a creation timestamp support context; the temporal rule supplies the ransomware relationship.')
    for name in ('windows_unattributed_note_created',):
        row = next(r for r in direct['ordered_rules'] if r['id']==name)
        row['description'] = 'Created YARA-qualified ransom note without attributable SID/profile; weaker same-image context only'
        direct['emissions'][name]['description'] = row['description']
    # A note's own AV classification must not seed a payload-to-note sequence.
    row = next(r for r in direct['ordered_rules'] if r['id']=='windows_ransomware_presence')
    row['when']['all'].append({'not':dict(op='signal_any_positive',signals=['yara_ransom_note'],minimum_value_exclusive=0)})
    for rule in doc['temporal_rules']:
        if rule['id'].startswith('WINDOWS_RANSOM_NOTE_'):
            rule['description'] = ('Ransomware artefact followed by a created YARA content-qualified ransom note in the configured account/image window; '
                                   'context for T1486, not proof of encrypted files or common author')
    return doc


def weights():
    doc=yaml.safe_load((ROOT/'rules/weights_evidence_calibrated_v21.yaml').read_text())
    doc['weights'].update(web_shell_name_probe=1,yara_ransom_note=8)
    return doc


def render():
    from benchmarks.build_attack_metadata_policy import matrix
    doc=build()
    return {
        'rules/rules_evidence_calibrated_v26.yaml': '# Generated by benchmarks/build_note_web_policy.py; v25 remains unchanged.\n'+yaml.safe_dump(doc,sort_keys=False,width=120),
        'rules/weights_evidence_calibrated_v22.yaml': '# V21 unchanged except two new signals: weak URL-name probe 1; content-qualified ransom note 8.\n'+yaml.safe_dump(weights(),sort_keys=False,width=120),
        'docs/ATTACK_MATRIX_CURRENT.md':matrix(doc,26,weights_version=22),
    }


if __name__=='__main__':
    sys.path.insert(0,str(ROOT))
    print('*** Begin Patch')
    for name, content in render().items():
        path=ROOT/name
        if not path.exists():
            print('*** Add File: '+str(path));print('\n'.join('+'+line for line in content.splitlines()))
        elif path.read_text()!=content:
            print('*** Update File: '+str(path))
            for line in list(difflib.unified_diff(path.read_text().splitlines(),content.splitlines(),n=3))[2:]:
                print('@@' if line.startswith('@@') else line)
    print('*** End Patch')
