"""Prepare a fresh frozen full-run bundle; does not launch or alter a checkout."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from run_final_dataset_validation import sha,save,stamp,RULES,WEIGHTS

def prepare(worktree,pipeline,validation):
    checked=json.loads((validation/'validation.json').read_text())
    if checked['status']!='passed' or checked['evaluated_rows']!=861371:
        raise ValueError('Complete final bounded evidence validation required')
    tests=json.loads((validation/'regression.json').read_text())
    if not tests['successful'] or tests['failures'] or tests['errors']:
        raise ValueError('Passing final regression receipt required')
    for path,digest in tests['sha256'].items():
        if sha(Path(path))!=digest:raise ValueError(f'Tested source changed: {path}')
    hashes=json.loads((validation/'provenance.json').read_text())['hashes']
    for path,digest in hashes.items():
        if sha(Path(path))!=digest: raise ValueError(f'Validated source/input changed: {path}')
    label=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    root=Path(tempfile.mkdtemp(prefix=label+'-chronosift-final-',dir=pipeline/'working'))
    source=root/'source'; source.mkdir()
    files=['chronoSIFT_v2_31.py','run_chronosift_sidecar_cli.py','summarize_chronosift_telemetry.py',
        'rules/'+RULES,'rules/'+WEIGHTS,
        'benchmarks/run_final_dataset_validation.py','benchmarks/audit_final_datasets.py',
        'benchmarks/prepare_final_dataset_validation.py','benchmarks/build_identity_roles_policy.py',
        'benchmarks/review_groundtruth_anchors.py','benchmarks/groundtruth_reviewed_anchors.json',
        'benchmarks/run_identity_regression.py',
        'docs/IDENTITY_ROLES.md','docs/DATASET_IMPROVEMENTS.md','docs/CONTEXT_PROVENANCE.md',
        'tests/test_v231_identity_roles.py','tests/test_final_dataset_validation.py','tests/test_groundtruth_anchor_review.py']
    for name in files: shutil.copy2(worktree/name,source/Path(name).name)
    oldwin=pipeline/'working/20260908T154700Z-chronosift-windows-full-xKbecp'
    oldubuntu=pipeline/'working/20260907T142709Z-chronosift-ubuntu-full'
    shutil.copy2(oldwin/'audit_windows.py',source/'windows_audit_reference.py')
    shutil.copy2(oldwin/'groundtruth.json',source/'groundtruth_windows.json')
    ubuntu=json.loads((oldubuntu/'validity-20260908/provenance.json').read_text())
    ledger=ubuntu['ledger']
    for event in ledger: event['anchor_ids']=[int(value) for value in event['plaso_event_ids'].split(';') if value]
    save(source/'groundtruth_ubuntu.json',dict(source=ubuntu['gt'],sha256=ubuntu['gt_sha256'],rows=ledger))
    for case in ('windows','ubuntu'):
        gt=json.loads((source/f'groundtruth_{case}.json').read_text())
        if sha(Path(gt['source']))!=gt['sha256']: raise ValueError('Ground truth no longer matches validated ledger')
    from review_groundtruth_anchors import prepare as review_anchors
    review_anchors(source,pipeline)
    save(source/'baseline_runs.json',dict(windows=str(oldwin),ubuntu=str(oldubuntu)))
    shutil.copy2(validation/'validation.json',source/'bounded_validation.json')
    shutil.copy2(validation/'provenance.json',source/'bounded_provenance.json')
    shutil.copy2(validation/'regression.json',source/'regression.json')
    save(source/'manifest.json',dict(created_utc=stamp(),worktree=str(worktree),
        branch=subprocess.check_output(['git','branch','--show-current'],cwd=worktree,text=True).strip(),
        commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=worktree,text=True).strip(),
        dirty_diff_sha256=__import__('hashlib').sha256(subprocess.check_output(['git','diff'],cwd=worktree)).hexdigest(),
        bounded_validation=str(validation),sha256={p.name:sha(p) for p in sorted(source.iterdir()) if p.is_file()}))
    print(root,flush=True)
    return root

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--worktree',type=Path,required=True)
    parser.add_argument('--pipeline',type=Path,required=True); parser.add_argument('--validation',type=Path,required=True)
    args=parser.parse_args(); prepare(args.worktree.resolve(),args.pipeline.resolve(),args.validation.resolve())
