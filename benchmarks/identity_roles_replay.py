"""Frozen v17 replay against the completed v16 candidate, not the old engine.

Uses the exact five bounded fixtures and complete selected authentication/tool
history. The full dataset worker is a separate, production-profile validation.
"""
import argparse
from dataclasses import replace
from functools import partial
import gc
import importlib.util
import json
import logging
from pathlib import Path
import shutil
import sys
import time

import duckdb
import pandas as pd
import context_provenance_replay as common

WT=Path(__file__).resolve().parents[1]
PIPE=WT.parent.parent
PREVIOUS=PIPE/'working/20260909-context-final-nHnzWZ'
HISTORY=PIPE/'working/20260909T123739Z-context-repair-bVXktt/windows-complete-auth-tool-history/input'
FILES=['chronoSIFT_v2_31.py','run_chronosift_sidecar_cli.py',
       'rules/rules_evidence_calibrated_v17.yaml','rules/weights_evidence_calibrated_v15.yaml',
       'benchmarks/identity_roles_replay.py','benchmarks/context_provenance_replay.py',
       'benchmarks/build_identity_roles_policy.py','tests/test_v231_identity_roles.py','docs/IDENTITY_ROLES.md']


def prepare(out):
    receipt=json.loads((PREVIOUS/'validation.json').read_text())
    assert receipt['status']=='passed'
    before=json.loads((PREVIOUS/'provenance.json').read_text())
    source=out/'source';source.mkdir()
    hashes={}
    for name in FILES:
        src=WT/name;dest=source/src.name;shutil.copy2(src,dest)
        hashes[str(src)]=common.sha(src);hashes[str(dest)]=common.sha(dest)
    resources=before['resources']
    for value in resources.values():
        assert common.sha(Path(value))==before['hashes'][value],('Changed baseline resource',value)
        hashes[value]=before['hashes'][value]
    for name,dataset in before['cases']:
        for path in Path(dataset).rglob('*.parquet'):
            assert common.sha(path)==before['hashes'][str(path)]
            hashes[str(path)]=before['hashes'][str(path)]
        for path in (PREVIOUS/name/'candidate').iterdir():
            if path.is_file():hashes[str(path)]=common.sha(path)
    for path in HISTORY.rglob('*.parquet'):hashes[str(path)]=common.sha(path)
    hashes[str(PREVIOUS/'native-history/scores.parquet')]=common.sha(PREVIOUS/'native-history/scores.parquet')
    common.save(out/'provenance.json',dict(hashes=hashes,resources=resources,cases=before['cases'],
        previous=str(PREVIOUS),history=str(HISTORY),scope='Frozen v17 candidate versus final v16 scalar scores; actual resources, neutral profiling, no NSRL; not full production validation.'))
    print('FROZEN',out,flush=True)


def load(out):
    p=json.loads((out/'provenance.json').read_text());source=out/'source'
    spec=importlib.util.spec_from_file_location('identity_candidate',source/'chronoSIFT_v2_31.py')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    resources={key:Path(value) for key,value in p['resources'].items()}
    engine=module.ChronoSiftEngine.from_yaml(source/'rules_evidence_calibrated_v17.yaml',
        source/'weights_evidence_calibrated_v15.yaml',yara_metadata_path=str(resources['yara']))
    return p,module,engine,resources


def role_examples(output,path):
    ids={13430615,13432066,13433555,13433556,13433561,13433562,11243208,11628952,11628979,12199528,12147014}
    fields=['chronosift_row_id','actor_principal','identity_reporting_sid','identity_authenticated_account',
        'identity_authenticated_sid','identity_acting_account','identity_acting_sid','identity_affected_account',
        'identity_affected_sid','identity_affected_group','identity_affected_group_sid','continuity_key','win_context_sid',
        'chronosift_score','chronosift_explain']
    rows=output.loc[output.chronosift_row_id.isin(ids),fields].to_dict(orient='records')
    common.save(path/'identity-examples.json',rows)


def bounded(out):
    p,_,_,_=load(out);results=[]
    for name,directory in p['cases']:
        _,module,engine,resources=load(out)
        path=out/name/'candidate';path.mkdir(parents=True);dataset=Path(directory)
        before=pd.read_parquet(Path(p['previous'])/name/'candidate/scores.parquet')
        start=time.monotonic();manifest=common.manifest_for(module,engine,dataset,resources)
        raw=module.load_plaso_parquet_dataset(str(dataset));ids=raw.chronosift_row_id.tolist()
        print('BOUNDED',name,len(raw),flush=True)
        output=engine.apply_contextual(engine.apply_atomic(raw,apply_profiling=False,
            **{k:str(v) for k,v in resources.items() if k!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
        assert output.chronosift_row_id.tolist()==ids
        scalar,summary=common.summarise(output,engine,path,time.monotonic()-start,before)
        role_examples(output,path)
        results.append(dict(case=name,**summary));print('BOUNDED RESULT',name,summary,flush=True)
        del raw,output,engine,module,manifest,before,scalar;gc.collect()
    common.save(out/'bounded-summary.json',results)


def native(out):
    p,module,engine,resources=load(out);path=out/'native-history';path.mkdir();dataset=Path(p['history'])
    engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
    engine._apply_non_temporal_contextual_sparse=partial(engine._apply_non_temporal_contextual_sparse,
        retain_zero_weight_lifecycle_signals=False)
    manifest=common.manifest_for(module,engine,dataset,resources);start=time.monotonic()
    raw=module.load_plaso_parquet_dataset(str(dataset))
    output=engine.apply_contextual(engine.apply_atomic(raw,apply_profiling=False,
        **{k:str(v) for k,v in resources.items() if k!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
    before=pd.read_parquet(Path(p['previous'])/'native-history/scores.parquet')
    # These are regression witnesses in evaluation only, never detector inputs.
    # Event-role repair must not break established bare-name privilege/failure
    # consumers. Check before spending time on the native monthly replay.
    witnessed=output.set_index('chronosift_row_id')
    for rid,names in {11243208:['privileged_login','exec_privileged_context','fail_then_success_user'],
                      11628952:['windows_risky_creator_context'],
                      12199528:['windows_risky_creator_context','windows_first_observed_dual_use_execution']}.items():
        assert all(witnessed.loc[rid,'chronosift_signals'].get(name) for name in names),(rid,'lost established feature')
    del witnessed
    _,summary=common.summarise(output,engine,path,time.monotonic()-start,before);role_examples(output,path)
    expected={int(row.chronosift_row_id):(float(row.chronosift_score),row.chronosift_signals or {},row.actor_principal)
              for _,row in output.iterrows()}
    del raw,output,before;gc.collect()
    engine.process_parquet_dataset_partitioned(str(dataset),str(path/'sidecar'),output_mode='sidecar',
        materialise_event_columns=True,file_hit_manifest=manifest,
        **{k:str(v) for k,v in resources.items() if k!='yara'})
    con=duckdb.connect()
    try:rows=con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_signals,chronosift_explain,actor_principal FROM read_parquet(?,union_by_name=true)',[str(path/'sidecar/**/*.parquet')]).fetchall()
    finally:con.close()
    assert len(rows)==len(expected) and {r[0] for r in rows}==set(expected)
    mismatches=[]
    for rid,score,signals,explain,actor in rows:
        signals=signals or {};explain=[json.loads(e) for e in (explain or [])]
        assert abs(score-engine._score_signals(signals))<1e-5
        assert abs(score-min(50,sum(e['score_contribution'] for e in explain)))<1e-5
        wanted=expected[rid];expected_actor=None if pd.isna(wanted[2]) else wanted[2]
        if abs(score-wanted[0])>1e-6 or signals!=wanted[1] or actor!=expected_actor:mismatches.append(rid)
        assert all(e['canonical_actor']==actor for e in explain),(rid,'canonical_actor')
    common.save(path/'partition-comparison.json',dict(**summary,partition_mismatches=len(mismatches),mismatch_ids=mismatches))
    assert not mismatches,mismatches[:15]
    print('NATIVE PASSED',len(rows),flush=True)


def finish(out):
    p=json.loads((out/'provenance.json').read_text())
    native_result=json.loads((out/'native-history/partition-comparison.json').read_text())
    results=json.loads((out/'bounded-summary.json').read_text())
    assert native_result['partition_mismatches']==0 and len(results)==5
    for name,digest in p['hashes'].items():assert common.sha(Path(name))==digest,('Changed validation provenance',name)
    common.save(out/'validation.json',dict(status='passed',evaluated_rows=sum(r['rows'] for r in results),
        native_rows=native_result['rows'],candidate_native_partition_mismatches=0,
        all_keys_scores_explanations_readbacks_valid=True,hashes_unchanged=True))
    print('VALIDATION PASSED',flush=True)


if __name__=='__main__':
    logging.Formatter.converter=time.gmtime
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['prepare','bounded','native','finish']);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();globals()[args.mode](args.output.resolve())
