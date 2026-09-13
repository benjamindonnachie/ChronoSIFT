"""Candidate-only final policy verification against immutable validated baselines.

Prepare once, run native/bounded independently, then finish hash verification.
This reuses only before-change scores, never candidate outputs.
"""
import argparse
from dataclasses import replace
from functools import partial
import gc
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time

import duckdb
import pandas as pd
import context_provenance_replay as replay


def save(path,value):replay.save(path,value)


def prepare(out,previous):
    assert json.loads((previous/'validation.json').read_text())['status']=='passed'
    replay.freeze(out)
    current=json.loads((out/'provenance.json').read_text())
    earlier=json.loads((previous/'provenance.json').read_text())
    evidence_paths=list(current['resources'].values())
    for _,root in current['cases']:evidence_paths += [str(p) for p in Path(root).rglob('*.parquet')]
    assert all(current['hashes'][p]==earlier['hashes'][p] for p in evidence_paths), 'Cached baseline uses different evidence/resources'
    shutil.copy2(__file__,out/'source/final_context_replay.py')
    cached=[previous/'validation.json',previous/'provenance.json',previous/'windows-complete-auth-tool-history/source-provenance.json']
    for name,_ in replay.CASES:cached += list((previous/name/'baseline').glob('*'))
    cached += list((previous/'baseline').glob('*'))
    cached += list((previous/'windows-complete-auth-tool-history/input').rglob('*.parquet'))
    cached += [previous/'windows-complete-auth-tool-history/baseline/scores.parquet']
    hashes={str(path):replay.sha(path) for path in cached if path.is_file()}
    hashes[str(Path(__file__).resolve())]=replay.sha(Path(__file__))
    for path in (out/'baseline').iterdir():
        assert replay.sha(path)==replay.sha(previous/'baseline'/path.name)
    save(out/'baseline-reuse.json',dict(previous=str(previous),hashes=hashes,
        scope='Reuse only validated pre-change engine v15/v14 scalar baselines and immutable selected input. Final candidate recomputed. Engine unchanged; YAML now requires complete scoped continuity identity.'))


def load(out):
    provenance=json.loads((out/'provenance.json').read_text());reuse=json.loads((out/'baseline-reuse.json').read_text())
    resources={key:Path(value) for key,value in provenance['resources'].items()}
    replay.CASES=[(name,Path(path)) for name,path in provenance['cases']]
    modules={}
    for label,folder in [('baseline',out/'baseline'),('candidate',out/'source')]:
        name='final_context_'+label;spec=importlib.util.spec_from_file_location(name,folder/'chronoSIFT_v2_31.py')
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
        modules[label]=(module,folder)
    return modules,resources,Path(reuse['previous'])


def bounded(out):
    modules,resources,previous=load(out);results=[]
    for name,input_dir in replay.CASES:
        path=out/name/'candidate';path.mkdir(parents=True);start=time.monotonic()
        before=pd.read_parquet(previous/name/'baseline/scores.parquet')
        module,engine=replay.engine_for('candidate',modules,resources)
        manifest=replay.manifest_for(module,engine,input_dir,resources)
        data=module.load_plaso_parquet_dataset(str(input_dir));ids=data.chronosift_row_id.tolist()
        print('final candidate',name,len(data),flush=True)
        output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,
            **{key:str(value) for key,value in resources.items() if key!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
        assert output.chronosift_row_id.tolist()==ids
        scalar,summary=replay.summarise(output,engine,path,time.monotonic()-start,before)
        baseline=json.loads((previous/name/'baseline/evaluation.json').read_text())
        results.append(dict(case=name,baseline={k:v for k,v in baseline.items() if k not in ('examples','lost_examples')},candidate=summary))
        print('final candidate result',name,summary,flush=True)
        del data,output,before,engine,manifest,scalar;gc.collect()
    save(out/'bounded-summary.json',results)


def native(out):
    modules,resources,previous=load(out)
    input_dir=previous/'windows-complete-auth-tool-history/input'
    path=out/'native-history';path.mkdir();start=time.monotonic()
    module,engine=replay.engine_for('candidate',modules,resources)
    engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
    engine._apply_non_temporal_contextual_sparse=partial(engine._apply_non_temporal_contextual_sparse,
        retain_zero_weight_lifecycle_signals=False)
    manifest=replay.manifest_for(module,engine,input_dir,resources)
    data=module.load_plaso_parquet_dataset(str(input_dir))
    print('final native reference',len(data),flush=True)
    output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,
        **{key:str(value) for key,value in resources.items() if key!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
    before=pd.read_parquet(previous/'windows-complete-auth-tool-history/baseline/scores.parquet')
    scalar,summary=replay.summarise(output,engine,path,time.monotonic()-start,before)
    expected={int(row.chronosift_row_id):(float(row.chronosift_score),row.chronosift_signals or {}) for _,row in output.iterrows()}
    del output,data,before,scalar;gc.collect()
    engine.process_parquet_dataset_partitioned(str(input_dir),str(path/'sidecar'),output_mode='sidecar',
        file_hit_manifest=manifest,materialise_event_columns=True,
        **{key:str(value) for key,value in resources.items() if key!='yara'})
    con=duckdb.connect();records=con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_signals,chronosift_explain FROM read_parquet(?,union_by_name=true)',[str(path/'sidecar/**/*.parquet')]).fetchall();con.close()
    assert len(records)==len(expected) and {row[0] for row in records}==set(expected)
    mismatches=[]
    for rid,score,signals,explanations in records:
        signals=signals or {};explanations=[json.loads(e) if isinstance(e,str) else e for e in (explanations or [])]
        assert abs(score-engine._score_signals(signals))<1e-5,(rid,'native signals')
        assert abs(score-min(50,sum(e['score_contribution'] for e in explanations)))<1e-5,(rid,'native explanations')
        if abs(score-expected[rid][0])>1e-6 or signals!=expected[rid][1]:mismatches.append(rid)
    save(path/'partition-comparison.json',dict(**summary,partition_mismatches=len(mismatches),mismatch_ids=mismatches,total_seconds=time.monotonic()-start))
    assert not mismatches,('Final candidate native mismatch',mismatches[:10])
    print('FINAL NATIVE PASSED',len(records),flush=True)


def finish(out):
    native_result=json.loads((out/'native-history/partition-comparison.json').read_text())
    bounded_result=json.loads((out/'bounded-summary.json').read_text())
    provenance=json.loads((out/'provenance.json').read_text());reuse=json.loads((out/'baseline-reuse.json').read_text())
    raw=json.loads((Path(reuse['previous'])/'windows-complete-auth-tool-history/source-provenance.json').read_text())
    for hashes in (provenance['hashes'],reuse['hashes'],raw['hashes']):
        assert all(replay.sha(Path(path))==digest for path,digest in hashes.items()),'Source/resource/cache changed'
    assert native_result['partition_mismatches']==0 and len(bounded_result)==5
    save(out/'validation.json',dict(status='passed',bounded_rows=sum(r['candidate']['rows'] for r in bounded_result),
        complete_auth_tool_history_rows=native_result['rows'],candidate_native_partition_mismatches=0,
        all_keys_scores_explanations_readbacks_valid=True,source_resource_and_cached_baseline_hashes_unchanged=True,
        baseline_reused_from=reuse['previous']))
    print('FINAL VALIDATION PASSED',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['prepare','native','bounded','finish'])
    parser.add_argument('--output',required=True,type=Path);parser.add_argument('--previous',type=Path)
    args=parser.parse_args()
    if args.mode=='prepare':prepare(args.output,args.previous)
    else:globals()[args.mode](args.output)
