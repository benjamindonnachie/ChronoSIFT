"""Finish a frozen context replay with identical lifecycle export contracts.

The original harness compared chronological retain-zero-label defaults with
native omit-zero-label defaults. Do not rewrite those diagnostic artifacts or
change engine behaviour: recompute the chronological reference using the same
existing omission flag, then validate the already generated native outputs.
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
import numpy as np
import pandas as pd


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


def main(out):
    replay=module('frozen_context_replay',out/'source/context_provenance_replay.py')
    provenance=json.loads((out/'provenance.json').read_text())
    resources={key:Path(value) for key,value in provenance['resources'].items()}
    replay.CASES=[(name,Path(path)) for name,path in provenance['cases']]
    modules={label:(module('completed_'+label,out/folder/'chronoSIFT_v2_31.py'),out/folder)
             for label,folder in [('baseline','baseline'),('candidate','source')]}
    assert all(replay.sha(Path(path))==digest for path,digest in provenance['hashes'].items())
    destination=out/'export-aligned-comparison';destination.mkdir()
    shutil.copy2(__file__,destination/'complete_context_validation.py')
    replay.save(destination/'provenance.json',dict(script_sha256=replay.sha(Path(__file__)),
        change='Chronological reference uses existing retain_zero_weight_lifecycle_signals=False, matching native default. No scoring/engine/rules changes; original diagnostics preserved.',
        engine_hashes={label:replay.sha(folder/'chronoSIFT_v2_31.py') for label,(_,folder) in modules.items()}))
    history=out/'windows-complete-auth-tool-history';results={}
    for label in ('baseline','candidate'):
        path=destination/label;path.mkdir();start=time.monotonic()
        engine_module,engine=replay.engine_for(label,modules,resources)
        engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
        engine._apply_non_temporal_contextual_sparse=partial(engine._apply_non_temporal_contextual_sparse,
            retain_zero_weight_lifecycle_signals=False)
        manifest=replay.manifest_for(engine_module,engine,history/'input',resources)
        data=engine_module.load_plaso_parquet_dataset(str(history/'input'))
        print('aligned reference',label,len(data),flush=True)
        output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,
            **{k:str(v) for k,v in resources.items() if k!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
        old=pd.read_parquet(history/label/'scores.parquet') if (history/label/'scores.parquet').exists() else None
        scalar,summary=replay.summarise(output,engine,path,time.monotonic()-start,old)
        expected={int(row.chronosift_row_id):(float(row.chronosift_score),row.chronosift_signals or {})
                  for _,row in output.iterrows()}
        # Preserve the complete reference for reproducible future comparisons.
        pd.DataFrame([dict(chronosift_row_id=rid,score=score,signals=signals)
                      for rid,(score,signals) in expected.items()]).to_parquet(path/'reference.parquet',index=False)
        del output,data,manifest;gc.collect()
        deadline=time.monotonic()+1800
        marker=history/label/'partition-comparison.json'
        while not marker.exists():
            if time.monotonic()>deadline:raise TimeoutError('Native output did not reach comparison marker')
            time.sleep(1)
        # All output rows were written before the marker. Original harness
        # subsequently fails its mismatched-export assertion, as documented.
        con=duckdb.connect()
        saved=con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_signals,chronosift_explain FROM read_parquet(?,union_by_name=true)',
                          [str(history/label/'sidecar/**/*.parquet')]).fetchall();con.close()
        assert len(saved)==len(expected) and {row[0] for row in saved}==set(expected)
        mismatches=[];score_mismatches=0
        for rid,score,signals,explanations in saved:
            signals=signals or {};explanations=[json.loads(e) if isinstance(e,str) else e for e in (explanations or [])]
            assert abs(score-engine._score_signals(signals))<1e-5,(rid,'native signals')
            assert abs(score-min(50,sum(e['score_contribution'] for e in explanations)))<1e-5,(rid,'native explanations')
            score_diff=abs(score-expected[rid][0])>1e-6;score_mismatches+=int(score_diff)
            if score_diff or signals!=expected[rid][1]:
                mismatches.append(dict(id=rid,chronological_score=expected[rid][0],partitioned_score=score,
                    chronological_signals=expected[rid][1],partitioned_signals=signals))
        old=pd.read_parquet(history/label/'scores.parquet').set_index('chronosift_row_id')
        assert np.array_equal(scalar.chronosift_score.to_numpy(),old.loc[scalar.chronosift_row_id,'chronosift_score'].to_numpy()),'Export setting changed scores'
        result=dict(**summary,partition_mismatches=len(mismatches),score_mismatches=score_mismatches,
                    export_setting_score_changes=0,examples=mismatches[:100])
        replay.save(path/'partition-comparison.json',result)
        if label=='candidate':assert not mismatches,('Actual candidate mismatch',len(mismatches),mismatches[:2])
        else:assert any(m['id']==11243208 and m['chronological_score']!=m['partitioned_score'] for m in mismatches)
        results[label]={key:value for key,value in result.items() if key!='examples'}
        print('aligned result',label,results[label],flush=True)
        del expected,saved,scalar,engine;gc.collect()
    comparisons=replay.bounded(out,modules,resources)
    source_provenance=json.loads((history/'source-provenance.json').read_text())
    for hashes in (provenance['hashes'],source_provenance['hashes']):
        assert all(replay.sha(Path(path))==digest for path,digest in hashes.items()),'Frozen source/resource changed'
    replay.save(out/'validation.json',dict(status='passed',bounded_rows=sum(r['candidate']['rows'] for r in comparisons),
        complete_auth_tool_history_rows=results['candidate']['rows'],candidate_native_partition_mismatches=0,
        all_keys_scores_explanations_readbacks_valid=True,source_and_resource_hashes_unchanged=True,
        export_aligned_history=results,original_replay_status='Failed comparison of different zero-weight lifecycle export settings; corrected by this separately frozen continuation without engine changes.'))
    print('COMPLETE',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path)
    main(parser.parse_args().output)
