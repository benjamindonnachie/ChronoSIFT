"""Frozen before/after evidence replay; new evaluation outputs only.

The bounded fixtures are not full corpus reruns. The separate complete-history
Windows authentication/PsExec cohort also exercises native monthly sidecars.
Ground-truth anchors select report examples, never detector inputs.
"""
import argparse
from collections import Counter
from dataclasses import replace
import gc
import hashlib
import importlib.util
import json
import logging
from pathlib import Path
import shutil
import sys
import time

import duckdb
import numpy as np
import pandas as pd

WT = Path(__file__).resolve().parents[1]
ROOT = WT.parent.parent
RAW = ROOT/'parquet/20240212-decrypted-Windows_Server_2022.E01~plaso-20260720~yara-rules-extended_20260719'
CROSS = ROOT/'working/20260908T125203Z-chronosift-scoring-2l87nf'
CASES = [('windows-context',ROOT/'working/20260908T201100Z-windows-policy-mflgUq/windows-context/input')]+[
    (name,CROSS/name/'input') for name in ('case1-sqli','case1-shell','ubuntu-setup','ubuntu-attack')]
ANCHORS = {2665521,11243208,11244381,11627225,11628952,11628953,11628979,11628980,11692834,12146098,
           12199528,12199536,12199538,12199539,12199738,13565563,13565564,13581759,
           12155531,12158631,12158648,12147014,12147015,12165416,13433555,13433556,13433561,13433562,
           23509840,23511704,23547120,23557825,23563703,23569494,23569496,23613276,23618511}


def sha(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda:handle.read(8*1024*1024),b''):result.update(block)
    return result.hexdigest()


def save(path,value):
    with Path(path).open('x') as handle:json.dump(value,handle,indent=2,default=str)


def freeze(out):
    source=out/'source';source.mkdir()
    sources=[WT/'chronoSIFT_v2_31.py',WT/'run_chronosift_sidecar_cli.py',Path(__file__),
             WT/'benchmarks/build_context_provenance_policy.py',WT/'tests/test_v231_context_provenance.py',
             WT/'rules/rules_evidence_calibrated_v16.yaml',WT/'rules/weights_evidence_calibrated_v15.yaml',
             WT/'docs/CONTEXT_PROVENANCE.md']
    for path in sources:shutil.copy2(path,source/path.name)
    hashes={str(p):sha(p) for p in sources}
    hashes.update({str(p):sha(p) for p in (out/'baseline').iterdir() if p.is_file()})
    resources=dict(yara=ROOT/'rules/yara-rules-extended_20260719.yar',
        av_csv_path=ROOT/'resources/enrichment/av.csv',luhn_csv_path=ROOT/'resources/enrichment/luhn.csv',
        geoip_city_db=ROOT/'rules/GeoLite2-City_20260217/GeoLite2-City.mmdb',
        geoip_asn_db=ROOT/'rules/GeoLite2-ASN_20260217/GeoLite2-ASN.mmdb')
    hashes.update({str(p):sha(p) for p in resources.values()})
    for _,case in CASES:hashes.update({str(p):sha(p) for p in sorted(case.rglob('*.parquet'))})
    save(out/'provenance.json',dict(hashes=hashes,resources=resources,cases=CASES,
        scope='Frozen baseline v15/v14 versus candidate v16/v15. Bounded all-row comparisons use actual YARA/AV/Luhn/GeoIP, neutral profiling and no NSRL in both variants. Separate complete-history selected auth/tool cohort tests native partition parity; not full production corpus output.'))
    modules={}
    for label,folder in [('baseline',out/'baseline'),('candidate',source)]:
        spec=importlib.util.spec_from_file_location('context_replay_'+label,folder/'chronoSIFT_v2_31.py')
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        modules[label]=(module,folder)
    return modules,resources,hashes


def engine_for(label,modules,resources):
    module,folder=modules[label]
    rules='rules_evidence_calibrated_v15.yaml' if label=='baseline' else 'rules_evidence_calibrated_v16.yaml'
    weights='weights_evidence_calibrated_v14.yaml' if label=='baseline' else 'weights_evidence_calibrated_v15.yaml'
    engine=module.ChronoSiftEngine.from_yaml(folder/rules,folder/weights,yara_metadata_path=str(resources['yara']))
    return module,engine


def manifest_for(module,engine,input_dir,resources):
    return module.build_global_referenced_file_hit_manifest(str(input_dir),
        av_csv_path=str(resources['av_csv_path']),luhn_csv_path=str(resources['luhn_csv_path']),
        yara_metadata_index=engine.yara_metadata_index,yara_metadata_path=str(resources['yara']),
        clamav_classifier_policy=engine.detector_policy.clamav_classification,
        yara_classifier_policy=engine.detector_policy.yara_classification,
        referenced_file_policy=engine.detector_policy.referenced_file_correlation)


def example(output,pos):
    row=output.iloc[pos]
    return dict(id=int(row.chronosift_row_id),timestamp=output.index[pos].isoformat(),score=float(row.chronosift_score),
        parser=row.get('parser'),message=row.get('message'),filename=row.get('filename'),
        signals=row.get('chronosift_signals') or {},explain=row.get('chronosift_explain') or [],
        creator=row.get('win_creator_sid'),child_or_actor=row.get('win_context_sid'),scope=row.get('continuity_scope'))


def summarise(output,engine,path,elapsed,before=None):
    ids=output.chronosift_row_id.to_numpy();scores=output.chronosift_score.to_numpy()
    assert len(set(ids))==len(ids) and output.chronosift_row_id.notna().all()
    counts=Counter();selected=[];losses=[]
    previous=before.set_index('chronosift_row_id').loc[ids,'chronosift_score'].to_numpy() if before is not None else scores
    top=set(np.argsort(-scores,kind='stable')[:15].tolist())
    for pos,(signals,explanations) in enumerate(zip(output.chronosift_signals,output.chronosift_explain)):
        signals=signals or {};explanations=explanations or []
        assert np.isfinite(scores[pos]) and 0<=scores[pos]<=50
        assert abs(scores[pos]-engine._score_signals(signals))<1e-5,(int(ids[pos]),'signals')
        assert abs(scores[pos]-min(50,sum(e.get('score_contribution',0) for e in explanations)))<1e-5,(int(ids[pos]),'explanations')
        counts.update(name for name,value in signals.items() if value)
        if int(ids[pos]) in ANCHORS or pos in top:selected.append(example(output,pos))
        if previous[pos]>0 and scores[pos]<=0 and len(losses)<50:losses.append(example(output,pos))
    scalar=pd.DataFrame(dict(chronosift_row_id=ids,chronosift_score=scores,previous_score=previous))
    scalar.to_parquet(path/'scores.parquet',index=False)
    check=pd.read_parquet(path/'scores.parquet')
    assert check.chronosift_row_id.tolist()==ids.tolist() and np.array_equal(check.chronosift_score,scores)
    delta=scores-previous
    summary=dict(rows=len(ids),seconds=elapsed,positive=int((scores>0).sum()),maximum=float(scores.max()),
        increased=int((delta>1e-6).sum()),decreased=int((delta<-1e-6).sum()),unchanged=int((abs(delta)<=1e-6).sum()),
        lost_all_score=int(((previous>0)&(scores<=0)).sum()),signal_counts=dict(counts))
    save(path/'evaluation.json',dict(**summary,examples=selected,lost_examples=losses))
    return scalar,summary


def bounded(out,modules,resources):
    results=[]
    for name,input_dir in CASES:
        case=out/name;case.mkdir();before=None;variants={}
        for label in ('baseline','candidate'):
            start=time.monotonic();path=case/label;path.mkdir()
            module,engine=engine_for(label,modules,resources)
            manifest=manifest_for(module,engine,input_dir,resources)
            data=module.load_plaso_parquet_dataset(str(input_dir));ids=data.chronosift_row_id.to_numpy()
            print(name,label,'scoring',len(data),flush=True)
            output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,
                **{k:str(v) for k,v in resources.items() if k!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
            assert output.chronosift_row_id.tolist()==ids.tolist()
            scalar,summary=summarise(output,engine,path,time.monotonic()-start,before)
            variants[label]=summary
            if label=='baseline':before=scalar
            print(name,label,summary,flush=True)
            del output,data,engine,manifest,scalar;gc.collect()
        results.append(dict(case=name,**variants))
    save(out/'bounded-summary.json',results)
    return results


def continuity(out,modules,resources):
    case=out/'windows-complete-auth-tool-history';case.mkdir();input_dir=case/'input';input_dir.mkdir()
    con=duckdb.connect();con.execute('SET threads=2');con.execute("SET TimeZone='UTC'")
    files=sorted(RAW.rglob('*.parquet'));source_hashes={str(p):sha(p) for p in files}
    con.from_parquet(str(RAW/'**/*.parquet'),union_by_name=True,hive_partitioning=True).create_view('base')
    predicate="""(event_identifier IN(4624,4625,1149,4778,4779) AND
        (contains(lower(message),'administrator') OR contains(message,'-2611')))
        OR (event_identifier IN(4720,4728,4732,4756) AND contains(message,'-2611'))
        OR ((contains(lower(message),'psexec.exe') OR contains(lower(message),'psexec64.exe')) AND
        (contains(data_type,'srum:application_usage') OR contains(data_type,'userassist') OR contains(parser,'bam')))
        OR chronosift_row_id IN(13565563,13565564)"""
    observed=con.execute('SELECT year,month,count(*) FROM base WHERE '+predicate+' GROUP BY 1,2 ORDER BY 1,2').fetchall()
    sizes={(year,month):n for year,month,n in observed}
    # Preserve the original intervening month layout even when this cohort has
    # zero rows there. January's forward overlap is what exposed the defect;
    # dropping its partition would accidentally make the broken baseline pass.
    bounds=[observed[i][0]*12+observed[i][1] for i in (0,-1)]
    layout=con.execute('SELECT DISTINCT year,month FROM base WHERE year*12+month BETWEEN ? AND ? ORDER BY 1,2',bounds).fetchall()
    counts=[(year,month,sizes.get((year,month),0)) for year,month in layout]
    for year,month,n in counts:
        loc=input_dir/f'year={year}'/f'month={month}';loc.mkdir(parents=True)
        # DuckDB COPY does not accept a bound filename in this installed build.
        # Quote the internally constructed destination; keep predicates bound.
        destination = "'" + str(loc/'part.parquet').replace("'", "''") + "'"
        con.execute('COPY (SELECT * EXCLUDE(year,month) FROM base WHERE ('+predicate+
                    ') AND year=? AND month=?) TO '+destination+' (FORMAT PARQUET)',[year,month])
    save(case/'source-provenance.json',dict(predicate=predicate,partitions=counts,hashes=source_hashes,
        scope='Complete available history for selected Administrator/new-account authentication, creation/grants and PsExec usage-shaped artefacts; preserved raw rows/IDs. Not all Windows events.'))
    print('complete-auth-tool-history',sum(row[2] for row in counts),'rows',len(counts),'months',flush=True)
    variants={}
    before=None
    for label in ('baseline','candidate'):
        path=case/label;path.mkdir();start=time.monotonic()
        module,engine=engine_for(label,modules,resources)
        engine.profiling_policy=replace(engine.profiling_policy,enabled=False)
        manifest=manifest_for(module,engine,input_dir,resources)
        data=module.load_plaso_parquet_dataset(str(input_dir))
        output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,
            **{k:str(v) for k,v in resources.items() if k!='yara'}),apply_profiling=False,file_hit_manifest=manifest)
        scalar,summary=summarise(output,engine,path,time.monotonic()-start,before)
        expected={int(row.chronosift_row_id):(float(row.chronosift_score),row.chronosift_signals or {}) for _,row in output.iterrows()}
        del output,data;gc.collect()
        engine.process_parquet_dataset_partitioned(str(input_dir),str(path/'sidecar'),output_mode='sidecar',
            file_hit_manifest=manifest,materialise_event_columns=True,retain_zero_weight_lifecycle_signals=True,
            **{k:str(v) for k,v in resources.items() if k!='yara'})
        records=con.execute('SELECT chronosift_row_id,chronosift_score,chronosift_signals,chronosift_explain FROM read_parquet(?,union_by_name=true)',
                            [str(path/'sidecar/**/*.parquet')]).fetchall()
        assert len(records)==len(expected) and {r[0] for r in records}==set(expected)
        mismatches=[]
        for rid,score,signals,explain in records:
            signals=signals or {};explain=[json.loads(e) if isinstance(e,str) else e for e in (explain or [])]
            assert abs(score-min(50,sum(e.get('score_contribution',0) for e in explain)))<1e-5,(rid,'native explanations')
            if abs(expected[rid][0]-score)>1e-6 or expected[rid][1]!=signals:
                mismatches.append(dict(id=rid,chronological_score=expected[rid][0],partitioned_score=score,
                    chronological_signals=expected[rid][1],partitioned_signals=signals))
        save(path/'partition-comparison.json',dict(rows=len(records),mismatches=len(mismatches),examples=mismatches[:100],
            overlap=str(engine.minimum_partition_overlap()),expected_equivalence=label=='candidate'))
        if label=='candidate':assert not mismatches,('candidate partition mismatch',len(mismatches),mismatches[:2])
        else:assert any(item['id']==11243208 for item in mismatches), 'Baseline did not reproduce initial-logon overlap defect'
        if label=='baseline':before=scalar
        variants[label]=dict(**summary,partition_mismatches=len(mismatches),total_seconds=time.monotonic()-start)
        print('complete-auth-tool-history',label,variants[label],flush=True)
        del records,expected,engine,manifest,scalar;gc.collect()
    assert all(sha(Path(p))==digest for p,digest in source_hashes.items())
    save(case/'summary.json',variants);con.close()
    return variants


def main(out):
    logging.Formatter.converter=time.gmtime;logging.getLogger().setLevel(logging.ERROR)
    modules,resources,hashes=freeze(out)
    history=continuity(out,modules,resources)
    comparisons=bounded(out,modules,resources)
    assert all(sha(Path(p))==digest for p,digest in hashes.items()),'Source/resource changed during validation'
    save(out/'validation.json',dict(status='passed',bounded_rows=sum(r['candidate']['rows'] for r in comparisons),
        complete_auth_tool_history_rows=history['candidate']['rows'],candidate_native_partition_mismatches=0,
        all_keys_scores_explanations_readbacks_valid=True,source_and_resource_hashes_unchanged=True))
    print('COMPLETE',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path)
    main(parser.parse_args().output)
