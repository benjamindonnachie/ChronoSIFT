"""Durable sequential Windows/Ubuntu validation of an immutable source snapshot.

No memory guard or elapsed-time termination. Resource sampling is observation
only. Run this snapshot under detached tmux; it never modifies existing runs.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback

CASES={
    'windows':('20240212-decrypted-Windows_Server_2022.E01~plaso-20260720~yara-rules-extended_20260719',13602181),
    'ubuntu':('20240606-defaced_ecomm-Ubuntu_22.04.3.E01~plaso-20260720~yara-rules-extended_20260719',24743538),
}
RULES='rules_evidence_calibrated_v17.yaml'
WEIGHTS='weights_evidence_calibrated_v15.yaml'

def stamp(): return datetime.now(timezone.utc).isoformat()

def sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda:handle.read(8*1024*1024),b''): value.update(block)
    return value.hexdigest()

def save(path,data):
    with Path(path).open('x') as handle: json.dump(data,handle,indent=2,default=str)

def arguments(pipeline,source,dataset,run):
    args=[str(dataset),str(run/'sidecar'),'--rules-yaml',str(source/RULES),'--weights-yaml',str(source/WEIGHTS),
        '--output-mode','sidecar','--reports-json',str(run/'reports.json'),'--telemetry-jsonl',str(run/'telemetry.jsonl'),
        '--telemetry-summary-json',str(run/'telemetry.summary.json'),'--profile-manifest-path',str(run/'profile_manifest.json'),
        '--file-hit-manifest-path',str(run/'file_hit_manifest.json'),'--log-level','INFO']
    # No --overlap override: the policy resolves and validates its full horizon.
    for flag,path in resource_paths(pipeline): args.extend([flag,str(path)])
    return args

def resource_paths(pipeline):
    return [('--yara-metadata-path',pipeline/'rules/yara-rules-extended_20260719.yar'),
        ('--av-csv-path',pipeline/'resources/enrichment/av.csv'),('--luhn-csv-path',pipeline/'resources/enrichment/luhn.csv'),
        ('--geoip-city-db',pipeline/'rules/GeoLite2-City_20260217/GeoLite2-City.mmdb'),
        ('--geoip-asn-db',pipeline/'rules/GeoLite2-ASN_20260217/GeoLite2-ASN.mmdb'),
        ('--nsrl-parquet-path',pipeline/'resources/nsrl/parquet/RDS_2026.06.1_modern-legacy_minimal.parquet')]

def verify_source(source):
    manifest=json.loads((source/'manifest.json').read_text())
    for name,digest in manifest['sha256'].items():
        if sha(source/name)!=digest: raise RuntimeError(f'Frozen source changed: {name}')
    return manifest

def observe(stop,run,summary):
    import psutil
    process=psutil.Process()
    with (run/'resources.jsonl').open('x') as handle:
        while not stop.is_set():
            try:
                cpu=process.cpu_times(); rss=process.memory_info().rss
                sample=dict(utc=stamp(),pid=process.pid,rss_bytes=rss,cpu_s=cpu.user+cpu.system,
                    system_memory=psutil.virtual_memory()._asdict(),system_swap=psutil.swap_memory()._asdict(),observation_only=True)
                summary['peak_sampled_rss_bytes']=max(summary['peak_sampled_rss_bytes'],rss)
            except Exception as exc:
                summary['counter_errors']+=1; sample=dict(utc=stamp(),counter_error=str(exc),observation_only=True)
            summary['samples']+=1
            try: handle.write(json.dumps(sample,default=str)+'\n'); handle.flush()
            except Exception as exc:
                print('Resource logger stopped; processing continues:',exc,flush=True); return
            stop.wait(5)

def validate(con,dataset,run,expected):
    con.from_parquet(str(dataset/'**/*.parquet'),union_by_name=True,hive_partitioning=True).create_view('base',replace=True)
    con.from_parquet(str(run/'sidecar/**/*.parquet'),union_by_name=True,hive_partitioning=True).create_view('side',replace=True)
    actual=con.execute('SELECT CAST(year AS INTEGER),CAST(month AS INTEGER),count(*) FROM side GROUP BY 1,2 ORDER BY 1,2').fetchall()
    counts=con.execute('SELECT count(*),count(DISTINCT chronosift_row_id),count(*) FILTER(WHERE chronosift_row_id IS NULL) FROM side').fetchone()
    missing=con.execute('SELECT count(*) FROM base b FULL JOIN side s USING(chronosift_row_id) WHERE b.chronosift_row_id IS NULL OR s.chronosift_row_id IS NULL').fetchone()[0]
    score_check=con.execute('''SELECT count(*) FILTER(WHERE chronosift_score IS NULL OR NOT isfinite(chronosift_score) OR chronosift_score<0 OR chronosift_score>50),
        count(*) FILTER(WHERE abs(chronosift_score-least(50,greatest(0,coalesce(list_sum(list_transform(chronosift_explain,
            item -> coalesce(try_cast(json_extract_string(item,'$.score_contribution') AS DOUBLE),0))),0))))>0.00001)
        FROM side''').fetchone()
    reports=json.loads((run/'reports.json').read_text())
    reported=[(item['year'],item['month'],item['rows_written']) for item in reports]
    n=sum(row[2] for row in expected)
    valid=actual==expected and reported==expected and counts==(n,n,0) and missing==0 and score_check==(0,0)
    result=dict(utc=stamp(),valid=valid,rows=counts[0],unique_ids=counts[1],null_ids=counts[2],missing_or_extra_keys=missing,
        invalid_scores=score_check[0],explanation_sum_errors=score_check[1],partitions=len(actual),
        parquet_files=len(list((run/'sidecar').rglob('*.parquet'))),all_partitions_match=actual==expected,reports_match=reported==expected)
    save(run/'validation.json',result)
    if not valid: raise RuntimeError('Full sidecar identity/score validation failed')
    return result

def worker(root,pipeline,case):
    source=root/'source'; manifest=verify_source(source)
    run=root/case
    with (run/'launch.lock').open('x') as handle: handle.write(str(os.getpid()))
    if (run/'sidecar').exists(): raise FileExistsError('Refusing an existing output root')
    sys.path.insert(0,str(source))
    import chronoSIFT_v2_31 as engine_module
    import run_chronosift_sidecar_cli as cli
    if Path(engine_module.__file__).resolve()!=source/'chronoSIFT_v2_31.py': raise RuntimeError('Wrong engine import')
    logging.Formatter.converter=time.gmtime
    name,expected_rows=CASES[case]; dataset=pipeline/'parquet'/name
    args=arguments(pipeline,source,dataset,run)
    save(run/'pids.json',dict(worker_pid=os.getpid(),utc=stamp()))
    print(stamp(),case,'Hashing input provenance before processing',flush=True)
    inputs={str(p):sha(p) for p in sorted(dataset.rglob('*.parquet'))}
    inventory={str(p):(p.stat().st_size,p.stat().st_mtime_ns) for p in sorted(dataset.rglob('*.parquet'))}
    resources={}
    for _,path in resource_paths(pipeline):
        print(stamp(),case,'Hashing resource',path.name,flush=True)
        resources[str(path)]=sha(path)
    save(run/'provenance.json',dict(utc=stamp(),case=case,dataset=str(dataset),source=manifest,input_sha256=inputs,resource_sha256=resources,
        input_inventory=inventory,cli_arguments=args,python=sys.executable,python_version=sys.version,hash_seed=os.environ.get('PYTHONHASHSEED'),
        memory_guard=False,runtime_limit=None,termination_thresholds=None,overlap='automatic policy horizon',
        scope='All chronological months; normal carry, fresh manifests and sidecars; original inputs/outputs untouched',
        duckdb_query_buffer='1GB spillable query buffer, not a process memory ceiling'))
    con=engine_module._get_duckdb_connection(); con.execute('SET threads=2'); con.execute("SET memory_limit='1GB'")
    con.execute("SET TimeZone='UTC'"); con.execute('SET temp_directory=?',[str(run/'spill')])
    stop=threading.Event(); summary=dict(samples=0,peak_sampled_rss_bytes=0,counter_errors=0)
    observer=threading.Thread(target=observe,args=(stop,run,summary),daemon=True); observer.start()
    started=time.monotonic(); result=dict(status='failed',exit_code=1)
    try:
        census=con.execute('SELECT CAST(year AS INTEGER),CAST(month AS INTEGER),count(*) FROM read_parquet(?,union_by_name=true,hive_partitioning=true) GROUP BY 1,2 ORDER BY 1,2',[str(dataset/'**/*.parquet')]).fetchall()
        save(run/'census.json',dict(rows=sum(row[2] for row in census),monthly=census))
        if sum(row[2] for row in census)!=expected_rows: raise RuntimeError('Input census differs from validated corpus')
        previous=sys.argv; sys.argv=[str(source/'run_chronosift_sidecar_cli.py'),*args]
        try: code=cli.main()
        finally: sys.argv=previous
        if code not in (None,0): raise RuntimeError(f'CLI exit {code}')
        validate(con,dataset,run,census)
        if inventory!={str(p):(p.stat().st_size,p.stat().st_mtime_ns) for p in sorted(dataset.rglob('*.parquet'))}:
            raise RuntimeError('Evidence inventory changed during run')
        from audit_final_datasets import audit
        audit(con,dataset,run,source,case)
        verify_source(source)
        if any(sha(Path(path))!=digest for path,digest in resources.items()): raise RuntimeError('Resource changed during run')
        result.update(status='completed',exit_code=0)
    except BaseException as exc:
        traceback.print_exc(); result.update(error=f'{type(exc).__name__}: {exc}',exit_code=130 if isinstance(exc,KeyboardInterrupt) else 1)
    finally:
        stop.set(); observer.join(timeout=10)
        result.update(finished_utc=stamp(),wall_seconds=time.monotonic()-started,resources=summary,memory_guard=False)
        save(run/'result.json',result); print(json.dumps(result),flush=True)
    return result['exit_code']

def queue(root,pipeline):
    verify_source(root/'source')
    with (root/'queue.lock').open('x') as handle: handle.write(str(os.getpid()))
    results=[]
    # Fewer rows and the previous measured shorter runtime give useful results
    # first. These are serial workers, never competing full-image processes.
    for case in CASES:
        run=root/case; run.mkdir()
        command=[sys.executable,'-B','-W','ignore',str(Path(__file__).resolve()),'--root',str(root),'--pipeline',str(pipeline),'--worker',case]
        print(stamp(),'START',case,flush=True)
        with (run/'worker.log').open('x') as log:
            code=subprocess.call(command,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'PYTHONHASHSEED':'20260906','TZ':'UTC'},cwd=root/'source')
        results.append(dict(case=case,exit_code=code,finished_utc=stamp()))
        print(stamp(),'END',case,code,flush=True)
        if code: break
    save(root/'queue-result.json',dict(finished_utc=stamp(),completed=len(results)==len(CASES) and all(r['exit_code']==0 for r in results),results=results))
    return next((r['exit_code'] for r in results if r['exit_code']),0)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--pipeline',required=True,type=Path); parser.add_argument('--worker',choices=CASES)
    args=parser.parse_args()
    sys.exit(worker(args.root.resolve(),args.pipeline.resolve(),args.worker) if args.worker else queue(args.root.resolve(),args.pipeline.resolve()))
