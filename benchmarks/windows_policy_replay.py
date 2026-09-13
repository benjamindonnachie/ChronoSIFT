"""Bounded real-evidence A/B, with stable IDs and immutable source inputs.

Ground-truth windows/anchors select validation observations, never rule inputs.
Writes new scalar score tables and selected full explanations, not production
sidecars. Optional cross-case inputs were prepared by the earlier audit.
"""
import argparse
from collections import Counter
import gc
import hashlib
import json
import logging
from pathlib import Path
import sys
import time
import warnings

import duckdb
import pandas as pd
import pyarrow.parquet as pq

WORKTREE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKTREE))
import chronoSIFT_v2_31 as c

WINDOWS = [
    ('2024-02-03T10:45:00Z','2024-02-03T12:00:00Z'),
    ('2024-02-05T22:30:00Z','2024-02-06T23:00:00Z'),
    ('2024-02-07T16:00:00Z','2024-02-07T17:30:00Z'),
    ('2024-02-08T18:30:00Z','2024-02-08T19:30:00Z'),
    ('2024-02-09T21:30:00Z','2024-02-09T23:10:00Z'),
]
ANCHORS = {11244381,11628952,11628953,11628979,11628980,12133971,12133973,
           12114344,12175886,12175887,12177944,12177945,12178630,12178634,
           12194386,12194373,12194380,13565563,13565564,13581759,13581774,
           13581766,13581767,12155531,12158631,12158648,11693685,11695377,
           11695378,11695383,11695387,11695392,12147014,12147015,23563703}

def write_json(path, data):
    with path.open('x') as f:
        json.dump(data, f, indent=2, default=str)

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pipeline-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cross-case-inputs',type=Path)
    parser.add_argument('--baseline-from',type=Path,help='Reuse completed baseline score tables and its exact Windows fixture; run only the final candidate')
    args=parser.parse_args()
    root=args.pipeline_root; out=args.output
    if any(out.iterdir()):
        raise ValueError('Replay requires a fresh empty output directory')
    logging.getLogger().setLevel(logging.ERROR)
    warnings.filterwarnings('ignore',category=FutureWarning)
    yara=root/'rules/yara-rules-extended_20260719.yar'
    av=root/'resources/enrichment/av.csv'; luhn=root/'resources/enrichment/luhn.csv'
    city=root/'rules/GeoLite2-City_20260217/GeoLite2-City.mmdb'
    asn=root/'rules/GeoLite2-ASN_20260217/GeoLite2-ASN.mmdb'
    base=root/'parquet/20240212-decrypted-Windows_Server_2022.E01~plaso-20260720~yara-rules-extended_20260719'
    variants=[('candidate',13,12)] if args.baseline_from else [('baseline',12,11),('candidate',13,12)]
    hashes={str(p):sha(p) for p in [Path(__file__),WORKTREE/'chronoSIFT_v2_31.py',yara,av,luhn,city,asn,
        *(WORKTREE/f'rules/rules_evidence_calibrated_v{r}.yaml' for _,r,_ in variants),
        *(WORKTREE/f'rules/weights_evidence_calibrated_v{w}.yaml' for _,_,w in variants)]}
    source_files=sorted((base/'year=2024/month=2').glob('*.parquet'))
    hashes.update({str(p):sha(p) for p in source_files})
    if args.baseline_from:
        for p in (args.baseline_from/'provenance.json',args.baseline_from/'validation.json',
                  *sorted((args.baseline_from/'windows-context/input').rglob('*.parquet')),
                  *sorted(args.baseline_from.glob('*/baseline-scores.parquet'))):
            hashes[str(p)]=sha(p)
    write_json(out/'provenance.json',dict(hashes=hashes,windows=WINDOWS,
        baseline_from=str(args.baseline_from) if args.baseline_from else None,
        scope='All channels in stated windows plus ALL successful Windows logon rows February 1–10. Gaps remain in other channels; not full-history novelty, full corpus, profiling or NSRL validation. Actual AV/Luhn/YARA/GeoIP resources; no ground-truth labels injected. A reused baseline has its own frozen engine/config provenance in baseline_from, not a claim of byte-identical engines.'))
    if args.baseline_from:
        cases=[('windows-context',args.baseline_from/'windows-context/input')]
    else:
        db=duckdb.connect(); db.execute("SET TimeZone='UTC'"); db.execute("SET memory_limit='4GB'"); db.execute('SET threads=2')
        clauses=['(datetime>=? AND datetime<?)' for _ in WINDOWS]
        parameters=[str(base/'year=2024/month=2/*.parquet'),*[item for pair in WINDOWS for item in pair]]
        clauses.append("(datetime>='2024-02-01T00:00:00Z' AND datetime<'2024-02-10T00:00:00Z' AND CAST(event_identifier AS VARCHAR) IN ('4624','4624.0','1149','1149.0') AND parser LIKE 'winevt%')")
        selected=db.execute('SELECT * FROM read_parquet(?, union_by_name=true) WHERE '+' OR '.join(clauses),parameters).fetch_arrow_table()
        selected=selected.drop([name for name in ('year','month') if name in selected.column_names])
        destination=out/'windows-context/input/year=2024/month=2'; destination.mkdir(parents=True)
        pq.write_table(selected,destination/'part.parquet')
        print('Windows selected rows',selected.num_rows,flush=True)
        del selected; db.close()
        cases=[('windows-context',out/'windows-context/input')]
    if args.cross_case_inputs:
        cases += [(name,args.cross_case_inputs/name/'input') for name in ('case1-sqli','case1-shell','ubuntu-setup','ubuntu-attack')]
    results=[]
    for label, input_dir in cases:
        case_dir=out/label; case_dir.mkdir(exist_ok=True)
        baseline_scores=(pd.read_parquet(args.baseline_from/label/'baseline-scores.parquet').set_index('chronosift_row_id').chronosift_score
                         if args.baseline_from else None)
        for variant,r,w in variants:
            started=time.monotonic()
            engine=c.ChronoSiftEngine.from_yaml(WORKTREE/f'rules/rules_evidence_calibrated_v{r}.yaml',
                WORKTREE/f'rules/weights_evidence_calibrated_v{w}.yaml',yara_metadata_path=str(yara))
            manifest=c.build_global_referenced_file_hit_manifest(str(input_dir),av_csv_path=str(av),luhn_csv_path=str(luhn),
                yara_metadata_index=engine.yara_metadata_index,yara_metadata_path=str(yara),
                clamav_classifier_policy=engine.detector_policy.clamav_classification,
                yara_classifier_policy=engine.detector_policy.yara_classification,
                referenced_file_policy=engine.detector_policy.referenced_file_correlation)
            data=c.load_plaso_parquet_dataset(str(input_dir))
            print(label,variant,'scoring',len(data),flush=True)
            expected=set(data.chronosift_row_id.tolist())
            assert len(expected)==len(data) and data.chronosift_row_id.notna().all()
            result=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,
                av_csv_path=str(av),luhn_csv_path=str(luhn),geoip_city_db=str(city),geoip_asn_db=str(asn)),
                apply_profiling=False,file_hit_manifest=manifest)
            assert len(result)==len(expected) and result.chronosift_row_id.is_unique and set(result.chronosift_row_id.tolist())==expected
            counts=Counter(); anchors=[]; top=[]; examples={}; errors=0; explanation_errors=0
            ids=result.chronosift_row_id.to_numpy(); scores=result.chronosift_score.to_numpy()
            signal_rows=result.chronosift_signals.to_numpy(); explanations=result.chronosift_explain.to_numpy()
            top_ids=set(ids[pos] for pos in sorted(range(len(scores)),key=lambda pos:(-scores[pos],ids[pos]))[:10])
            for pos,(rid,score,signals,explain) in enumerate(zip(ids,scores,signal_rows,explanations)):
                signals=signals or {}; explain=explain or []
                expected_score=engine._score_signals(signals)
                if abs(score-expected_score)>1e-5: errors+=1
                explained=min(engine.max_event_score,max(0,sum(float(item.get('score_contribution',0)) for item in explain)))
                if abs(score-explained)>1e-5: explanation_errors+=1
                counts.update(k for k,v in signals.items() if v)
                novel=[k for k,v in signals.items() if v and k.startswith('windows_') and len(examples.get(k,[]))<3]
                if int(rid) in ANCHORS or rid in top_ids or novel:
                    row=result.iloc[pos]
                    evidence=dict(id=int(rid),timestamp=result.index[pos].isoformat(),score=float(score),
                        parser=row.get('parser'),message=row.get('message'),filename=row.get('filename'),
                        sid=row.get('win_context_sid'),signals=signals,explain=explain)
                    if int(rid) in ANCHORS: anchors.append(evidence)
                    if rid in top_ids: top.append(evidence)
                    for k in novel: examples.setdefault(k,[]).append(evidence)
            assert errors==0, errors
            assert explanation_errors==0, explanation_errors
            simple=pd.DataFrame({'chronosift_row_id':ids,'chronosift_score':scores})
            simple.to_parquet(case_dir/f'{variant}-scores.parquet',index=False)
            keyed=simple.set_index('chronosift_row_id').chronosift_score
            changes=None
            if baseline_scores is None: baseline_scores=keyed
            else:
                assert keyed.index.equals(baseline_scores.index), 'Baseline keys/order differ from candidate'
                delta=keyed-baseline_scores
                changes=dict(increased=int((delta>1e-6).sum()),decreased=int((delta<-1e-6).sum()),unchanged=int((delta.abs()<=1e-6).sum()))
            summary=dict(case=label,variant=variant,rows=len(result),seconds=time.monotonic()-started,
                maximum=float(scores.max()),positive=int((scores>0).sum()),changes=changes,score_errors=errors,explanation_errors=explanation_errors,signal_counts=counts)
            write_json(case_dir/f'{variant}.json',dict(**summary,anchors=anchors,examples=examples,top=top))
            results.append(summary)
            print(label,variant,len(result),round(summary['seconds'],2),changes,flush=True)
            del result,data,engine,manifest,simple,keyed,signal_rows,explanations
            gc.collect()
    write_json(out/'summary.json',results)
    assert all(sha(Path(p))==digest for p,digest in hashes.items()),'Source/config changed during replay'
    write_json(out/'validation.json',dict(status='passed',evaluated_rows=sum(r['rows'] for r in results),source_hashes_unchanged=True))
    print('REPLAY COMPLETE',flush=True)

if __name__=='__main__':
    main()
