"""Fresh candidate replay against frozen prior evaluation, preserving all keys.

Ground truth chooses audit anchors only. No prior score is a detector input.
This produces evaluation tables, not final production sidecars.
"""
import argparse
from collections import Counter
import gc
import hashlib
import json
import logging
from pathlib import Path
import shutil
import sys
import time

import numpy as np
import pandas as pd

WORKTREE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(WORKTREE))
import chronoSIFT_v2_31 as c
from windows_policy_replay import ANCHORS, sha, write_json

ROOT=Path('/Volumes/EXTERNAL/PhD/202607-snake-make-driven')
OLD=ROOT/'working/20260908T203700Z-windows-policy-verified-VT2uNA'
WININPUT=ROOT/'working/20260908T201100Z-windows-policy-mflgUq/windows-context/input'
CROSS=ROOT/'working/20260908T125203Z-chronosift-scoring-2l87nf'
ANCHORS.update({369338,23509840,23511704,23547120,23557825,23563703,23569494,23569496,23613276,23618511,
    11695419,11652211,12166843,12165416,12165417,12165418,12165419,12165420,12165423,12165434,
    11727760,11727761,1321143,1326686,1326696,1327639,1328222,1328224})

def main(out):
    if any(out.iterdir()): raise ValueError('Fresh empty output required')
    logging.Formatter.converter=time.gmtime
    logging.getLogger().setLevel(logging.ERROR)
    cases=[('windows-context',WININPUT)]+[(name,CROSS/name/'input') for name in ('case1-sqli','case1-shell','ubuntu-setup','ubuntu-attack')]
    yara=ROOT/'rules/yara-rules-extended_20260719.yar'
    av=ROOT/'resources/enrichment/av.csv'; luhn=ROOT/'resources/enrichment/luhn.csv'
    city=ROOT/'rules/GeoLite2-City_20260217/GeoLite2-City.mmdb'; asn=ROOT/'rules/GeoLite2-ASN_20260217/GeoLite2-ASN.mmdb'
    sources=[WORKTREE/'chronoSIFT_v2_31.py',WORKTREE/'run_chronosift_sidecar_cli.py',Path(__file__),
        WORKTREE/'benchmarks/build_evidence_linkage_policy.py',WORKTREE/'rules/rules_evidence_calibrated_v14.yaml',
        WORKTREE/'rules/weights_evidence_calibrated_v13.yaml',WORKTREE/'tests/test_v231_evidence_linkage.py']
    snapshot=out/'source'; snapshot.mkdir()
    for source in sources: shutil.copy2(source,snapshot/source.name)
    provenance={str(p):sha(p) for p in [*sources,yara,av,luhn,city,asn,OLD/'RESULTS.md',OLD/'validation.json']}
    for label,input_dir in cases:
        provenance.update({str(p):sha(p) for p in sorted(input_dir.rglob('*.parquet'))})
        provenance[str(OLD/label/'final-scores.parquet')]=sha(OLD/label/'final-scores.parquet')
    write_json(out/'provenance.json',dict(hashes=provenance,baseline=str(OLD),cases=[(a,str(b)) for a,b in cases],
        scope='Same frozen 861371 source rows as preceding bounded validation; neutral profiling, actual YARA/AV/Luhn/GeoIP, no NSRL. All keys and every scalar/explanation checked. Baseline final-scores includes its documented isolated note delta. No production sidecars or ground-truth labels used as detector inputs.'))
    results=[]
    for label,input_dir in cases:
        started=time.monotonic(); case=out/label; case.mkdir()
        engine=c.ChronoSiftEngine.from_yaml(WORKTREE/'rules/rules_evidence_calibrated_v14.yaml',WORKTREE/'rules/weights_evidence_calibrated_v13.yaml',yara_metadata_path=str(yara))
        manifest=c.build_global_referenced_file_hit_manifest(str(input_dir),av_csv_path=str(av),luhn_csv_path=str(luhn),
            yara_metadata_index=engine.yara_metadata_index,yara_metadata_path=str(yara),
            clamav_classifier_policy=engine.detector_policy.clamav_classification,yara_classifier_policy=engine.detector_policy.yara_classification,
            referenced_file_policy=engine.detector_policy.referenced_file_correlation)
        data=c.load_plaso_parquet_dataset(str(input_dir)); ids=data.chronosift_row_id.to_numpy()
        expected=set(ids.tolist()); assert len(expected)==len(ids) and data.chronosift_row_id.notna().all()
        print(label,'scoring',len(data),flush=True)
        output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,av_csv_path=str(av),luhn_csv_path=str(luhn),
            geoip_city_db=str(city),geoip_asn_db=str(asn)),apply_profiling=False,file_hit_manifest=manifest)
        assert set(output.chronosift_row_id.tolist())==expected and output.chronosift_row_id.is_unique
        previous=pd.read_parquet(OLD/label/'final-scores.parquet').set_index('chronosift_row_id')
        # Earlier scalar tables use the standard chronosift_score field.
        before=previous.loc[ids,'chronosift_score'].to_numpy()
        scores=output.chronosift_score.to_numpy()
        lost=(before>0)&(scores<=0); delta=scores-before
        scalar=pd.DataFrame(dict(chronosift_row_id=ids,previous_score=before,chronosift_score=scores,lost_all_score=lost))
        scalar.to_parquet(case/'scores.parquet',index=False)
        counts=Counter(); examples={}; anchors=[]; lost_examples=[]; tops=[]
        top_positions=set(np.argsort(-scores,kind='stable')[:10].tolist())
        for pos,(score,signals,explanations) in enumerate(zip(scores,output.chronosift_signals.to_numpy(),output.chronosift_explain.to_numpy())):
            signals=signals or {}; explanations=explanations or []
            assert abs(float(score)-engine._score_signals(signals))<1e-5,(label,int(ids[pos]),'signal sum')
            assert abs(float(score)-min(50,max(0,sum(float(e.get('score_contribution',0)) for e in explanations))))<1e-5,(label,int(ids[pos]),'explanation sum')
            counts.update(name for name,value in signals.items() if value)
            novel=[name for name,value in signals.items() if value and name.startswith(('evidence_','web_recent_file_','web_hostile_','windows_qualified_','windows_malware_use_')) and len(examples.get(name,[]))<3]
            if int(ids[pos]) in ANCHORS or pos in top_positions or novel or (lost[pos] and len(lost_examples)<40):
                row=output.iloc[pos]
                item=dict(id=int(ids[pos]),timestamp=output.index[pos].isoformat(),previous=float(before[pos]),score=float(score),
                    parser=row.get('parser'),filename=row.get('filename'),message=row.get('message'),signals=signals,explain=explanations,
                    web_identity=row.get('evidence_web_identity'),payload_identity=row.get('evidence_payload_identity'),sid=row.get('win_context_sid'))
                if int(ids[pos]) in ANCHORS: anchors.append(item)
                if pos in top_positions: tops.append(item)
                if lost[pos] and len(lost_examples)<40: lost_examples.append(item)
                for name in novel: examples.setdefault(name,[]).append(item)
        check=pd.read_parquet(case/'scores.parquet')
        assert check.chronosift_row_id.tolist()==ids.tolist() and np.array_equal(check.chronosift_score.to_numpy(),scores)
        summary=dict(case=label,rows=len(output),seconds=time.monotonic()-started,maximum=float(scores.max()),
            increased=int((delta>1e-6).sum()),decreased=int((delta<-1e-6).sum()),unchanged=int((abs(delta)<=1e-6).sum()),
            lost_all_score=int(lost.sum()),positive=int((scores>0).sum()),signal_counts=counts)
        write_json(case/'evaluation.json',dict(**summary,anchors=anchors,examples=examples,top=tops,lost_examples=lost_examples))
        results.append(summary); print(label,summary['seconds'],'increases',summary['increased'],'decreases',summary['decreased'],'lost',summary['lost_all_score'],flush=True)
        del data,output,engine,manifest,previous,scalar,check
        gc.collect()
    assert all(sha(Path(p))==digest for p,digest in provenance.items()),'Source changed during evaluation'
    write_json(out/'summary.json',results)
    write_json(out/'validation.json',dict(status='passed',evaluated_rows=sum(r['rows'] for r in results),all_keys_scores_explanations_readback_valid=True,source_hashes_unchanged=True))
    print('COMPLETE',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',required=True,type=Path)
    main(parser.parse_args().output)
