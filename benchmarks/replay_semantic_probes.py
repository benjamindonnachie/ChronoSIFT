"""Replay saved synthetic scan inputs; never reads corpus Parquet or rescoring outputs."""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import pandas as pd
import chronoSIFT_v2_31 as c


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scan_directory',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    if args.output.exists(): raise SystemExit('Refusing to overwrite an existing receipt')
    logging.getLogger().setLevel(logging.ERROR)
    rules=ROOT/'rules/rules_evidence_calibrated_v25.yaml'
    weights=ROOT/'rules/weights_evidence_calibrated_v21.yaml'
    files=[ROOT/'chronoSIFT_v2_31.py',ROOT/'command_evidence.py',rules,weights]
    hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    engine=c.ChronoSiftEngine.from_yaml(rules,weights,yara_metadata_path=str(args.scan_directory/'unused.yar'))
    results=[]
    for filename in ['probe-result.json','probe-extra-result.json']:
        original=json.loads((args.scan_directory/filename).read_text())
        for case in original['results']:
            frame=pd.DataFrame([dict(chronosift_row_id=900+i,hostname='synthetic-host',**record)
                for i,record in enumerate(case['input'])],index=pd.date_range('2024-01-01T12:00:00Z',periods=len(case['input']),freq='min',name='datetime'))
            out=engine.apply(frame,apply_profiling=False)
            rows=[]
            for i,(_,row) in enumerate(out.iterrows()):
                explains=row.get('chronosift_explain'); explains=explains if isinstance(explains,list) else []
                signals=row.get('chronosift_signals'); signals=signals if isinstance(signals,dict) else {}
                assert int(row.chronosift_row_id)==900+i
                assert out.index[i]==frame.index[i]
                rows.append(dict(score=float(row.chronosift_score),signals=signals,explanations=explains,
                    accounting_ok=abs(min(50,sum(x['score_contribution'] for x in explains))-row.chronosift_score)<1e-8,
                    baseline_score=case['output'][i]['score']))
            results.append(dict(case=case['case'],input=case['input'],output=rows))
            print(case['case'],[(r['baseline_score'],r['score']) for r in rows],flush=True)
    assert hashes=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    mismatches=[r['case'] for r in results if any(not x['accounting_ok'] for x in r['output'])]
    receipt=dict(synthetic_only=True,profiling=False,source_sha256=hashes,results=results,accounting_mismatches=mismatches)
    with args.output.open('x') as handle: json.dump(receipt,handle,indent=2,default=str)
    print('COMPLETE',len(results),'scenarios;',sum(len(x['output']) for x in results),'rows;',len(mismatches),'accounting mismatches')
    if mismatches: raise SystemExit(2)


if __name__=='__main__': main()
