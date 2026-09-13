"""Incremental note-only validation over all relevant rows in frozen fixtures.

Verifies the YAML delta is limited to note detection, then evaluates both note
policies on all file artefacts and identity seeds (not GT-selected note rows).
Combines only that isolated contribution with the completed full-frame scores.
These are scalar evaluation tables, never replacement production sidecars.
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import sys
import warnings

import duckdb
import pandas as pd
import pyarrow.parquet as pq
import yaml

WORKTREE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(WORKTREE))
import chronoSIFT_v2_31 as c

NOTE_SIGNALS={'windows_note_created','windows_unattributed_note_created','windows_ransom_note_context','windows_ransom_note_host_context'}

def neutralise(config):
    # Compare all other policy byte-values after removing the isolated branch.
    direct=config['detector_policy']['detectors']['direct_attack_semantics']
    direct['ordered_rules']=[r for r in direct['ordered_rules'] if r['emission'] not in NOTE_SIGNALS]
    direct['emissions']={k:v for k,v in direct['emissions'].items() if k not in NOTE_SIGNALS}
    config['temporal_rules']=[r for r in config['temporal_rules'] if not any(s['name'] in NOTE_SIGNALS for s in r['emit']['signals'])]
    return config

def write(path,data):
    with path.open('x') as f: json.dump(data,f,indent=2,default=str)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pipeline-root',type=Path,required=True)
    p.add_argument('--replay',type=Path,required=True)
    p.add_argument('--windows-input',type=Path,required=True)
    p.add_argument('--cross-case-inputs',type=Path,required=True)
    args=p.parse_args(); root=args.pipeline_root; replay=args.replay
    logging.getLogger().setLevel(logging.ERROR); warnings.filterwarnings('ignore',category=FutureWarning)
    oldr=replay/'source/rules_evidence_calibrated_v13.yaml'; oldw=replay/'source/weights_evidence_calibrated_v12.yaml'
    newr=WORKTREE/'rules/rules_evidence_calibrated_v13.yaml'; neww=WORKTREE/'rules/weights_evidence_calibrated_v12.yaml'
    assert neutralise(yaml.safe_load(oldr.read_text()))==neutralise(yaml.safe_load(newr.read_text()))
    wa=yaml.safe_load(oldw.read_text()); wb=yaml.safe_load(neww.read_text())
    for cfg in (wa,wb): cfg['weights']={k:v for k,v in cfg['weights'].items() if k not in NOTE_SIGNALS}
    assert wa==wb
    # No other rules consume the changed markers; there is no hidden feedback.
    residual=neutralise(yaml.safe_load(newr.read_text()))
    assert not any(name in yaml.safe_dump(residual) for name in NOTE_SIGNALS)
    yara=root/'rules/yara-rules-extended_20260719.yar'
    av=root/'resources/enrichment/av.csv'; luhn=root/'resources/enrichment/luhn.csv'
    audit=replay/'note-audit'; audit.mkdir(exist_ok=True)
    source_paths=[Path(__file__),WORKTREE/'chronoSIFT_v2_31.py',oldr,oldw,newr,neww,yara,av,luhn]
    cases=[('windows-context',args.windows_input)]+[(case,args.cross_case_inputs/case/'input') for case in ('case1-sqli','case1-shell','ubuntu-setup','ubuntu-attack')]
    source_paths += [path for _,base in cases for path in base.rglob('*.parquet')]
    if (audit/'initial-source.py').exists(): source_paths.append(audit/'initial-source.py')
    hashes={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
    summary=[]
    for label,base in cases:
        fixture=audit/label
        if (fixture/'result.json').exists():
            result=json.loads((fixture/'result.json').read_text())
            original=pd.read_parquet(replay/label/'candidate-scores.parquet')
            saved=pd.read_parquet(replay/label/'final-scores.parquet')
            delta={r['id']:r['final_note_contribution']-r['previous_note_contribution'] for r in result['changes']}
            original['chronosift_score']=(original.chronosift_score+original.chronosift_row_id.map(delta).fillna(0)).clip(0,50)
            pd.testing.assert_frame_equal(original,saved)
            summary.append(result)
            print(label,'resumed and scalar composition rechecked',flush=True)
            continue
        db=duckdb.connect(); db.execute("SET TimeZone='UTC'")
        schema={row[0] for row in db.execute('DESCRIBE SELECT * FROM read_parquet(?,union_by_name=true)',[str(base/'**/*.parquet')]).fetchall()}
        identity=("contains(coalesce(xml_string,''),'TargetSid') OR contains(coalesce(xml_string,''),'TargetUserSid')" if 'xml_string' in schema else 'false')
        raw=db.execute("SELECT * FROM read_parquet(?,union_by_name=true) WHERE parser IN ('filestat','usnjrnl','mft') OR "+identity,
            [str(base/'**/*.parquet')]).fetch_arrow_table()
        raw=raw.drop([name for name in ('year','month') if name in raw.column_names]); db.close()
        fixture.mkdir(exist_ok=True)
        if not (fixture/'input.parquet').exists(): pq.write_table(raw,fixture/'input.parquet')
        full=json.loads((replay/label/'candidate.json').read_text())
        expected_ransom={e['id'] for e in full['examples'].get('windows_ransomware_presence',[])}
        assert len(expected_ransom)==full['signal_counts'].get('windows_ransomware_presence',0), 'Need complete source IDs, not sampled sources'
        previous={}; changes=[]
        for name,rules,weights in [('previous',oldr,oldw),('final',newr,neww)]:
            engine=c.ChronoSiftEngine.from_yaml(rules,weights,yara_metadata_path=str(yara))
            data=c.load_plaso_parquet_dataset(str(fixture))
            output=engine.apply_contextual(engine.apply_atomic(data,apply_profiling=False,av_csv_path=str(av),luhn_csv_path=str(luhn)),apply_profiling=False)
            ransom=set()
            for pos,(rid,signals) in enumerate(zip(output.chronosift_row_id,output.chronosift_signals)):
                signals=signals or {}; rid=int(rid)
                if signals.get('windows_ransomware_presence'): ransom.add(rid)
                contribution=sum(float(v)*engine.weights.get(k,0) for k,v in signals.items() if k in NOTE_SIGNALS)
                if name=='previous':
                    if contribution: previous[rid]=contribution
                elif contribution or previous.get(rid):
                    row=output.iloc[pos]
                    changes.append(dict(id=rid,timestamp=output.index[pos].isoformat(),filename=row.get('filename'),
                        previous_note_contribution=previous.get(rid,0),final_note_contribution=contribution,
                        explain=[e for e in row.chronosift_explain if any(k in e['rule_id'] for k in ('NOTE','RANSOM_NOTE'))]))
            assert ransom==expected_ransom,(label,ransom,expected_ransom)
        # The full-frame replay had no prior note emissions in these fixtures.
        # If this changes, require complete prior provenance before composing.
        assert not previous and not full['signal_counts'].get('windows_ransom_note_context')
        scores=pd.read_parquet(replay/label/'candidate-scores.parquet')
        indexed=scores.set_index('chronosift_row_id').chronosift_score
        additions={row['id']:row['final_note_contribution']-row['previous_note_contribution'] for row in changes}
        for row in changes:
            row['previous_score']=float(indexed.loc[row['id']])
            row['final_score']=min(50,max(0,row['previous_score']+additions[row['id']]))
        scores['chronosift_score']=(scores.chronosift_score+scores.chronosift_row_id.map(additions).fillna(0)).clip(0,50)
        assert scores.chronosift_row_id.is_unique and len(scores)==full['rows']
        scores.to_parquet(replay/label/'final-scores.parquet',index=False)
        result=dict(case=label,relevant_rows=raw.num_rows,total_rows=len(scores),changed_rows=len(changes),changes=changes,
            limitation='Only isolated note contribution re-evaluated on all relevant file rows and identity seeds; other scores retained from full-frame validated replay. Not full final-policy sidecars.')
        write(fixture/'result.json',result); summary.append(result)
        print(label,'relevant',raw.num_rows,'note changes',len(changes),flush=True)
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest for path,digest in hashes.items())
    write(audit/'validation.json',dict(status='passed',hashes=hashes,branch_isolated=True,summary=summary))
    print('NOTE DELTA VALIDATED',flush=True)

if __name__=='__main__': main()
