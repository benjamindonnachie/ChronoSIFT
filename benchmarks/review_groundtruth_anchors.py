"""Validate evaluation-only anchor corrections against raw evidence, not scores."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import duckdb
from run_final_dataset_validation import CASES, save, sha, stamp


def reviewed_ledger(con,dataset,ledger,changes):
    events={event['event_id'] for event in ledger['rows']}
    if set(changes)-events:raise ValueError('Review names an unknown ground-truth event')
    checks={}
    for event_id,change in changes.items():
        original=next(event['anchor_ids'] for event in ledger['rows'] if event['event_id']==event_id)
        primary=change['primary_ids'];support=change.get('additional_supporting_ids',[]);excluded=change['excluded_original_ids']
        if any(not isinstance(i,int) or isinstance(i,bool) or i<0 for i in primary+support+excluded):raise ValueError('Invalid anchor ID')
        if not set(excluded)<=set(original):raise ValueError('Excluded anchor absent from original ledger')
        if set(primary)&set(support) or set(excluded)&set(primary+support):raise ValueError('Conflicting anchor roles')
        event_checks={item['id']:item for item in change['checks']}
        if len(event_checks)!=len(change['checks']):raise ValueError('Duplicate evidence checks')
        if set(event_checks)!=set(primary+support+excluded):raise ValueError('Every reviewed anchor requires an explicit raw-evidence check')
        for rid,check in event_checks.items():
            if rid in checks and checks[rid]!=check:raise ValueError('Conflicting raw-evidence checks')
            checks[rid]=check
    ids=sorted(checks)
    cursor=con.execute('SELECT * FROM read_parquet(?,union_by_name=true,hive_partitioning=true) WHERE chronosift_row_id IN (SELECT unnest(?)) ORDER BY chronosift_row_id',[str(dataset/'**/*.parquet'),ids])
    columns=[d[0] for d in cursor.description];raw=[dict(zip(columns,row)) for row in cursor.fetchall()]
    if len(raw)!=len(ids) or {r['chronosift_row_id'] for r in raw}!=set(ids):raise ValueError('Missing or duplicate reviewed anchor')
    for row in raw:
        rid=row['chronosift_row_id'];check=checks[rid]
        if row.get('parser')!=check['parser']:raise ValueError(f'Parser mismatch for reviewed anchor {rid}')
        text=' '.join(str(row.get(field) or '') for field in ('message','filename'))
        if any(token not in text for token in check.get('contains',[])):raise ValueError(f'Observation mismatch for reviewed anchor {rid}')
        if any(row.get(k)!=v for k,v in check.get('fields_equal',{}).items()):raise ValueError(f'Structured field mismatch for reviewed anchor {rid}')
        if check.get('xml_data_equals'):
            document=ET.fromstring(row['xml_string'])
            fields={e.attrib.get('Name'):e.text for e in document.iter() if e.tag.rsplit('}',1)[-1]=='Data'}
            if any(fields.get(k)!=v for k,v in check['xml_data_equals'].items()):raise ValueError(f'XML identity mismatch for reviewed anchor {rid}')
    result={**ledger,'rows':[],'review_scope':'Audit-only; original ledger unchanged; reviewed evidence is not an independent hold-out.'}
    for original in ledger['rows']:
        event={**original,'original_anchor_ids':list(original['anchor_ids'])}
        change=changes.get(event['event_id'])
        if change:
            primary=change['primary_ids'];excluded=change['excluded_original_ids']
            supporting=sorted((set(original['anchor_ids'])|set(change.get('additional_supporting_ids',[])))-set(primary)-set(excluded))
            event.update(anchor_ids=sorted(set(original['anchor_ids'])|set(primary)|set(supporting)),
                primary_anchor_ids=primary,supporting_anchor_ids=supporting,misassigned_original_ids=excluded,
                unreviewed_anchor_ids=[],review_observation=change['observation'],review_rationale=change['rationale'])
        else:
            event.update(primary_anchor_ids=[],supporting_anchor_ids=[],misassigned_original_ids=[],
                unreviewed_anchor_ids=list(original['anchor_ids']),review_observation='Original ledger anchors; causal roles not reclassified in this review.')
        result['rows'].append(event)
    proof=dict(utc=stamp(),dataset=str(dataset),groundtruth_source=ledger['source'],groundtruth_sha256=ledger['sha256'],
        reviewed_rows=len(raw),checks=checks,raw_rows=raw,
        raw_rows_sha256=hashlib.sha256(json.dumps(raw,sort_keys=True,default=str).encode()).hexdigest())
    return result,proof


def prepare(source,pipeline):
    overlay=json.loads((source/'groundtruth_reviewed_anchors.json').read_text())
    con=duckdb.connect();con.execute("SET TimeZone='UTC'");con.execute("SET memory_limit='1GB'")
    try:
        for case,(name,_) in CASES.items():
            ledger=json.loads((source/f'groundtruth_{case}.json').read_text())
            if sha(Path(ledger['source']))!=ledger['sha256']:raise ValueError('Ground truth source changed')
            reviewed,proof=reviewed_ledger(con,pipeline/'parquet'/name,ledger,overlay[case])
            save(source/f'reviewed_groundtruth_{case}.json',reviewed)
            save(source/f'anchor_review_proof_{case}.json',proof)
            print('REVIEWED',case,proof['reviewed_rows'],flush=True)
    finally:con.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--pipeline',type=Path,required=True)
    args=parser.parse_args();prepare(args.source,args.pipeline)
