"""Ground-truth-linked stage audit, after validation; never detection input."""
import json
from pathlib import Path
import time

from run_final_dataset_validation import save,sha,stamp

DETAIL='''b.chronosift_row_id,b.datetime,b.parser,b.filename,b.message,
    s.chronosift_score,s.chronosift_signals,s.chronosift_explain'''

def audit(con,dataset,run,source,case):
    if not json.loads((run/'validation.json').read_text())['valid']:
        raise ValueError('Audit requires validated full sidecars')
    out=run/'audit'; out.mkdir()
    ledger=json.loads((source/f'groundtruth_{case}.json').read_text())
    if sha(Path(ledger['source']))!=ledger['sha256']: raise ValueError('Ground truth changed')
    reviewed_path=source/f'reviewed_groundtruth_{case}.json'
    if reviewed_path.exists():
        reviewed=json.loads(reviewed_path.read_text())
        if reviewed['source']!=ledger['source'] or reviewed['sha256']!=ledger['sha256']:
            raise ValueError('Reviewed anchors reference a different ledger')
        originals={event['event_id']:event['anchor_ids'] for event in ledger['rows']}
        if {event['event_id']:event['original_anchor_ids'] for event in reviewed['rows']}!=originals:
            raise ValueError('Reviewed anchors did not preserve original references')
        ledger=reviewed
    ids=sorted({i for event in ledger['rows'] for i in event['anchor_ids']})
    # Validation has already defined base and side views on the complete corpus.
    baseline=json.loads((source/'baseline_runs.json').read_text())[case]
    con.from_parquet(str(Path(baseline)/'sidecar/**/*.parquet'),union_by_name=True,hive_partitioning=True).create_view('previous',replace=True)
    def query(name,sql,parameters=None):
        start=time.monotonic(); cursor=con.execute(sql,parameters or [])
        columns=[d[0] for d in cursor.description]; rows=[dict(zip(columns,row)) for row in cursor.fetchall()]
        save(out/(name+'.json'),dict(sql=sql,parameters=parameters or [],seconds=time.monotonic()-start,rows=rows))
        print(stamp(),'AUDIT',case,name,len(rows),flush=True)
        return rows
    save(out/'provenance.json',dict(utc=stamp(),groundtruth=ledger,baseline=baseline,
        source=str(source),script_sha256=sha(Path(__file__)),
        scope='Intermediate-stage plausibility; GT anchors/cohorts are audit-only. Prior full runs used older policies; Ubuntu also lacked actual YARA metadata. Not an optimisation A/B or a confusion matrix.'))
    anchors=query('anchors',f'''SELECT {DETAIL},p.chronosift_score AS previous_score
        FROM base b JOIN side s USING(chronosift_row_id) JOIN previous p USING(chronosift_row_id)
        WHERE b.chronosift_row_id IN (SELECT unnest(?)) ORDER BY b.chronosift_row_id''',[ids])
    if {row['chronosift_row_id'] for row in anchors}!=set(ids): raise ValueError('Audit anchors missing')
    by_id={row['chronosift_row_id']:row for row in anchors}
    matrix=[]
    for event in ledger['rows']:
        rows=[by_id[i] for i in event['anchor_ids']]
        matrix.append(dict(event_id=event['event_id'],description=event['event_description'],phase=event.get('phase'),
            anchor_ids=event['anchor_ids'],scores=[row['chronosift_score'] for row in rows],
            previous_scores=[row['previous_score'] for row in rows],
            primary_anchor_ids=event.get('primary_anchor_ids',[]),
            primary_scores=[by_id[i]['chronosift_score'] for i in event.get('primary_anchor_ids',[])],
            supporting_anchor_ids=event.get('supporting_anchor_ids',[]),
            supporting_scores=[by_id[i]['chronosift_score'] for i in event.get('supporting_anchor_ids',[])],
            misassigned_original_ids=event.get('misassigned_original_ids',[]),
            unreviewed_anchor_ids=event.get('unreviewed_anchor_ids',event['anchor_ids']),
            review_observation=event.get('review_observation','Original ledger anchors; causal roles not reclassified.'),
            review_rationale=event.get('review_rationale'),
            caveat='Exact anchor rows, not recall or proof of every described action.'))
    save(out/'groundtruth_matrix.json',matrix)
    query('overall', '''SELECT count(*) AS rows,count_if(chronosift_score>0) AS positive_rows,
        count_if(chronosift_score=50) AS capped_rows,max(chronosift_score) AS maximum FROM side''')
    query('monthly', '''SELECT year,month,count(*) AS rows,count_if(chronosift_score>0) AS positive_rows,
        max(chronosift_score) AS maximum FROM side GROUP BY 1,2 ORDER BY 1,2''')
    top=query('highest_events',f'''WITH best AS (SELECT chronosift_row_id FROM side
        ORDER BY chronosift_score DESC,chronosift_row_id LIMIT 60)
        SELECT {DETAIL},p.chronosift_score AS previous_score FROM best JOIN base b USING(chronosift_row_id)
        JOIN side s USING(chronosift_row_id) JOIN previous p USING(chronosift_row_id)
        ORDER BY s.chronosift_score DESC,b.chronosift_row_id''')
    query('full_score_changes', '''SELECT count(*) AS compared_rows,
        count_if(s.chronosift_score>p.chronosift_score+0.000001) AS increased,
        count_if(s.chronosift_score<p.chronosift_score-0.000001) AS decreased,
        count_if(p.chronosift_score>0 AND s.chronosift_score=0) AS lost_all_score
        FROM side s JOIN previous p USING(chronosift_row_id)''')
    if case=='windows':
        from windows_audit_reference import COHORTS,cohort_predicate
        cohorts=[(name,label,cohort_predicate(predicate)) for name,label,predicate in COHORTS]
    else:
        request="lower(coalesce(b.http_request,''))"; text="lower(concat_ws(' ',b.http_request,b.filename,b.message))"
        cohorts=[
            ('main_actor_http','GT client HTTP; IP is audit selector only',"b.parser='text/apache_access' AND b.ip_address='123.7.220.100'"),
            ('sqlmap','SQLmap user-agent comparator',"contains(lower(coalesce(b.http_request_user_agent,'')),'sqlmap')"),
            ('skipfish','Skipfish scanner comparator',"contains(coalesce(b.http_request_user_agent,''),'SF/2.10b')"),
            ('nmap','Nmap scanner comparator',"contains(coalesce(b.http_request_user_agent,''),'Nmap Scripting Engine')"),
            ('pre_attack_http','May1-27 HTTP background comparator',"b.parser='text/apache_access' AND b.datetime>=TIMESTAMPTZ '2024-05-01' AND b.datetime<TIMESTAMPTZ '2024-05-28'"),
            ('shell_requests','Observed main shell requests, not command completion',f"contains({request},'/shell.php')"),
            ('mysql_shell_requests','Observed MySQL shell requests; below metadata gate',f"contains({request},'mysql%20web%20shell.php')"),
            ('uploader_requests','Observed uploader requests',f"contains({request},'/uploader.php')"),
            ('dump_requests','Sensitive dump HTTP requests; status remains visible in raw evidence',f"contains({request},'/includes/sqldump.sql')"),
            ('content_changes','Target content file metadata, not visual proof',"b.parser='filestat' AND b.filename IN ('/var/www/html/contact/index.html','/var/www/html/contact/hacked.gif')"),
            ('database_metadata','Database metadata, not reconstructed SQL',f"b.parser='filestat' AND contains({text},'/var/lib/mysql/')"),
        ]
    summaries=[]
    for name,label,predicate in cohorts:
        clause=f'FROM base b JOIN side s USING(chronosift_row_id) WHERE {predicate}'
        stats=query(name+'_summary',f'''SELECT count(*) AS rows,count_if(s.chronosift_score>0) AS positive_rows,
            min(s.chronosift_score) AS minimum,max(s.chronosift_score) AS maximum {clause}''')[0]
        summaries.append(dict(cohort=name,label=label,**stats))
        query(name+'_highest',f'SELECT {DETAIL} {clause} ORDER BY s.chronosift_score DESC,b.chronosift_row_id LIMIT 12')
    save(out/'cohort_summary.json',summaries)
    lines=[f'# {case.title()} full-dataset stage audit','',
        'Automated evidence tables are complete. Human interpretation remains separate from reconciliation.',
        'Scores are out of 50, not probabilities. Ground truth was used only for this audit.',
        'The previous full-run policy differs; score changes are not an optimisation-only comparison.','',
        '## Ground-truth anchors','',
        'Reviewed primary observations are separated from supporting, misassigned and unreviewed original anchors. All originals remain in the JSON audit; no zero is silently discarded.',
        '', '| Event | Reviewed observation | Primary scores | All original/additional scores |','| --- | --- | --- | --- |']
    for item in matrix:
        lines.append(f"| {item['event_id']} | {item['review_observation'].replace('|','/')} | {', '.join(map(str,item['primary_scores'])) or 'Not reclassified'} | {', '.join(map(str,sorted(set(item['scores'])))) or 'No disk anchor'} |")
    lines+=['','## Highest-scoring evidence','','| Row ID | Score | Parser | Evidence excerpt |','| --- | ---: | --- | --- |']
    for row in top[:12]:
        excerpt=str(row['message'] or row['filename'] or '').replace('|','/').replace('\n',' ')[:220]
        lines.append(f"| {row['chronosift_row_id']} | {row['chronosift_score']:g} | {row['parser']} | {excerpt} |")
    lines+=['','Full explanations: `anchors.json`, `highest_events.json`, and `*_highest.json`. All supporting records remain joined by integer ID.']
    with (out/'ASSESSMENT.md').open('x') as handle: handle.write('\n'.join(lines)+'\n')
    save(out/'complete.json',dict(utc=stamp(),valid=True,anchors=len(ids),cohorts=len(cohorts),interpretation='Automated stage evidence tables; review contextual claims before adoption.'))
