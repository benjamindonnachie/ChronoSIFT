"""Frozen, bounded native-driver comparison for v18 execution policy.

Actual evidence and enrichment; neutral profiling/no NSRL are explicit so this
is an execution regression, not a replacement for a production corpus audit.
Old and new sidecars are written only under the supplied fresh working folder.
"""
import argparse
from dataclasses import replace
import importlib.util
import json
import logging
from pathlib import Path
import resource
import shutil
import sys
import time

import pandas as pd
import memory_replay as common

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT.parent.parent
PREVIOUS = PIPE / 'working/20260909-identity-final-pGAZaw/provenance.json'


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=str) + '\n')


def prepare(out):
    p = json.loads(PREVIOUS.read_text())
    assert (out / 'baseline/chronoSIFT_v2_31.py').exists()
    assert not (out / 'provenance.json').exists()
    candidate = out / 'candidate'; candidate.mkdir()
    for name in ('chronoSIFT_v2_31.py', 'run_chronosift_sidecar_cli.py'):
        shutil.copy2(ROOT / name, candidate / name)
    for name in ('rules_evidence_calibrated_v18.yaml', 'weights_evidence_calibrated_v15.yaml'):
        shutil.copy2(ROOT / 'rules' / name, candidate / name)
    cases = [pair for pair in p['cases'] if pair[0] != 'windows-context']
    cases.insert(0, ['windows-history', str(common.HISTORY)])
    hashes = {}
    for folder in (out / 'baseline', candidate):
        for path in folder.iterdir():
            hashes[str(path)] = common.common.sha(path)
    for _, directory in cases:
        for path in Path(directory).rglob('*.parquet'):
            hashes[str(path)] = common.common.sha(path)
    for path in p['resources'].values():
        hashes[path] = common.common.sha(Path(path))
    save(out / 'provenance.json', dict(cases=cases, resources=p['resources'], hashes=hashes,
        scope='Native monthly sidecar v17/199h versus v18 dataset-aware/compact history. Actual YARA/AV/Luhn/GeoIP; neutral profiling, no NSRL. Bounded evidence, not production assessment.'))


def load(out, label):
    folder = out / label
    spec = importlib.util.spec_from_file_location('partition_' + label, folder / 'chronoSIFT_v2_31.py')
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    p = read_provenance(out)
    engine = module.ChronoSiftEngine.from_yaml(folder / f'rules_evidence_calibrated_v{17 if label == "baseline" else 18}.yaml',
        folder / 'weights_evidence_calibrated_v15.yaml', yara_metadata_path=p['resources']['yara'])
    engine.profiling_policy = replace(engine.profiling_policy, enabled=False)
    return module, engine, p


def worker(out, label, case):
    module, engine, p = load(out, label)
    directory = Path(dict(p['cases'])[case]); target = out / label / case; target.mkdir()
    resources = {k: Path(v) for k, v in p['resources'].items()}
    manifest = common.common.manifest_for(module, engine, directory, resources)
    started = time.monotonic()
    reports = engine.process_parquet_dataset_partitioned(str(directory), str(target / 'sidecar'),
        output_mode='sidecar', materialise_event_columns=True, file_hit_manifest=manifest,
        telemetry_jsonl_path=str(target / 'telemetry.jsonl'),
        **{k: str(v) for k, v in resources.items() if k != 'yara'})
    seconds = time.monotonic() - started
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != 'darwin': rss *= 1024
    result = module.load_plaso_parquet_dataset(str(target / 'sidecar'))
    # A Parquet null payload can arrive as pd.NA rather than None. Normalise
    # missing sentinels only; never turn real empty maps/lists into other data.
    for column in ('chronosift_signals', 'chronosift_explain'):
        if column in result:
            result[column] = pd.Series([None if value is pd.NA else value for value in result[column]],
                                       index=result.index, dtype=object)
    columns = common.fingerprints(module, engine, result, target / 'fingerprints.parquet')
    source_ids = module.load_plaso_parquet_dataset(str(directory), columns=['chronosift_row_id']).chronosift_row_id
    assert sorted(source_ids.tolist()) == sorted(result.chronosift_row_id.tolist()), 'Every input row exactly once'
    save(target / 'result.json', dict(rows=len(result), seconds=seconds, peak_rss_bytes=rss, columns=columns, reports=reports))
    print(label, case, len(result), round(seconds, 3), rss, flush=True)


def compare(out):
    p = read_provenance(out); results = []
    labels = ('baseline', p.get('candidate_label', 'candidate'))
    for case, directory in p['cases']:
        frames = [pd.read_parquet(out / label / case / 'fingerprints.parquet').set_index('id').sort_index()
                  for label in labels]
        assert frames[0].index.equals(frames[1].index), (case, 'row IDs')
        differences = {c: int((frames[0][c] != frames[1][c]).sum()) for c in frames[0]}
        scores = frames[1].score - frames[0].score
        variants = {name: json.loads((out / label / case / 'result.json').read_text()) for name, label in zip(('baseline', 'candidate'), labels)}
        assert variants['baseline']['columns'] == variants['candidate']['columns'], (case, 'schema')
        changed = frames[0].index[(frames[0] != frames[1]).any(axis=1)].tolist()
        anchors = [11243208, 11627225, 11628952, 11628979, 12147014, 12199528, 13565563, 13581759]
        results.append(dict(case=case, rows=len(frames[0]), differences=differences, changed_ids=changed,
            score_increases=int((scores > 0).sum()), score_decreases=int((scores < 0).sum()),
            anchor_scores={str(rid): [float(f.loc[rid, 'score']) for f in frames] for rid in anchors if rid in frames[0].index},
            top_candidate=frames[1].nlargest(10, 'score').reset_index()[['id', 'score']].to_dict('records'), variants=variants))
    unchanged = all(common.common.sha(Path(path)) == value for path, value in p['hashes'].items())
    assert unchanged, 'Frozen source/evidence/resources changed'
    save(out / ('comparison-typed.json' if p.get('candidate_label') == 'candidate-typed' else 'comparison.json'), dict(source_unchanged=unchanged, rows=sum(r['rows'] for r in results),
        exact=all(not any(r['differences'].values()) for r in results), cases=results))
    print(json.dumps([{k: r[k] for k in ('case', 'rows', 'differences', 'anchor_scores')} for r in results], indent=2))


def read_provenance(out):
    name = next(name for name in ('typed-provenance.json', 'final-provenance.json', 'provenance.json') if (out / name).exists())
    return json.loads((out / name).read_text())


def freeze_final(out, label='candidate-final'):
    p = json.loads((out / 'provenance.json').read_text())
    folder = out / label; folder.mkdir()
    for name in ('chronoSIFT_v2_31.py', 'run_chronosift_sidecar_cli.py'):
        shutil.copy2(ROOT / name, folder / name)
    for name in ('rules_evidence_calibrated_v18.yaml', 'weights_evidence_calibrated_v15.yaml'):
        shutil.copy2(ROOT / 'rules' / name, folder / name)
    for path in folder.iterdir(): p['hashes'][str(path)] = common.common.sha(path)
    p['candidate_label'] = label
    save(out / ('typed-provenance.json' if label == 'candidate-typed' else 'final-provenance.json'), p)


def recover(out, label, case):
    """Validate a completed write whose old fingerprint harness rejected pd.NA.

    Never rerun scoring or overwrite outputs. Exact worker timing/RSS were lost
    with that harness exception; retain only explicitly labelled telemetry time.
    """
    from datetime import datetime
    module, engine, p = load(out, label)
    target = out / label / case; assert not (target / 'result.json').exists()
    events = [json.loads(line) for line in (target / 'telemetry.jsonl').read_text().splitlines()]
    ends = [e for e in events if e['event'] == 'run_end']; assert len(ends) == 1
    result = module.load_plaso_parquet_dataset(str(target / 'sidecar'))
    for column in ('chronosift_signals', 'chronosift_explain'):
        if column in result:
            result[column] = pd.Series([None if value is pd.NA else value for value in result[column]], index=result.index, dtype=object)
    columns = common.fingerprints(module, engine, result, target / 'fingerprints.parquet')
    source_ids = module.load_plaso_parquet_dataset(dict(p['cases'])[case], columns=['chronosift_row_id']).chronosift_row_id
    assert sorted(source_ids.tolist()) == sorted(result.chronosift_row_id.tolist())
    save(target / 'result.json', dict(rows=len(result), columns=columns, peak_rss_bytes=None,
        seconds=(datetime.fromisoformat(ends[0]['ts_utc']) - datetime.fromisoformat(events[0]['ts_utc'])).total_seconds(),
        timing_source='recovered telemetry interval, not original worker stopwatch; peak RSS unavailable',
        reports=[e for e in events if e['event'] == 'partition_end'], recovered_after='fingerprint harness pd.NA error; completed sidecars not modified'))
    print('Recovered and validated completed sidecar', label, case, len(result), flush=True)


if __name__ == '__main__':
    logging.Formatter.converter = time.gmtime
    parser = argparse.ArgumentParser(); parser.add_argument('mode', choices=['prepare', 'worker', 'compare', 'freeze_final', 'recover'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--label', choices=['baseline', 'candidate', 'candidate-final', 'candidate-typed']); parser.add_argument('--case')
    args = parser.parse_args()
    if args.mode in ('worker', 'recover'): globals()[args.mode](args.output, args.label, args.case)
    elif args.mode == 'freeze_final': freeze_final(args.output, args.label or 'candidate-final')
    else: globals()[args.mode](args.output)
