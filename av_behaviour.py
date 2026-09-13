"""Offline, hash-bound AV behavioural evidence. Semantics and weights live in YAML.

Transport schema parsing is deliberately separate from policy interpretation.
No network clients, dataframe copies, vendor-family heuristics or case constants.
"""
from collections import OrderedDict
from dataclasses import dataclass
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import re
import attack_metadata as _attack_metadata

SCHEMA_VERSION = 1
PARSER_VERSION = 1
_CATALOG_CACHE = OrderedDict()
_SOURCES = {'mitre', 'signature', 'sigma', 'tag'}
_FIELDS = {'technique', 'description', 'severity', 'provider', 'format', 'tag',
           'target_object', 'details', 'image', 'command_line', 'event_type'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _keys(value, expected, where):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f'{where}: expected exactly {sorted(expected)}')


def _strings(value, where, *, nonempty=True):
    if not isinstance(value, list) or (nonempty and not value) or any(not isinstance(x, str) or not x for x in value):
        raise ValueError(f'{where}: expected a list of nonempty strings')
    if len(set(value)) != len(value):
        raise ValueError(f'{where}: duplicate values')
    return tuple(value)


def _number(value, where, *, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or (maximum is not None and value > maximum):
        raise ValueError(f'{where}: expected a finite positive number' + (f' <= {maximum}' if maximum else ''))
    return float(value)


@dataclass(frozen=True)
class BehaviourPolicy:
    enabled: bool
    require_enriched_csv: bool
    max_contribution: float
    referenced_strength: float
    max_evidence: int
    capabilities: dict
    rules: tuple
    confidence: tuple
    policy_digest: str

    @property
    def emissions(self):
        return tuple(x['emission'] for x in self.capabilities.values())


def parse_policy(raw, emission_parser):
    where = 'clamav_classification.behaviour'
    _keys(raw, {'enabled', 'require_enriched_csv', 'max_contribution', 'referenced_strength',
                'max_evidence', 'capabilities', 'rules', 'confidence'}, where)
    for name in ('enabled', 'require_enriched_csv'):
        if type(raw[name]) is not bool:
            raise ValueError(f'{where}.{name}: expected boolean')
    if type(raw['max_evidence']) is not int or not 1 <= raw['max_evidence'] <= 32:
        raise ValueError(f'{where}.max_evidence: expected integer 1..32')
    if not isinstance(raw['capabilities'], dict) or not raw['capabilities']:
        raise ValueError(f'{where}.capabilities: expected nonempty mapping')
    capabilities = {}
    for name, value in raw['capabilities'].items():
        if not re.fullmatch(r'[a-z][a-z0-9_]*', name):
            raise ValueError(f'{where}: invalid capability identifier')
        _keys(value, {'emission', 'attack_ids'}, f'{where}.{name}')
        attack_ids = _strings(value['attack_ids'], f'{where}.{name}.attack_ids')
        if any(not re.fullmatch(r'T\d{4}(?:\.\d{3})?', x) for x in attack_ids):
            raise ValueError(f'{where}.{name}: invalid ATT&CK identifier')
        capabilities[name] = {'emission': emission_parser(value['emission'],
            f'detector_policy.detectors.clamav_classification.behaviour.capabilities.{name}.emission'), 'attack_ids': attack_ids}
    confidence = []
    if not isinstance(raw['confidence'], list) or not raw['confidence']:
        raise ValueError(f'{where}.confidence: expected ordered list')
    supports = set()
    names = set()
    previous = float('inf')
    for band in raw['confidence']:
        _keys(band, {'name', 'any_support', 'strength'}, where+'.confidence')
        if band['name'] not in {'low', 'medium', 'high'} or band['name'] in names:
            raise ValueError(f'{where}: confidence names must be unique low/medium/high')
        support = _strings(band['any_support'], where+'.confidence.any_support')
        strength = _number(band['strength'], where+'.confidence.strength', maximum=1)
        if strength >= previous:
            raise ValueError(f'{where}: confidence strengths must strictly descend')
        previous = strength
        confidence.append((band['name'], frozenset(support), strength))
        supports.update(support); names.add(band['name'])
    rules = []
    ids = set()
    if not isinstance(raw['rules'], list) or not raw['rules']:
        raise ValueError(f'{where}.rules: expected nonempty list')
    for item in raw['rules']:
        _keys(item, {'id', 'source', 'capability', 'support', 'conditions', 'attack_ids'}, where+'.rules')
        if not isinstance(item['id'], str) or not re.fullmatch(r'[a-z][a-z0-9_]*', item['id']) or item['id'] in ids:
            raise ValueError(f'{where}: invalid or duplicate evidence rule ID')
        ids.add(item['id'])
        if item['source'] not in _SOURCES or item['capability'] not in capabilities or item['support'] not in supports:
            raise ValueError(f'{where}.{item["id"]}: unknown source, capability or support')
        conditions = []
        if not isinstance(item['conditions'], list) or not item['conditions']:
            raise ValueError(f'{where}.{item["id"]}: conditions cannot be empty')
        for condition in item['conditions']:
            op = condition.get('op') if isinstance(condition, dict) else None
            expected = {'field', 'op'} | ({'values'} if op == 'in' else {'pattern'} if op == 'regex' else set())
            _keys(condition, expected, where+'.conditions')
            if condition['field'] not in _FIELDS or op not in {'in', 'regex', 'exists'}:
                raise ValueError(f'{where}: unsupported condition field/operator')
            operand = None
            if op == 'in':
                operand = frozenset(_strings(condition['values'], where+'.conditions.values'))
            if op == 'regex':
                if not isinstance(condition['pattern'], str) or not condition['pattern']:
                    raise ValueError(f'{where}: expected nonempty regex')
                operand = re.compile(condition['pattern'])
            conditions.append((condition['field'], op, operand))
        attack_ids = _strings(item['attack_ids'], where+'.rules.attack_ids', nonempty=False)
        if any(not re.fullmatch(r'T\d{4}(?:\.\d{3})?', x) for x in attack_ids):
            raise ValueError(f'{where}: invalid rule ATT&CK identifier')
        rules.append((item['id'], item['source'], item['capability'], item['support'], tuple(conditions), attack_ids))
    return BehaviourPolicy(raw['enabled'], raw['require_enriched_csv'],
        _number(raw['max_contribution'], where+'.max_contribution'),
        _number(raw['referenced_strength'], where+'.referenced_strength', maximum=1), raw['max_evidence'],
        capabilities, tuple(rules), tuple(confidence), digest(json.dumps(raw, sort_keys=True).encode()))


def _pointer(value):
    return value.replace('~', '~0').replace('/', '~1')


def iter_findings(endpoint, body, report_file):
    """Yield compact transport facts, never interpret ATT&CK descriptions as hits."""
    data = body.get('data')
    if data is None:
        return
    if not isinstance(data, dict):
        raise ValueError(f'{report_file}: expected object or null data')
    if endpoint == 'behaviour_mitre_trees':
        for provider, report in data.items():
            if not isinstance(report, dict):
                raise ValueError(f'{report_file}: malformed analysis provider')
            for ti, tactic in enumerate(report.get('tactics', [])):
                for ii, technique in enumerate(tactic.get('techniques', [])):
                    for si, signature in enumerate(technique.get('signatures') or []):
                        yield {'source': 'mitre', 'technique': technique.get('id', ''),
                            'description': signature.get('description', ''), 'severity': signature.get('severity', ''),
                            'provider': provider, 'report': report_file,
                            'pointer': f'/data/{_pointer(provider)}/tactics/{ti}/techniques/{ii}/signatures/{si}'}
        return
    if endpoint != 'behaviour_summary':
        raise ValueError('Unsupported behaviour endpoint')
    for i, item in enumerate(data.get('mitre_attack_techniques') or []):
        yield {'source': 'mitre', 'technique': item.get('id', ''), 'description': item.get('signature_description', ''),
            'severity': str(item.get('severity', '')).removeprefix('IMPACT_SEVERITY_'),
            'provider': 'VT merged summary', 'report': report_file, 'pointer': f'/data/mitre_attack_techniques/{i}'}
    for i, item in enumerate(data.get('signature_matches') or []):
        yield {'source': 'signature', 'description': item.get('description') or item.get('name', ''),
            'format': item.get('format', ''), 'provider': str(item.get('rule_src', '')),
            'report': report_file, 'pointer': f'/data/signature_matches/{i}'}
    for i, item in enumerate(data.get('sigma_analysis_results') or []):
        # Only events with matched values qualify; title/level alone is not an event.
        for j, context in enumerate(item.get('match_context') or []):
            values = context.get('values', {})
            if not isinstance(values, dict):
                raise ValueError(f'{report_file}: malformed Sigma matched values')
            yield {'source': 'sigma', 'description': item.get('rule_description', ''),
                'severity': item.get('rule_level', ''), 'provider': item.get('rule_source', ''),
                'target_object': values.get('TargetObject', ''), 'details': values.get('Details', ''),
                'image': values.get('Image', ''), 'command_line': values.get('CommandLine', ''),
                'event_type': values.get('EventType', ''), 'report': report_file,
                'pointer': f'/data/sigma_analysis_results/{i}/match_context/{j}'}
    for i, tag in enumerate(data.get('tags') or []):
        if not isinstance(tag, str):
            raise ValueError(f'{report_file}: behaviour tags must be strings')
        yield {'source': 'tag', 'tag': tag, 'provider': 'VT merged summary',
            'report': report_file, 'pointer': f'/data/tags/{i}'}


def make_profile(findings, policy, sha256, source):
    matches = {}
    for fact in findings:
        for rule_id, origin, capability, support, conditions, attack_ids in policy.rules:
            if fact['source'] != origin:
                continue
            matched = True
            for field, op, operand in conditions:
                value = fact.get(field, '')
                if not isinstance(value, str):
                    raise ValueError(f'Behaviour fact {field} must be text')
                if not (bool(value.strip()) if op == 'exists' else value in operand if op == 'in' else bool(operand.search(value))):
                    matched = False; break
            if not matched:
                continue
            record = matches.setdefault(capability, {'support': set(), 'evidence': {}, 'attack_ids': set()})
            record['support'].add(support)
            record['attack_ids'].update(attack_ids)
            if origin == 'mitre':
                record['attack_ids'].add(fact['technique'])
            # Duplicate tactics, mappings or Sigma rules never produce extra strength.
            signature = (support, fact['source'], fact.get('description', ''), fact.get('tag', ''),
                         fact.get('target_object', ''), fact.get('details', ''))
            if signature not in record['evidence'] and sum(key[0] == support for key in record['evidence']) < policy.max_evidence:
                record['evidence'][signature] = {'policy_rule': rule_id, 'source_kind': origin, 'support_kind': support,
                    'provider': fact.get('provider', ''), 'report': fact['report'], 'pointer': fact['pointer'],
                    'detail': (fact.get('details') or fact.get('description') or fact.get('tag', ''))[:240]}
    capabilities = {}
    for name, item in matches.items():
        for confidence, support, strength in policy.confidence:
            if item['support'] & support:
                capabilities[name] = {'confidence': confidence, 'strength': strength,
                    'support': sorted(item['support']), 'attack_ids': sorted(item['attack_ids']),
                    'evidence': sorted(item['evidence'].values(), key=lambda x: x['support_kind'] not in support)[:policy.max_evidence]}
                break
    return {'sha256': sha256, 'source': source, 'capabilities': capabilities}


def _read_report(root, name, expected):
    if not isinstance(name, str) or not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Behaviour report requires a path and SHA-256 digest')
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Behaviour report path must stay inside enrichment directory')
    file = (root / relative).resolve(strict=True)
    if not file.is_relative_to(root.resolve()):
        raise ValueError('Behaviour report symlink escapes enrichment directory')
    data = file.read_bytes()
    if digest(data) != expected:
        raise ValueError(f'Behaviour report digest mismatch: {name}')
    body = json.loads(data)
    if not isinstance(body, dict) or 'data' not in body:
        raise ValueError(f'Malformed behaviour report: {name}')
    return body


def load_catalog(csv_path, policy):
    """Content-versioned bounded cache; raw reports are verified on initial load.

    Each run consumes an immutable enrichment snapshot. Replacing CSV bytes,
    even with unchanged size/mtime, selects a new cache key and revalidates it.
    """
    if not policy or not policy.enabled:
        return {}
    if not csv_path:
        if policy.require_enriched_csv:
            raise ValueError('Configured AV behavioural enrichment requires an AV CSV path')
        return {}
    file = Path(csv_path).resolve(strict=True)
    contents = file.read_bytes()
    source_digest = digest(contents)
    key = (str(file), source_digest, policy.policy_digest, PARSER_VERSION)
    if key in _CATALOG_CACHE:
        _CATALOG_CACHE.move_to_end(key)
        return _CATALOG_CACHE[key]
    old_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(max(old_limit, 16 * 1024 * 1024))
        reader = csv.DictReader(io.StringIO(contents.decode('utf-8-sig')))
        fields = reader.fieldnames or []
        if len(set(fields)) != len(fields) or not {'sha256', 'av_hit'} <= set(fields):
            raise ValueError('AV behaviour CSV requires unique sha256 and av_hit columns')
        enriched = 'vt_behaviour_context' in fields
        if not enriched:
            if policy.require_enriched_csv:
                raise ValueError('Configured AV behavioural enrichment is missing vt_behaviour_context')
            if any(name.startswith('vt_behaviour_') for name in fields):
                raise ValueError('Incomplete AV behavioural enrichment columns')
            return {}
        catalog = {}; seen = {}
        for row in reader:
            sha256 = (row.get('sha256') or '').strip().upper()
            if not sha256 or sha256.startswith('#'):
                continue
            if not re.fullmatch(r'[0-9A-F]{64}', sha256):
                raise ValueError('AV behavioural enrichment contains an invalid SHA-256')
            if (row.get('av_hit') or '').casefold() not in {'true', '1'}:
                continue
            context = json.loads(row.get('vt_behaviour_context') or 'null')
            if not isinstance(context, dict) or type(context.get('schema_version')) is not int or context['schema_version'] != SCHEMA_VERSION:
                raise ValueError('Unsupported AV behavioural enrichment schema')
            if str(context.get('sha256', '')).upper() != sha256:
                raise ValueError('AV behavioural enrichment hash identity mismatch')
            canonical = json.dumps(context, sort_keys=True)
            if sha256 in seen:
                if seen[sha256] != canonical:
                    raise ValueError('Conflicting behavioural metadata for duplicate SHA-256')
                continue
            seen[sha256] = canonical
            endpoints = context.get('endpoints')
            if not isinstance(endpoints, list) or len(endpoints) != 2 or {x.get('endpoint') for x in endpoints if isinstance(x, dict)} != {'behaviour_mitre_trees', 'behaviour_summary'}:
                raise ValueError('Behavioural context requires both endpoint statuses')
            findings = []
            sources = []
            for entry in endpoints:
                if str(entry.get('hash', '')).upper() != sha256:
                    raise ValueError('Behaviour endpoint hash identity mismatch')
                status = entry.get('status')
                if status in {'available', 'no_summary_returned'}:
                    body = _read_report(file.parent, entry.get('report_file'), entry.get('report_sha256'))
                    expected_url = f'https://www.virustotal.com/api/v3/files/{sha256.lower()}/{entry["endpoint"]}'
                    if body.get('links', {}).get('self', expected_url) != expected_url:
                        raise ValueError('Behaviour report self-link identity mismatch')
                    if status == 'no_summary_returned' and body != {'data': None}:
                        raise ValueError('Null-summary status does not match raw response')
                    if status == 'available' and not isinstance(body['data'], dict):
                        raise ValueError('Available behaviour report must contain object data')
                    findings.extend(iter_findings(entry['endpoint'], body, entry['report_file']))
                    sources.append({'file': entry['report_file'], 'sha256': entry['report_sha256'], 'status': status})
                elif status not in {'not_found', 'access_denied', 'quota_limited', 'not_requested', 'http_error', 'authentication_error', 'request_or_validation_error'}:
                    raise ValueError(f'Unknown behaviour endpoint status: {status!r}')
            catalog[sha256] = make_profile(findings, policy, sha256,
                {'csv_sha256': source_digest, 'policy_sha256': policy.policy_digest, 'reports': sources})
    finally:
        csv.field_size_limit(old_limit)
    _CATALOG_CACHE[key] = catalog
    while len(_CATALOG_CACHE) > 4:
        _CATALOG_CACHE.popitem(last=False)
    return catalog


def merge_into_row(policy, profiles, signals, explanations, weights, *, scope):
    """One bounded contribution per capability; preserve provenance, not vote counts."""
    if not policy or not policy.enabled:
        return
    owned = {item['emission'].rule_id: name for name, item in policy.capabilities.items()}
    candidates = {}
    retained = []
    for entry in explanations:
        name = owned.get(entry.get('rule_id'))
        if name and entry.get('evidence', {}).get('av_behaviour_schema') == SCHEMA_VERSION:
            candidates[name] = (entry['evidence']['unscaled_strength'], entry['confidence'], entry['evidence'])
        else:
            retained.append(entry)
    for profile in profiles:
        for name, detail in profile.get('capabilities', {}).items():
            if name not in policy.capabilities:
                raise ValueError('Cached AV profile has unknown capability')
            raw = detail['strength'] * (1.0 if scope in {'hash', 'upload_hash'} else policy.referenced_strength)
            if name in candidates and candidates[name][0] >= raw:
                continue
            evidence = {'av_behaviour_schema': SCHEMA_VERSION, 'capability': name,
                'sha256': profile['sha256'], 'match_scope': scope, 'unscaled_strength': raw,
                'support': detail['support'], 'attack_ids': detail['attack_ids'],
                'capability_confidence': detail['confidence'],
                'identity_confidence': 'high' if scope in {'hash', 'upload_hash'} else 'medium',
                'source': profile['source'], 'findings': detail['evidence'],
                'interpretation': 'AV-supported suspected capability; not proof of local execution or outcome'}
            confidence = 'medium' if scope not in {'hash', 'upload_hash'} and detail['confidence'] == 'high' else detail['confidence']
            candidates[name] = (raw, confidence, evidence)
    if not candidates:
        return
    unbounded = sum(raw * policy.capabilities[name]['emission'].value * float(weights.get(policy.capabilities[name]['emission'].name, 0))
                    for name, (raw, _, _) in candidates.items())
    factor = min(1.0, policy.max_contribution / unbounded) if unbounded else 1.0
    explanations[:] = retained
    for name, (raw, confidence, evidence) in candidates.items():
        emission = policy.capabilities[name]['emission']
        signals[emission.name] = raw * emission.value * factor
        explanations.append({**_attack_metadata.reference_fields(emission.attack_ref),
            'rule_id': emission.rule_id, 'description': emission.description,
            'confidence': confidence, 'evidence_type': 'contextual', 'signals': [emission.name],
            'evidence': {**evidence, 'contribution_cap': policy.max_contribution, 'cap_multiplier': factor}})


def validate_payload(payload, policy):
    if not payload:
        return
    if not policy or not policy.enabled:
        raise ValueError('AV behavioural manifest supplied to disabled policy')
    _keys(payload, {'schema_version', 'policy_sha256', 'profiles', 'paths', 'web_paths',
                    'web_casefold_paths', 'web_names', 'web_casefold_names'}, 'AV behavioural manifest')
    if type(payload['schema_version']) is not int or payload['schema_version'] != SCHEMA_VERSION or payload['policy_sha256'] != policy.policy_digest:
        raise ValueError('AV behavioural manifest schema/policy mismatch')
    profiles = payload['profiles']
    if not isinstance(profiles, dict):
        raise ValueError('AV behavioural profiles must be a mapping')
    for key, profile in profiles.items():
        if not re.fullmatch(r'[A-F0-9]{64}', key) or profile.get('sha256') != key:
            raise ValueError('AV behavioural profile hash mismatch')
        if profile.get('source', {}).get('policy_sha256') != policy.policy_digest:
            raise ValueError('AV behavioural profile policy mismatch')
        for name, detail in profile.get('capabilities', {}).items():
            if name not in policy.capabilities or (detail.get('confidence'), detail.get('strength')) not in {(level, strength) for level, _, strength in policy.confidence}:
                raise ValueError('AV behavioural profile confidence/strength mismatch')
    for field in ('paths', 'web_paths', 'web_casefold_paths', 'web_names', 'web_casefold_names'):
        if not isinstance(payload[field], dict):
            raise ValueError('AV behavioural identity map must be a mapping')
        for hashes in payload[field].values():
            if not isinstance(hashes, list) or not set(hashes) <= profiles.keys():
                raise ValueError('AV behavioural identity refers to unknown hash')
