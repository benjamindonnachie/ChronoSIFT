"""Offline, scoring-neutral ATT&CK attribution for configured rule producers.

YAML owns mappings; Python validates and exports them. Nothing in this module
changes signal values, scores, confidence, evidence admission or detector masks.
"""
from dataclasses import fields, is_dataclass
from functools import lru_cache
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import re
from types import MappingProxyType

ANNOTATION_KEYS = frozenset({'attack_ids', 'attack_basis', 'attack_note', 'attack_source'})
BASES = frozenset({'observed_behaviour', 'attempted_behaviour', 'contextual_inference',
                   'artefact_capability', 'unmapped'})
ID_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?\Z')


def parse_annotation(raw, path):
    """Validate annotation syntax; return a producer reference, never a signal key."""
    if not ANNOTATION_KEYS.intersection(raw):
        return ''
    required = {'attack_ids', 'attack_basis', 'attack_note'}
    if not required <= raw.keys():
        raise ValueError(f'{path}: ATT&CK annotation requires {sorted(required)}')
    ids = raw['attack_ids']
    if not isinstance(ids, list) or any(not isinstance(x, str) or not ID_PATTERN.fullmatch(x) for x in ids):
        raise ValueError(f'{path}.attack_ids: expected a list of ATT&CK technique IDs')
    if len(ids) != len(set(ids)):
        raise ValueError(f'{path}.attack_ids: duplicate technique ID')
    basis = raw['attack_basis']
    if not isinstance(basis, str) or basis not in BASES:
        raise ValueError(f'{path}.attack_basis: expected one of {sorted(BASES)}')
    if not isinstance(raw['attack_note'], str) or not raw['attack_note'].strip():
        raise ValueError(f'{path}.attack_note: expected a non-empty mapping rationale')
    source = raw.get('attack_source', 'policy')
    if not isinstance(source, str) or source not in {'policy', 'matched_external'}:
        raise ValueError(f'{path}.attack_source: expected policy or matched_external')
    if source == 'matched_external':
        if basis != 'artefact_capability' or ids:
            raise ValueError(f'{path}: matched_external requires artefact_capability and no static IDs')
    elif bool(ids) != (basis != 'unmapped'):
        raise ValueError(f'{path}: unmapped annotations must be empty; mapped policy annotations need IDs')
    # Unmapped background observations need no per-event metadata allocation.
    return path if basis != 'unmapped' else ''


@lru_cache(maxsize=4096)
def reference_fields(ref):
    """One immutable, tiny key/value mapping per producer, unpacked into explanations."""
    return MappingProxyType({'attack_ref': ref} if ref else {})


def iter_producers(doc):
    """Inventory actual emission definitions and ordinary atomic/temporal rules."""
    def walk(value, path, enabled=True, stage=''):
        if isinstance(value, dict):
            enabled = enabled and value.get('enabled', True) is not False
            stage = value.get('stage', stage)
            if {'name', 'value', 'rule_id'} <= value.keys():
                yield path, value, enabled, stage, (value['name'],)
            for key, child in value.items():
                yield from walk(child, f'{path}.{key}', enabled, stage)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from walk(child, f'{path}[{index}]', enabled, stage)
    yield from walk(doc.get('detector_policy', {}), 'detector_policy')
    for section, stage in [('rules', 'atomic'), ('temporal_rules', 'temporal')]:
        for index, rule in enumerate(doc.get(section, [])):
            yield f'{section}[{index}]', rule, True, stage, tuple(x['name'] for x in rule['emit']['signals'])


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'ATT&CK catalogue: duplicate JSON key {key!r}')
        result[key] = value
    return result


def _catalogue(name, expected_sha256):
    if not isinstance(name, str) or not re.fullmatch(r'enterprise-attack-\d+\.\d+\.json', name):
        raise ValueError('attack_metadata.catalogue: expected a bundled Enterprise catalogue filename')
    if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('attack_metadata.catalogue_sha256: expected lowercase SHA-256')
    raw = files('chronosift_data').joinpath(name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('ATT&CK catalogue checksum mismatch')
    data = json.loads(raw, object_pairs_hook=_unique_object)
    if (type(data.get('schema_version')) is not int or data['schema_version'] != 1
            or data.get('domain') != 'enterprise-attack'
            or name != f"enterprise-attack-{data.get('release')}.json"
            or not isinstance(data.get('techniques'), dict) or not data['techniques']):
        raise ValueError('ATT&CK catalogue schema/domain/release mismatch')
    for ident, item in data['techniques'].items():
        if not ID_PATTERN.fullmatch(ident) or not isinstance(item, dict):
            raise ValueError('ATT&CK catalogue contains an invalid technique')
        for key in ('revoked', 'deprecated'):
            if type(item.get(key)) is not bool:
                raise ValueError(f'ATT&CK catalogue {ident}.{key}: expected boolean')
    return data


def _typed_refs(value):
    if is_dataclass(value):
        for field in fields(value):
            child = getattr(value, field.name)
            if field.name == 'attack_ref':
                if child:
                    yield child
            else:
                yield from _typed_refs(child)
    elif isinstance(value, dict):
        for child in value.values():
            yield from _typed_refs(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            yield from _typed_refs(child)


class AttackMetadata:
    """Per-engine policy inventory and bounded external-ID resolution."""
    def __init__(self, doc):
        self.enabled = 'attack_metadata' in doc
        self.entries = {}
        self._external_cache = {}
        producers = list(iter_producers(doc))
        if not self.enabled:
            if any(ANNOTATION_KEYS.intersection(raw) for _, raw, *_ in producers):
                raise ValueError('ATT&CK annotations require an attack_metadata catalogue declaration')
            return
        cfg = doc['attack_metadata']
        required = {'schema_version', 'catalogue', 'catalogue_sha256', 'legacy_ids'}
        if not isinstance(cfg, dict) or set(cfg) != required or type(cfg['schema_version']) is not int or cfg['schema_version'] != 1:
            raise ValueError('attack_metadata: expected schema_version=1, catalogue, catalogue_sha256 and legacy_ids')
        self.catalogue = _catalogue(cfg['catalogue'], cfg['catalogue_sha256'])
        self.techniques = self.catalogue['techniques']
        legacy = cfg['legacy_ids']
        if not isinstance(legacy, dict):
            raise ValueError('attack_metadata.legacy_ids: expected ID-to-reviewed-rationale mapping')
        for ident, note in legacy.items():
            item = self.techniques.get(ident)
            if (not item or not (item['revoked'] or item['deprecated'])
                    or not isinstance(note, str) or not note.strip()):
                raise ValueError(f'attack_metadata.legacy_ids.{ident}: expected a retired ID and explicit rationale')
        used_legacy = set()
        for path, raw, enabled, stage, signals in producers:
            parse_annotation(raw, path)
            if not ANNOTATION_KEYS.intersection(raw):
                raise ValueError(f'{path}: catalogue-enabled policy requires mapped or explicitly unmapped annotation')
            for ident in raw['attack_ids']:
                item = self.techniques.get(ident)
                if item is None:
                    raise ValueError(f'{path}.attack_ids: unknown Enterprise ATT&CK ID {ident}')
                if item['revoked'] or item['deprecated']:
                    if ident not in legacy:
                        raise ValueError(f'{path}.attack_ids: retired ID {ident} needs explicit legacy review')
                    used_legacy.add(ident)
            self.entries[path] = dict(rule_id=raw.get('rule_id', raw.get('id')), signals=signals,
                attack_ids=tuple(raw['attack_ids']), attack_basis=raw['attack_basis'],
                attack_source=raw.get('attack_source', 'policy'), note=raw['attack_note'],
                enabled=enabled, stage=stage)
        if used_legacy != set(legacy):
            raise ValueError('attack_metadata.legacy_ids: unused legacy exception')
        encoded = json.dumps(self.entries, sort_keys=True, separators=(',', ':')).encode()
        self.provenance = dict(schema_version=1, domain='enterprise-attack', release=self.catalogue['release'],
            catalogue=cfg['catalogue'], catalogue_sha256=cfg['catalogue_sha256'],
            source=self.catalogue['source'], mapping_sha256=hashlib.sha256(encoded).hexdigest())

    def validate_typed_refs(self, *roots):
        if not self.enabled:
            return
        expected = {ref for ref, entry in self.entries.items() if entry['attack_basis'] != 'unmapped'}
        actual = set(ref for root in roots for ref in _typed_refs(root))
        if actual != expected:
            raise ValueError(f'ATT&CK producer/parser mismatch: missing={sorted(expected-actual)}, unknown={sorted(actual-expected)}')

    def _external_ids(self, raw):
        if not isinstance(raw, (list, tuple)) or any(not isinstance(x, str) for x in raw):
            raise ValueError('External ATT&CK IDs must remain a list of strings')
        key = tuple(sorted(set(raw)))
        if key not in self._external_cache:
            accepted, diagnostics = [], []
            for ident in key:
                item = self.techniques.get(ident)
                status = ('unknown' if item is None else 'revoked' if item['revoked'] else
                          'deprecated' if item['deprecated'] else 'recognized')
                if status == 'recognized':
                    accepted.append(ident)
                else:
                    diagnostics.append(f'{ident}: {status}')
            if len(self._external_cache) >= 4096:
                self._external_cache.pop(next(iter(self._external_cache)))
            self._external_cache[key] = (tuple(accepted), tuple(diagnostics))
        return key, self._external_cache[key]

    def annotate(self, item):
        """Called at final materialisation; input is an already isolated explanation."""
        ref = item.get('attack_ref')
        if not ref:
            return
        if not self.enabled or ref not in self.entries:
            raise ValueError(f'Unknown ATT&CK producer reference: {ref!r}')
        entry = self.entries[ref]
        if item.get('rule_id') != entry['rule_id']:
            raise ValueError('ATT&CK producer reference does not match the firing rule')
        ids = entry['attack_ids']
        if entry['attack_source'] == 'matched_external':
            evidence = item.get('evidence', {})
            if not isinstance(evidence, dict) or 'attack_ids' not in evidence or 'source' not in evidence:
                raise ValueError('External ATT&CK mapping requires matched profile evidence and provenance')
            reported, (ids, diagnostics) = self._external_ids(evidence['attack_ids'])
            item['attack_reported_ids'] = list(reported)
            item['attack_diagnostics'] = list(diagnostics)
        item['attack_ids'] = list(ids)
        item['attack_basis'] = entry['attack_basis']

    def run_metadata(self):
        if not self.enabled:
            return {}
        # External per-hash IDs may not occur in static mappings. Store names and
        # URLs for the whole small catalogue once per run, never in frame attrs.
        return dict(**self.provenance, producers=self.entries,
                    techniques=self.techniques)

    def write_run_metadata(self, output_root):
        if not self.enabled:
            return
        path = Path(output_root) / '_chronosift_attack_metadata.json'
        payload = json.dumps(self.run_metadata(), sort_keys=True, indent=2)
        if path.exists():
            if path.read_text() != payload:
                raise ValueError(f'Conflicting ATT&CK run metadata at {path}; use a fresh output directory')
            return
        with path.open('x') as handle:
            handle.write(payload)
