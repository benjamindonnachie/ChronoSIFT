import yaml, re, collections, json
R = "rules/rules_evidence_calibrated_v24.yaml"
d = yaml.safe_load(open(R))

TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# 1. Where do ATT&CK IDs appear at all?
key_hits = collections.Counter()
val_hits = collections.Counter()
tech_ids = collections.Counter()
def walk(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str) and ("attack" in k.lower() or "technique" in k.lower() or "mitre" in k.lower()):
                key_hits[k] += 1
            if isinstance(v, str) and TECH.fullmatch(v):
                tech_ids[v] += 1
                val_hits[re.sub(r"\.[^.]*$","",path)+"."+k if k else path] += 1
            walk(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i,e in enumerate(o): walk(e, path)
walk(d)
print("=== keys mentioning attack/technique/mitre ===")
for k,c in key_hits.most_common(): print(f"  {k:<40} {c}")
print(f"\n=== distinct ATT&CK technique IDs found in YAML: {len(tech_ids)} ===")
print("  total occurrences:", sum(tech_ids.values()))
print("  sample:", ", ".join(sorted(tech_ids)[:25]))

# 2. Emissions: how many signals, how many carry an ATT&CK ID?
emissions = []
def find_emissions(o, path=""):
    if isinstance(o, dict):
        if "name" in o and isinstance(o.get("name"), str) and ("value" in o or "rule_id" in o):
            emissions.append((path, o))
        for k,v in o.items(): find_emissions(v, f"{path}.{k}")
    elif isinstance(o, list):
        for e in o: find_emissions(e, path)
find_emissions(d.get("detector_policy", {}), "detector_policy")
with_tech = [ (p,e) for p,e in emissions if any(isinstance(v,str) and TECH.fullmatch(v) for v in e.values()) ]
print(f"\n=== emission blocks (signal definitions) ===")
print(f"  total          : {len(emissions)}")
print(f"  with ATT&CK id : {len(with_tech)}")
print(f"  WITHOUT        : {len(emissions)-len(with_tech)}")
print("\n  fields present across emissions:")
fc = collections.Counter()
for p,e in emissions: fc.update(e.keys())
for k,c in fc.most_common(20): print(f"    {k:<26} {c}")
