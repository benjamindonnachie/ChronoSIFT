import yaml, re, collections, json
TECH=re.compile(r"^T\d{4}(?:\.\d{3})?$")
d=yaml.safe_load(open("rules/rules_evidence_calibrated_v24.yaml"))
emissions=[]
def find(o,p=""):
    if isinstance(o,dict):
        if isinstance(o.get("name"),str) and ("value" in o or "rule_id" in o):
            emissions.append((p,o))
        for k,v in o.items(): find(v,f"{p}.{k}")
    elif isinstance(o,list):
        for e in o: find(e,p)
find(d.get("detector_policy",{}),"detector_policy")
print(f"emission blocks: {len(emissions)}")
have=[e for _,e in emissions if "attack_ids" in e]
nonempty=[e for e in have if e.get("attack_ids")]
empty=[e for e in have if not e.get("attack_ids")]
print(f"  with attack_ids key      : {len(have)}")
print(f"  with NON-EMPTY attack_ids: {len(nonempty)}")
print(f"  with EMPTY attack_ids    : {len(empty)}")
ids=collections.Counter()
bad=[]
for e in nonempty:
    for t in e["attack_ids"]:
        ids[t]+=1
        if not TECH.fullmatch(str(t)): bad.append((e["name"],t))
print(f"\ndistinct techniques mapped: {len(ids)}  (total refs {sum(ids.values())})")
print(f"malformed ids: {bad if bad else 'none'}")
basis=collections.Counter(e.get("attack_basis") for e in have)
print(f"\nattack_basis distribution:")
for k,v in basis.most_common(): print(f"   {str(k):<28} {v}")
src=collections.Counter(e.get("attack_source") for e in have if e.get("attack_source"))
print(f"attack_source: {dict(src)}")
print("\nemissions with EMPTY attack_ids (unmapped signals):")
for e in empty[:20]: print(f"   {e['name']:<52} basis={e.get('attack_basis')}")
if len(empty)>20: print(f"   ... {len(empty)-20} more")
meta=d.get("detector_policy",{}).get("attack_metadata") or d.get("attack_metadata")
print(f"\nattack_metadata: {json.dumps(meta, indent=2)[:600] if meta else 'NOT FOUND at top level'}")
