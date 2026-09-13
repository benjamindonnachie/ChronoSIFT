import yaml, re, ast, collections, sys

W = "rules/weights_evidence_calibrated_v21.yaml"
R = "rules/rules_evidence_calibrated_v23.yaml"

wdoc = yaml.safe_load(open(W))
weights = wdoc.get("weights", wdoc)
if isinstance(weights, dict) and "signal_weights" in weights:
    weights = weights["signal_weights"]
signal_names = set(k for k in weights if isinstance(k, str)) if isinstance(weights, dict) else set()
print(f"weights file: {W}  -> {len(signal_names)} signal names")

# Also harvest every 'signal:' / 'signals:' value from the rules doc
rdoc = yaml.safe_load(open(R))
harvested = set()
def walk(o, keypath=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("signal", "name") and isinstance(v, str) and re.fullmatch(r"[a-z][a-z0-9_]*", v):
                harvested.add(v)
            if k in ("signals", "emit", "emits", "require_all", "require_any", "reset_signals") and isinstance(v, list):
                for e in v:
                    if isinstance(e, str) and re.fullmatch(r"[a-z][a-z0-9_]*", e):
                        harvested.add(e)
            walk(v, f"{keypath}.{k}")
    elif isinstance(o, list):
        for e in o: walk(e, keypath)
walk(rdoc)
print(f"rules file  : {R}  -> {len(harvested)} harvested signal-ish names")

all_signals = signal_names | harvested
print(f"union       : {len(all_signals)}\n")

# Now: which of these appear as STRING LITERALS in the engine?
src = open("chronoSIFT_v2_31.py").read()
tree = ast.parse(src)
lit_lines = collections.defaultdict(list)
for node in ast.walk(tree):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value in all_signals:
            lit_lines[node.value].append(node.lineno)

print("="*90)
print("YAML SIGNAL NAMES APPEARING AS STRING LITERALS IN THE ENGINE")
print("="*90)
if not lit_lines:
    print("NONE — no YAML signal name is hardcoded in the engine.")
for name, lns in sorted(lit_lines.items(), key=lambda kv: -len(kv[1])):
    in_weights = "WEIGHTED" if name in signal_names else "         "
    print(f"{in_weights}  {name:<52} x{len(lns):<3} lines {lns[:8]}")
print(f"\ntotal distinct: {len(lit_lines)}")
