import ast, re, collections
src = open("chronoSIFT_v2_31.py").read()
tree = ast.parse(src)
owner = {}
for n in tree.body:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        for c in ast.walk(n): owner[id(c)] = n.name
# method-level owner inside the engine class
mowner = {}
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for c in ast.walk(n): mowner.setdefault(id(c), n.name)

def is_s(n): return isinstance(n, ast.Constant) and isinstance(n.value, str)
def lits(n):
    if is_s(n): return [n.value]
    if isinstance(n,(ast.Tuple,ast.List,ast.Set)) and n.elts and all(is_s(e) for e in n.elts):
        return [e.value for e in n.elts]
    return None

# Things that are clearly NOT detection content
BENIGN = re.compile(
    r'\.columns\b|^available$|^desired_columns$|^frame$|^out$|^df$|^subset$|'
    r'executor|\.stage\b|^method$|^unit$|^kind$|^tag$|^tags$|^original_tags$|'
    r'^role$|\.match\b|^mode$|^op$|^operator$|policy|cfg|config|spec|schema|'
    r'^name$|^key$|^field$|^column$|\.name\b|\.kind\b|\.dtype\b|sys\.|os\.', re.I)

rows=[]
for node in ast.walk(tree):
    if not isinstance(node, ast.Compare) or not node.ops: continue
    if not isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn)): continue
    l,r = node.left, node.comparators[0]
    v = lits(r); other = l
    if v is None: v = lits(l); other = r
    if v is None: continue
    e = ast.unparse(other)
    if BENIGN.search(e): continue
    rows.append((node.lineno, owner.get(id(node),'<mod>'), mowner.get(id(node),'?'), e, v))

print(f"non-benign string comparisons: {len(rows)}\n")
by = collections.defaultdict(list)
for ln,o,m,e,v in rows: by[(o,m)].append((ln,e,v))
for (o,m),items in sorted(by.items(), key=lambda kv:-len(kv[1])):
    print(f"\n### {o} :: {m}  ({len(items)})")
    for ln,e,v in items[:12]:
        print(f"  L{ln}: {e[:64]:<64} vs {v if len(v)<=5 else v[:5]+['...']}")
    if len(items)>12: print(f"  ...{len(items)-12} more")
