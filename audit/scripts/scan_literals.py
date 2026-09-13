import ast, sys, collections, re

path = "chronoSIFT_v2_31.py"
src = open(path).read()
tree = ast.parse(src)
lines = src.splitlines()

# Map each node to its enclosing top-level function/class
owner = {}
def tag(node, name):
    for child in ast.walk(node):
        owner[id(child)] = name
for n in tree.body:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        tag(n, n.name)

def is_str_const(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)

def literal_strs(n):
    if is_str_const(n):
        return [n.value]
    if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
        if n.elts and all(is_str_const(e) for e in n.elts):
            return [e.value for e in n.elts]
    return None

def side_repr(n):
    try:
        return ast.unparse(n)
    except Exception:
        return "<?>"

# Names that indicate the compared expression is CONFIG/POLICY, not event data
POLICY_HINT = re.compile(
    r'policy|policies|cfg|config|spec|raw|node|entry|kind|mode|op\b|operator|'
    r'\.name\b|key\b|path\b|field\b|dtype|kwargs|meta\b|args|sys\.|schema',
    re.I)

results = []
for node in ast.walk(tree):
    if not isinstance(node, ast.Compare):
        continue
    if not node.ops or not isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
        continue
    left, right = node.left, node.comparators[0]
    lits = literal_strs(right)
    other = left
    if lits is None:
        lits = literal_strs(left)
        other = right
    if lits is None:
        continue
    expr = side_repr(other)
    results.append((node.lineno, owner.get(id(node), "<module>"), expr, lits))

print(f"total string comparisons: {len(results)}\n")

# Bucket: does the non-literal side look like policy/config, or like data?
data_like, policy_like = [], []
for lineno, own, expr, lits in results:
    (policy_like if POLICY_HINT.search(expr) else data_like).append((lineno, own, expr, lits))

print(f"policy/config-side comparisons: {len(policy_like)}")
print(f"OTHER (candidate data-side)   : {len(data_like)}\n")
print("=" * 100)
print("CANDIDATE DATA-SIDE STRING COMPARISONS (grouped by owning function)")
print("=" * 100)
by_owner = collections.defaultdict(list)
for lineno, own, expr, lits in data_like:
    by_owner[own].append((lineno, expr, lits))
for own, items in sorted(by_owner.items(), key=lambda kv: -len(kv[1])):
    print(f"\n### {own}  ({len(items)})")
    for lineno, expr, lits in items[:14]:
        shown = lits if len(lits) <= 6 else lits[:6] + ["..."]
        print(f"  L{lineno}: {expr[:70]:<70} vs {shown}")
    if len(items) > 14:
        print(f"  ... {len(items)-14} more")
