import ast, collections
src=open("chronoSIFT_v2_31.py").read(); tree=ast.parse(src)
own={}
for n in ast.walk(tree):
    if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
        for c in ast.walk(n): own.setdefault(id(c), n.name)
# numeric literals compared against non-policy expressions => candidate hardcoded thresholds
SAFE={0,1,-1,2,100,1000,255,0.0,1.0,2.0,0.5,3,4,8,16,32,64,24,60,3600,1024,65536,240,None,True,False}
rows=[]
for n in ast.walk(tree):
    if not isinstance(n,ast.Compare) or not n.ops: continue
    if not isinstance(n.ops[0],(ast.Lt,ast.LtE,ast.Gt,ast.GtE)): continue
    for side,other in ((n.comparators[0],n.left),(n.left,n.comparators[0])):
        if isinstance(side,ast.Constant) and isinstance(side.value,(int,float)) and not isinstance(side.value,bool):
            if side.value in SAFE: continue
            e=ast.unparse(other)
            if any(k in e.lower() for k in ("policy","cfg","config","spec","threshold","len(","limit","max","min","size","count","version")): continue
            rows.append((n.lineno, own.get(id(n),"<mod>"), e[:58], side.value))
print(f"candidate hardcoded numeric thresholds in comparisons: {len(rows)}\n")
for ln,o,e,v in sorted(rows)[:40]:
    print(f"  L{ln:<6} {o[:44]:<44} {e:<58} vs {v}")
