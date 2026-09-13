import pandas as pd, time, numpy as np
def make(n=3000, sr=3000):
    df = pd.DataFrame({"k": np.arange(n), "t": ["x"]*n})
    sparse = {"signals":{i:{f"s{j}":1.0 for j in range(6)} for i in range(sr)},
              "explain":{i:[f"e{j} r{i}" for j in range(4)] for i in range(sr)}}
    return df, sparse
def bench(attach, reads=200):
    df,sp = make()
    if attach: df.attrs["chronosift_sparse"]=sp
    loc=df.columns.get_loc("k"); t0=time.perf_counter(); s=0
    for pos in range(reads): s+=df.iat[pos,loc]
    return time.perf_counter()-t0
print("pandas",pd.__version__,"| 200 scalar .iat READS, 3k-row sparse payload")
b=min(bench(False) for _ in range(3)); a=min(bench(True) for _ in range(3))
print(f"  attrs detached : {b*1000:9.2f} ms")
print(f"  attrs attached : {a*1000:9.2f} ms  -> {a/b:7.1f}x slower")
