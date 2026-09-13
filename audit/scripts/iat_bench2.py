import pandas as pd, numpy as np, time
def make(n=5000, sparse_rows=5000):
    df = pd.DataFrame({
        "distance_km": pd.Series([None]*n, dtype="object"),
        "from_country": pd.Series([None]*n, dtype="object"),
        "k": np.arange(n),
    })
    sparse = {
        "signals": {i: {f"sig_{j}": 1.0 for j in range(6)} for i in range(sparse_rows)},
        "explain": {i: [f"evidence {j} row {i}" for j in range(4)] for i in range(sparse_rows)},
    }
    return df, sparse
def bench(attach, writes=500):
    df, sparse = make()
    if attach: df.attrs["chronosift_sparse"] = sparse
    ld = df.columns.get_loc("distance_km"); lc = df.columns.get_loc("from_country")
    t0=time.perf_counter()
    for pos in range(writes):
        df.iat[pos, ld] = float(pos); df.iat[pos, lc] = "GB"
    return time.perf_counter()-t0
print("pandas", pd.__version__, "| 1000 scalar .iat WRITES, 5k-row sparse payload")
base = min(bench(False) for _ in range(3))
att  = min(bench(True)  for _ in range(3))
print(f"  attrs detached : {base*1000:9.2f} ms")
print(f"  attrs attached : {att*1000:9.2f} ms   -> {att/base:6.1f}x slower")
