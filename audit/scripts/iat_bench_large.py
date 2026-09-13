import pandas as pd, numpy as np, time

def make(n=20000, sparse_rows=20000):
    df = pd.DataFrame({
        "distance_km": pd.Series([None]*n, dtype="object"),
        "from_country": pd.Series([None]*n, dtype="object"),
        "k": np.arange(n),
    })
    # realistic sparse payload: per-row signal dicts + explain lists
    sparse = {
        "signals": {i: {f"sig_{j}": 1.0 for j in range(6)} for i in range(sparse_rows)},
        "explain": {i: [f"evidence string {j} for row {i}" for j in range(4)] for i in range(sparse_rows)},
    }
    return df, sparse

def bench(attach, writes=4000):
    df, sparse = make()
    if attach:
        df.attrs["chronosift_sparse"] = sparse
    loc_d = df.columns.get_loc("distance_km")
    loc_c = df.columns.get_loc("from_country")
    t0 = time.perf_counter()
    for pos in range(writes):
        df.iat[pos, loc_d] = float(pos)
        df.iat[pos, loc_c] = "GB"
    return time.perf_counter() - t0

print("pandas", pd.__version__)
for attach in (False, True):
    ts = [bench(attach) for _ in range(3)]
    print(f"attrs attached={str(attach):<5}  best={min(ts)*1000:8.1f} ms   (8000 scalar .iat writes)")

# read path, for comparison with the documented finding
def bench_read(attach, reads=4000):
    df, sparse = make()
    if attach: df.attrs["chronosift_sparse"] = sparse
    loc = df.columns.get_loc("k")
    t0=time.perf_counter()
    s=0
    for pos in range(reads): s += df.iat[pos, loc]
    return time.perf_counter()-t0
print()
for attach in (False, True):
    ts=[bench_read(attach) for _ in range(3)]
    print(f"READ attrs attached={str(attach):<5} best={min(ts)*1000:8.1f} ms   (4000 scalar .iat reads)")
