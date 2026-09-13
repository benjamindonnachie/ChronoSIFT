import sys, time, warnings, numpy as np, pandas as pd
warnings.filterwarnings("ignore")
sys.path.insert(0,".")
import chronoSIFT_v2_31 as M

rules  = M._load_unique_yaml_mapping("rules/rules_evidence_calibrated_v23.yaml","rules")
weights= M._load_unique_yaml_mapping("rules/weights_evidence_calibrated_v21.yaml","weights")
eng = M.ChronoSiftEngine(rules, weights)

def synth(n):
    rng=np.random.default_rng(7)
    base=pd.Timestamp("2024-05-01",tz="UTC")
    idx=pd.DatetimeIndex(base+pd.to_timedelta(np.sort(rng.integers(0,86400*20,n)),unit="s"))
    parsers=np.array(["filestat","syslog","bash_history","utmp","apache_access","systemd_journal"])
    df=pd.DataFrame({
      "parser":rng.choice(parsers,n),
      "message":[f"event {i} sshd Accepted password for user{i%40} from 10.0.{i%250}.{i%99} port 2200" for i in range(n)],
      "filename":[f"/var/www/html/app{i%400}.php" if i%13==0 else f"/home/u{i%40}/f{i%900}.txt" for i in range(n)],
      "display_name":["TSK:/x"]*n,
      "timestamp_desc":rng.choice(["mtime","ctime","atime","crtime"],n),
      "hostname":rng.choice(["web01","db01"],n),
      "username":[f"user{i%40}" for i in range(n)],
    },index=idx)
    df.index.name="datetime"
    return df

for n in (2000, 10000, 40000):
    df=synth(n)
    df=eng.ensure_required_fields(df)
    t0=time.perf_counter()
    out=eng.apply(df.copy())
    dt=time.perf_counter()-t0
    res = out[0] if isinstance(out,tuple) else out
    sc = res["chronosift_score"] if "chronosift_score" in res.columns else None
    print(f"n={n:>6}  {dt:7.3f}s  {n/dt:9.0f} rows/s  "
          f"scored>0: {(sc>0).sum() if sc is not None else '?':>6}  cols={len(res.columns)}")
