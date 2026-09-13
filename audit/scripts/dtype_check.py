import sys,warnings,logging,numpy as np,pandas as pd,collections,time
warnings.filterwarnings("ignore"); logging.disable(logging.CRITICAL); sys.path.insert(0,".")
import chronoSIFT_v2_31 as M
rules=M._load_unique_yaml_mapping("rules/rules_evidence_calibrated_v23.yaml","rules")
weights=M._load_unique_yaml_mapping("rules/weights_evidence_calibrated_v21.yaml","weights")
eng=M.ChronoSiftEngine(rules,weights)
n=3000; rng=np.random.default_rng(7); base=pd.Timestamp("2024-05-01",tz="UTC")
idx=pd.DatetimeIndex(base+pd.to_timedelta(np.sort(rng.integers(0,86400*20,n)),unit="s"))
df=pd.DataFrame({
 "parser":rng.choice(np.array(["filestat","syslog","apache_access"]),n),
 "message":[f"sshd Accepted password for user{i%40} from 10.0.{i%250}.{i%99}" for i in range(n)],
 "filename":[f"/var/www/html/a{i%400}.php" for i in range(n)],
 "display_name":["TSK:/x"]*n,"timestamp_desc":rng.choice(["mtime","ctime"],n),
 "hostname":rng.choice(["web01"],n),"username":[f"user{i%40}" for i in range(n)],
},index=idx); df.index.name="datetime"
df=eng.ensure_required_fields(df)
c=collections.Counter(str(t) for t in df.dtypes)
print("dtypes after ensure_required_fields:")
for k,v in c.most_common(): print(f"   {k:<28} {v}")
print("\npd.options string storage:", pd.get_option("mode.string_storage"))

# Quantify the available win on a representative op
s_py = pd.Series([f"sshd Accepted password for user{i%40} from 10.0.{i%250}.{i}" for i in range(200000)], dtype="string[python]")
s_pa = s_py.astype("string[pyarrow]")
s_ob = s_py.astype(object)
import re
pat = r"(?i)accepted\s+password"
for name,s in (("object",s_ob),("string[python]",s_py),("string[pyarrow]",s_pa)):
    t0=time.perf_counter()
    for _ in range(3): s.str.contains(pat, regex=True, na=False)
    t1=(time.perf_counter()-t0)/3
    t0=time.perf_counter()
    for _ in range(3): s.str.strip()
    t2=(time.perf_counter()-t0)/3
    print(f"  {name:<16} contains={t1*1000:7.1f} ms   strip={t2*1000:7.1f} ms   (200k rows)")
