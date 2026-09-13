import sys, warnings, cProfile, pstats, io, logging, numpy as np, pandas as pd
warnings.filterwarnings("ignore"); logging.disable(logging.CRITICAL)
sys.path.insert(0,".")
import chronoSIFT_v2_31 as M
rules  = M._load_unique_yaml_mapping("rules/rules_evidence_calibrated_v23.yaml","rules")
weights= M._load_unique_yaml_mapping("rules/weights_evidence_calibrated_v21.yaml","weights")
eng = M.ChronoSiftEngine(rules, weights)
n=10000
rng=np.random.default_rng(7); base=pd.Timestamp("2024-05-01",tz="UTC")
idx=pd.DatetimeIndex(base+pd.to_timedelta(np.sort(rng.integers(0,86400*20,n)),unit="s"))
df=pd.DataFrame({
 "parser":rng.choice(np.array(["filestat","syslog","bash_history","utmp","apache_access","systemd_journal"]),n),
 "message":[f"event {i} sshd Accepted password for user{i%40} from 10.0.{i%250}.{i%99} port 2200" for i in range(n)],
 "filename":[f"/var/www/html/app{i%400}.php" if i%13==0 else f"/home/u{i%40}/f{i%900}.txt" for i in range(n)],
 "display_name":["TSK:/x"]*n,
 "timestamp_desc":rng.choice(["mtime","ctime","atime","crtime"],n),
 "hostname":rng.choice(["web01","db01"],n),
 "username":[f"user{i%40}" for i in range(n)],
},index=idx); df.index.name="datetime"
df=eng.ensure_required_fields(df)
pr=cProfile.Profile(); pr.enable(); eng.apply(df.copy()); pr.disable()
s=io.StringIO(); ps=pstats.Stats(pr,stream=s).sort_stats("cumulative"); ps.print_stats(28); print(s.getvalue()[:5200])
s2=io.StringIO(); pstats.Stats(pr,stream=s2).sort_stats("tottime").print_stats(22); 
print("\n\n===== BY SELF TIME (tottime) =====")
print(s2.getvalue()[:3800])
