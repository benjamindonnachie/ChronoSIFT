import sys, time, warnings, yaml
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
import chronoSIFT_v2_31 as M

t0=time.perf_counter()
rules  = M._load_unique_yaml_mapping("rules/rules_evidence_calibrated_v23.yaml", "rules")
weights= M._load_unique_yaml_mapping("rules/weights_evidence_calibrated_v21.yaml", "weights")
t_load=time.perf_counter()-t0

t0=time.perf_counter()
eng = M.ChronoSiftEngine(rules, weights)
t_build=time.perf_counter()-t0
print(f"YAML load      : {t_load:6.2f}s")
print(f"engine build   : {t_build:6.2f}s   <-- policy parse + validation")
print(f"max_event_score: {eng.max_event_score}")
print(f"weights        : {len(eng.weights)} signals")
print(f"rules          : {len(eng.rules)}")
print(f"temporal_rules : {len(eng.temporal_rules)}")
dp = eng.detector_policy
print(f"detectors      : {len(dp.detectors)}")
