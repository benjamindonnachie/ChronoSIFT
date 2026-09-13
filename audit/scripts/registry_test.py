import sys,warnings,logging,copy
warnings.filterwarnings("ignore"); logging.disable(logging.CRITICAL); sys.path.insert(0,".")
import chronoSIFT_v2_31 as M
rules=M._load_unique_yaml_mapping("rules/rules_evidence_calibrated_v23.yaml","rules")
weights=M._load_unique_yaml_mapping("rules/weights_evidence_calibrated_v21.yaml","weights")

# A: can an operator DISABLE/REMOVE a detector via YAML alone?
r=copy.deepcopy(rules); del r["detector_policy"]["detectors"]["mft_timestomping"]
try:
    M.ChronoSiftEngine(r,weights); print("A. remove 'mft_timestomping'      -> ACCEPTED")
except Exception as e: print(f"A. remove 'mft_timestomping'      -> REFUSED: {str(e)[:95]}")

# B: can they RENAME one?
r=copy.deepcopy(rules)
r["detector_policy"]["detectors"]["mft_timestomping_v2"]=r["detector_policy"]["detectors"].pop("mft_timestomping")
try:
    M.ChronoSiftEngine(r,weights); print("B. rename 'mft_timestomping'      -> ACCEPTED")
except Exception as e: print(f"B. rename 'mft_timestomping'      -> REFUSED: {str(e)[:95]}")

# C: does 'enabled: false' satisfy the registry?
r=copy.deepcopy(rules); r["detector_policy"]["detectors"]["mft_timestomping"]["enabled"]=False
try:
    M.ChronoSiftEngine(r,weights); print("C. set enabled:false              -> ACCEPTED (registry satisfied by presence)")
except Exception as e: print(f"C. set enabled:false              -> REFUSED: {str(e)[:95]}")

# D: can a BRAND-NEW detector be added in YAML alone?
r=copy.deepcopy(rules)
src=copy.deepcopy(r["detector_policy"]["detectors"]["mft_timestomping"])
r["detector_policy"]["detectors"]["my_new_detector"]=src
try:
    M.ChronoSiftEngine(r,weights); print("D. add new detector id            -> ACCEPTED")
except Exception as e: print(f"D. add new detector id            -> REFUSED: {str(e)[:110]}")

# E: change a required detector's executor
r=copy.deepcopy(rules); r["detector_policy"]["detectors"]["execution_lolbin"]["executor"]="signal_projection"
try:
    M.ChronoSiftEngine(r,weights); print("E. change required executor       -> ACCEPTED")
except Exception as e: print(f"E. change required executor       -> REFUSED: {str(e)[:95]}")
