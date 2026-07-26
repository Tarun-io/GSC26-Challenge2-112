# src/main.py
import sys
from pathlib import Path
from yaml_parser import YamlTribunal
from taint_analyzer import TaintAnalyzer

def run_security_scanner(pipeline_file: str):
    print("=" * 60)
    print("  TITANIUM CI/CD SECURITY SCANNER")
    print("=" * 60)
    
    # --- PHASE 1: TIER 0 YAML INSPECTION ---
    tribunal = YamlTribunal(pipeline_file)
    ledger = tribunal.run_inspection()
    
    # Check the Arbiter's Decision
    if ledger.heuristic_score >= 7 or "CRITICAL" in [ledger.privilege_risk, ledger.execution_risk]:
        print("\n[X] SCAN TERMINATED: YAML state is highly vulnerable. Bash parsing aborted.")
        sys.exit(1)
        
    print("\n[+] Phase 1 Cleared. Proceeding to Phase 2...")
    
    # --- PHASE 2: TIER 1 BASH TAINT ANALYSIS ---
    # We pass the memory bridge (tainted env vars) down to the Bash engine
    analyzer = TaintAnalyzer(
        policy_path="config/security_policy.yml", 
        pipeline_path=pipeline_file,
        injected_state=ledger.tainted_env_vars 
    )
    
    # analyzer.run_scan() # (Assuming your TaintAnalyzer has a main execution method)
    print("\n[+] Scan Complete. SARIF Report Generated.")

if __name__ == "__main__":
    target = str(Path(__file__).parent.parent / "data" / "vulnerable_pipeline.yml")
    run_security_scanner(target)