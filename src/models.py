from dataclasses import dataclass, field
from typing import List, Dict, Union

@dataclass
class YamlStateLedger:
    # 1. Dimension Vectors
    privilege_risk: str = "SAFE"       
    execution_risk: str = "SAFE"       
    supply_chain_risk: str = "SAFE"    
    runner_trust: str = "EPHEMERAL"    
    
    # 2. Context & Triggers
    trigger_event: str = ""
    is_high_risk_context: bool = False
    
    # 3. The Memory Bridge (Hierarchical Taint Handoff)
    tainted_env_vars: Dict[str, Union[List[str], Dict]] = field(default_factory=lambda: {
        'workflow': [],                   
        'jobs': {},                       
        'steps': {}                       
    })
    
    # 4. Forensic Log & Policy Heuristics
    critical_violations: List[str] = field(default_factory=list)
    heuristic_score: int = 0