import sys
import re
from pathlib import Path
import networkx as nx
from ruamel.yaml import YAML
from collections import deque  # Added for the BFS Fix!
from reporter import generate_sarif_report

# Import our original Phase 1 & 2 engines
from parser import extract_run_blocks
from graph_builder import build_pipeline_map

# --- The AST Engines ---
import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser

BASH_LANGUAGE = Language(tsbash.language())
parser = Parser(BASH_LANGUAGE)

# ==========================================
# 1. THE AST BRIDGES (KEPT EXACTLY AS YOU WROTE THEM)
# ==========================================
def bridge_bash_variables(graph: nx.DiGraph):
    nodes = list(graph.nodes(data=True))
    for node, data in nodes:
        if isinstance(node, str) and node.startswith('$'):
            base_var = node.replace('$', '').replace('{', '').replace('}', '')
            if graph.has_node(base_var):
                graph.add_edge(base_var, node, relation="variable_expansion")

def bridge_bash_io(graph: nx.DiGraph, script_text: str):
    """Uses Tree-sitter to perfectly map Bash grammar file redirects."""
    source_bytes = script_text.encode('utf8')
    tree = parser.parse(source_bytes)
    
    def crawl_ast_for_redirects(node):
        if node.type == 'redirected_statement':
            body_node = node.child_by_field_name('body')
            target_file = None
            
            for child in node.children:
                if child.type == 'file_redirect':
                    dest_node = child.child_by_field_name('destination')
                    if dest_node:
                        target_file = source_bytes[dest_node.start_byte:dest_node.end_byte].decode('utf8')
            
            if body_node and target_file:
                body_text = source_bytes[body_node.start_byte:body_node.end_byte].decode('utf8')
                variables = re.findall(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', body_text)
                
                for var in variables:
                    var_node = f"${var}"
                    if graph.has_node(var_node):
                        if not graph.has_node(target_file):
                            graph.add_node(target_file, type='artifact')
                        graph.add_edge(var_node, target_file, relation="ast_file_redirect")
                        print(f"    [AST Mapped] {var_node} bridged to {target_file}")

        for child in node.children:
            crawl_ast_for_redirects(child)
            
    crawl_ast_for_redirects(tree.root_node)

# ==========================================
# 2. THE NEW TIER 1 ENGINE (OBJECT-ORIENTED)
# ==========================================
class TaintAnalyzer:
    def __init__(self, policy_path: str, pipeline_path: str, injected_state: dict = None):
        """Initializes the engine and accepts the Memory Bridge from YAML Tier 0."""
        self.pipeline_path = pipeline_path
        
        # Issue 2 Fixed: We now catch the Tier 0 state
        self.injected_state = injected_state or {'workflow': [], 'jobs': {}, 'steps': {}}
        
        yaml = YAML(typ='safe')
        with open(policy_path, 'r') as f:
            self.policy = yaml.load(f)
            
        self.sources = set(self.policy.get('sources', []))
        self.sinks = set(self.policy.get('sinks', []))
        self.sanitizers = set(self.policy.get('sanitizers', []))
        self.trucks = set(self.policy.get('trucks', []))
        self.ignore = set(self.policy.get('ignore', []))
        
        # Replaces global variable CLOUD_LOCKER
        self.cloud_locker = set()
        self.vulnerabilities = []

    def run_scan(self):
        """Extracts scripts, builds the map, and runs the gauntlet."""
        print(f"\n[*] Booting Tier 1 Taint Engine for: {Path(self.pipeline_path).name}")
        scripts = extract_run_blocks(self.pipeline_path)
        
        if not scripts:
            print("[-] No executable Bash blocks found. Skipping.")
            return self.vulnerabilities

        for i, script in enumerate(scripts):
            job_name = f"Job_{i+1}"
            print(f"--- Scanning {job_name} ---")
            
            # Build and bridge the graph using your original logic
            job_graph = build_pipeline_map(script)
            bridge_bash_variables(job_graph)
            bridge_bash_io(job_graph, script) 
            
            self._analyze_job(job_graph, job_name)
            
        return self.vulnerabilities

    def _analyze_job(self, graph: nx.DiGraph, job_name: str):
        """Scans the AST map using the Policy and the Memory Bridge."""
        current_sources = []
        upload_trucks = []
        current_sinks = []

        # Sweep the map
        for node, data in graph.nodes(data=True):
            if isinstance(node, str):
                
                # Standard YAML Policy Sources
                if any(src in node for src in self.sources):
                    current_sources.append(node)
                    
                # Vector C: Cloud Locker Crumb Check
                elif node in self.cloud_locker:
                    print(f"[!] Alert: Found tainted artifact '{node}' in {job_name}. Paint applied.")
                    current_sources.append(node)

                # --- Issue 2 Fixed: The Memory Bridge check! ---
                # Check if this node contains a tainted variable passed from Tier 0
                for tainted_var in self.injected_state.get('workflow', []):
                    if f"${tainted_var}" in node:
                        current_sources.append(node)
                        print(f"[*] Memory Bridge Activated: Paint applied to ${tainted_var} from YAML layer.")

                # Trucks & Detonators
                if any(truck in node for truck in self.trucks):
                    upload_trucks.append(node)
                    
                if any(node.startswith(sink) or sink in node.split() for sink in self.sinks):
                    if not any(safe_cmd in node for safe_cmd in self.ignore):
                        current_sinks.append(node)

        # Issue 6 Fixed: Dynamic Artifact Extraction (No hardcoded names)
        for source in current_sources:
            for truck in upload_trucks:
                if nx.has_path(graph, source, truck):
                    # We extract the last argument of the upload command as the artifact name
                    artifact = truck.split()[-1] if len(truck.split()) > 1 else "unknown-artifact"
                    self.cloud_locker.add(artifact)
                    print(f"[+] Crumb Ledger Updated: '{artifact}' was uploaded by {job_name} and is TAINTED.")

        # Fire the lightning-fast BFS instead of the exponential simple_paths
        self._stateful_bfs(graph, current_sources, current_sinks, job_name)

    def _stateful_bfs(self, graph, current_sources, current_sinks, job_name):
        """Fixed: Agents now explore through sanitizers with a clean (is_tainted = False) state."""
        for source in current_sources:
            if source not in graph:
                continue
                
            # Agent Ledger: (current_node, path_history, is_tainted)
            queue = deque([(source, [source], True)])
            
            while queue:
                current_node, path, is_tainted = queue.popleft()
                
                # Detonator Check: Only fire if the agent is still carrying paint
                if is_tainted and current_node in current_sinks:
                    self.vulnerabilities.append({
                        "job": job_name,
                        "file": Path(self.pipeline_path).name,
                        "source": source,
                        "sink": current_node,
                        "path": path
                    })
                    continue 

                # Explore the pipes
                for neighbor in graph.successors(current_node):
                    # The Soap Check: Wash the paint, but DON'T kill the agent!
                    neighbor_sanitizes = any(soap in neighbor for soap in self.sanitizers)
                    next_taint = False if neighbor_sanitizes else is_tainted
                    
                    # Cycle Prevention
                    if neighbor not in path:
                        queue.append((neighbor, path + [neighbor], next_taint))

# ==========================================
# 3. SINGLE MAIN EXECUTION BLOCK (Issue 5 Fixed)
# ==========================================
if __name__ == "__main__":
    current_dir = Path(__file__).parent
    data_dir = current_dir.parent / "data"
    policy_file = current_dir.parent / "config" / "security_policy.yml"
    
    global_vulnerabilities = []

    print("[*] Booting Standalone Tier 1 Execution (Bypassing Tier 0)...")
    for test_file in data_dir.glob('*.yml'):
        print(f"\n========== SCANNING PIPELINE: {test_file.name} ==========")
        
        # Instantiate the new class instead of calling procedural loops
        analyzer = TaintAnalyzer(
            policy_path=str(policy_file),
            pipeline_path=str(test_file)
        )
        
        vulns = analyzer.run_scan()
        if vulns:
            print(f"[!!!] CRITICAL VULNERABILITIES DETECTED [!!!]")
            for v in vulns:
                formatted_path = " -> \n    ".join(v['path'])
                print(f"    {formatted_path}\n")
            global_vulnerabilities.extend(vulns)

    if global_vulnerabilities:
        generate_sarif_report(global_vulnerabilities, "results.sarif")
        