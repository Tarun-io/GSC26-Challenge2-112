cat > README.md << 'EOF'
# Titanium AST Vulnerability Scanner
### IEEE Computer Society 2026 Global Student Challenge — Challenge 2

## Overview
Titanium is a deterministic, two-tier static analysis engine for detecting and patching code injection vulnerabilities in GitHub Actions CI/CD workflows.

Instead of regex pattern matching, Titanium simulates the **physics of data flow** — tracking untrusted data from the moment it enters the pipeline until it reaches an execution sink.

## Architecture

### Tier 0: 7-Gate YAML Tribunal
A context-aware heuristic engine that analyzes workflow structure before any code execution analysis:

- **Gate 1** — Context Analyst: detects dangerous triggers (`pull_request_target`, `issue_comment`)
- **Gate 2** — IAM Analyst: evaluates token permissions, correlates with trigger risk
- **Gate 3** — Infrastructure Analyst: flags self-hosted runners as persistent threat multipliers
- **Gate 4** — Supply Chain Analyst: detects mutable action references vs SHA-pinned
- **Gate 5** — Input Router: detects direct `${{ untrusted }}` expression injection in run blocks
- **Gate 6** — Memory Bridge: tracks tainted env vars across the YAML→Bash boundary
- **Gate 7** — Final Arbiter: weighted heuristic scoring + triggers cross-component scanner

### Tier 1: Bash Taint Engine
Compiler-grade AST analysis using Tree-sitter:
- Builds a directed data flow graph across all bash scripts
- Tracks taint with stateful BFS — O(V+E) vs exponential all-paths
- Cross-VM Crumb Ledger: maintains taint across isolated job boundaries via artifacts

### Cross-Component Scanner
- Resolves `uses:` references to vendored action/reusable-workflow files
- Scans action files for direct expression injection
- Tracks taint across workflow→action boundaries via enriched input taint maps

## Setup

```bash
git clone <your-repo-url>
cd GSC26-Challenge2-112
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Requirements
tree-sitter>=0.25.0
tree-sitter-bash>=0.25.0
tree-sitter-yaml>=0.7.0
networkx
ruamel.yaml

## Running Detection

```bash
cd src
python3 validate.py --dataset-root "/path/to/dataset"
```

The dataset root must contain:
train.csv
untrusted_data.csv
train/
workflows/
actions/
reusable_workflows/

## Output Format
Generates `test.csv` with columns:
- `sample_id` — workflow sample identifier
- `vulnerabilities` — JSON list of `{"from": "file:line", "to": "file:line", "explanation": "..."}`
- `patches` — JSON list of patch references

## LLM Usage
Patch generation uses the Anthropic Claude API via OpenRouter.
Model: `anthropic/claude-sonnet-4-5`
All API calls use the team-issued OpenRouter key.

## Project Structure
src/
yaml_parser.py # Tier 0: 7-gate YAML tribunal
taint_analyzer.py # Tier 1: Bash taint engine
graph_builder.py # AST-based data flow graph builder
component_resolver.py # Cross-component scanner
untrusted_sources.py # Loads untrusted_data.csv
validate.py # Evaluation against training ground truth
reporter.py # SARIF + competition CSV output
parser.py # YAML run block extractor
models.py # Shared data models
config/
security_policy.yml # Declarative security rules (sources, sinks, sanitizers)

