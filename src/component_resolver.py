"""
component_resolver.py

Cross-component scanner for GitHub Actions workflows.
Resolves uses: references and scans action/reusable-workflow files for injection.

Fix 2 is implemented here: when injection is found via input_taint_map,
the 'from' field points to the WORKFLOW line where the tainted input was
passed, not the action file line.
"""

import re
from pathlib import Path
from typing import Optional, Dict, List

import tree_sitter_yaml as tsyaml
from tree_sitter import Language, Parser, Query, QueryCursor

YAML_LANGUAGE = Language(tsyaml.language())
yaml_parser_engine = Parser(YAML_LANGUAGE)
EXPR_PATTERN = re.compile(r'\$\{\{(.+?)\}\}', re.DOTALL)


# ──────────────────────────────────────────────────────────────
# PART 1: PATH RESOLVER
# ──────────────────────────────────────────────────────────────

def resolve_component_path(uses_value: str, dataset_base: Path) -> Optional[Path]:
    """
    Resolve a uses: string to its vendored file path.

    Convention:
      uses: owner/repo@sha
        -> dataset_base/actions/owner/repo/sha[:12]/action.yml

      uses: owner/repo/subpath@sha
        -> dataset_base/actions/owner/repo/sha[:12]/subpath/action.yml

      uses: owner/repo/.github/workflows/file.yml@sha
        -> dataset_base/reusable_workflows/owner/repo/sha[:12]/.github/workflows/file.yml
    """
    uses_value = uses_value.strip()
    if uses_value.startswith('./') or uses_value.startswith('../'):
        return None
    if uses_value.startswith('docker://'):
        return None
    if '@' not in uses_value:
        return None

    ref, sha = uses_value.rsplit('@', 1)
    sha_short = sha[:12]

    # Reusable workflow
    if '.github/workflows/' in ref:
        parts = ref.split('/')
        if len(parts) < 2:
            return None
        owner = parts[0]
        repo = parts[1]
        inner_path = '/'.join(parts[2:])
        candidate = dataset_base / 'reusable_workflows' / owner / repo / sha_short / inner_path
        return candidate if candidate.exists() else None

    # Regular action
    parts = ref.split('/')
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1]
    subpath = '/'.join(parts[2:]) if len(parts) > 2 else ''

    search_base = dataset_base / 'actions' / owner / repo / sha_short
    if subpath:
        search_base = search_base / subpath

    for ext in ['action.yml', 'action.yaml']:
        candidate = search_base / ext
        if candidate.exists():
            return candidate

    return None


def get_relative_path(absolute_path: Path, competition_root: Path) -> str:
    try:
        return str(absolute_path.relative_to(competition_root))
    except ValueError:
        return str(absolute_path)


# ──────────────────────────────────────────────────────────────
# PART 2: COMPONENT SCANNER
# ──────────────────────────────────────────────────────────────

def scan_component_file(
    file_path: Path,
    relative_path: str,
    untrusted_sources: tuple,
    input_taint_map: Dict = None
) -> List[Dict]:
    """
    Scan an action.yml or reusable workflow for expression injection.

    input_taint_map format (Fix 2 — enriched with workflow origin):
      {
        "inputs.commit_message": {
          "source": "github.event.pull_request.title",
          "workflow_file": "train/workflows/xxx.yml",
          "workflow_line": 54
        }
      }
    Also accepts legacy string format for backwards compatibility:
      {"inputs.commit_message": "github.event.pull_request.title"}

    Returns findings in competition format:
      [{"from": "file:line", "to": "file:line", "explanation": "..."}]
    """
    if input_taint_map is None:
        input_taint_map = {}

    findings = []

    try:
        source_text = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"[!] Could not read {file_path}: {e}")
        return findings

    source_bytes = source_text.encode('utf8')

    try:
        tree = yaml_parser_engine.parse(source_bytes)
    except Exception as e:
        print(f"[!] Parse failed on {file_path.name}: {e}")
        return findings

    root = tree.root_node

    try:
        run_query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key
                (#eq? @key "run")
                value: (_) @run_val
            )
        """)
        run_captures = QueryCursor(run_query).captures(root)
    except Exception as e:
        print(f"[!] Query failed on {file_path.name}: {e}")
        return findings

    for run_node in run_captures.get('run_val', []):
        run_text = source_bytes[run_node.start_byte:run_node.end_byte].decode('utf8')
        run_line = run_node.start_point[0] + 1

        if '${{' not in run_text:
            continue

        expressions = EXPR_PATTERN.findall(run_text)

        for expr in expressions:
            expr_stripped = expr.strip()
            matched_source = None
            from_file = relative_path
            from_line = run_line
            to_file = relative_path
            to_line = run_line

            # Check 1: Direct untrusted source
            for source in untrusted_sources:
                if source in expr_stripped:
                    matched_source = source
                    # from and to are both in this file at this line
                    expr_line = _find_expr_line(run_text, expr_stripped, run_node.start_point[0])
                    from_file = relative_path
                    from_line = expr_line
                    to_file = relative_path
                    to_line = expr_line
                    break

            # Check 2: Tainted input reference — FIX 2
            if not matched_source:
                for input_ref, taint_info in input_taint_map.items():
                    if input_ref in expr_stripped:
                        expr_line = _find_expr_line(run_text, expr_stripped, run_node.start_point[0])

                        if isinstance(taint_info, dict):
                            # Enriched format: from = workflow origin
                            matched_source = taint_info.get('source', '')
                            from_file = taint_info.get('workflow_file', relative_path)
                            from_line = taint_info.get('workflow_line', expr_line)
                        else:
                            # Legacy string format
                            matched_source = taint_info
                            from_file = relative_path
                            from_line = expr_line

                        to_file = relative_path
                        to_line = expr_line
                        break

            if matched_source:
                explanation = (
                    f"Untrusted `{matched_source}` "
                    f"{'flows through `' + expr_stripped + '` into' if from_file != to_file else 'is used directly in'}"
                    f" a `run:` shell command in `{Path(to_file).name}`."
                )

                findings.append({
                    "from": f"{from_file}:{from_line}",
                    "to":   f"{to_file}:{to_line}",
                    "explanation": explanation,
                    "_source": matched_source,
                    "_file": to_file
                })
                break  # first exploitable sink per run block

    return findings


def _find_expr_line(run_text: str, expression: str, block_start_row: int) -> int:
    """Find the 1-indexed line number where an expression appears in a run block."""
    # Search for common forms of the expression
    targets = [
        expression,
        expression.strip(),
        expression[:30],
    ]
    for target in targets:
        idx = run_text.find(target)
        if idx >= 0:
            lines_before = run_text[:idx].count('\n')
            return block_start_row + lines_before + 1
    return block_start_row + 1


# ──────────────────────────────────────────────────────────────
# PART 3: ORCHESTRATOR
# ──────────────────────────────────────────────────────────────

def scan_all_referenced_components(
    uses_references: List[Dict],
    dataset_base: Path,
    competition_root: Path,
    untrusted_sources: tuple
) -> List[Dict]:
    """
    Called by Gate 7. Scans all uses: referenced files.

    Each entry in uses_references:
      {
        "uses": "owner/repo@sha",
        "input_taint_map": { ... }   # enriched format with workflow_file/workflow_line
      }
    """
    all_findings = []
    scanned = set()

    for ref_info in uses_references:
        uses_value = ref_info.get('uses', '')
        input_taint_map = ref_info.get('input_taint_map', {})

        file_path = resolve_component_path(uses_value, dataset_base)
        if file_path is None:
            continue
        if str(file_path) in scanned:
            continue
        scanned.add(str(file_path))

        relative_path = get_relative_path(file_path, competition_root)
        print(f"  [Resolver] Scanning: {relative_path}")

        if input_taint_map:
            print(f"  [Bridge] Input taint: {list(input_taint_map.keys())}")

        findings = scan_component_file(
            file_path=file_path,
            relative_path=relative_path,
            untrusted_sources=untrusted_sources,
            input_taint_map=input_taint_map
        )

        if findings:
            print(f"  [!!!] {len(findings)} finding(s) in {file_path.name}")

        all_findings.extend(findings)

    return all_findings