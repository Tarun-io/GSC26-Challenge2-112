"""
yaml_parser.py — Titanium Tier 0: 7-Gate YAML Tribunal

Phase 1: Dynamic untrusted sources, cross-component scanning.
Phase 2 fixes:
  Fix 1 — ENV_TO_RUN detects ${{ env.VAR }} syntax (not just $VAR)
  Fix 2 — Cross-component findings use workflow line as 'from' (in component_resolver.py)
  Fix 3 — Bash parameter expansion ${VAR//...} treated as sanitizer
"""

import re
import tree_sitter_yaml as tsyaml
from tree_sitter import Language, Parser, Query, QueryCursor
from pathlib import Path
from typing import List, Dict, Optional
from models import YamlStateLedger
from untrusted_sources import load_untrusted_sources, is_tainted_expression
from component_resolver import scan_all_referenced_components

YAML_LANGUAGE = Language(tsyaml.language())
yaml_parser_engine = Parser(YAML_LANGUAGE)
EXPR_PATTERN = re.compile(r'\$\{\{(.+?)\}\}', re.DOTALL)
# Matches ${{ env.VARNAME }} with any internal whitespace
ENV_EXPR_RE = re.compile(r'\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}')


class YamlTribunal:

    def __init__(
        self,
        file_path: str,
        untrusted_csv: str = None,
        dataset_base: str = None,
        competition_root: str = None
    ):
        self.file_path = file_path
        self.ledger = YamlStateLedger()
        self.component_findings: List[Dict] = []
        self._uses_references: List[Dict] = []

        # Load dynamic untrusted sources
        if untrusted_csv:
            self.untrusted_sources = load_untrusted_sources(untrusted_csv)
        else:
            # Auto-discover untrusted_data.csv relative to this file
            default_csv = Path(__file__).parent.parent / "competition" / "untrusted_data.csv"
            self.untrusted_sources = load_untrusted_sources(str(default_csv))

        # Paths for component resolution
        self.dataset_base = Path(dataset_base) if dataset_base else Path(file_path).parent.parent
        self.competition_root = (
            Path(competition_root) if competition_root
            else Path(file_path).parent.parent.parent
        )

        with open(file_path, 'r') as f:
            self.source_code = f.read().encode('utf8')

        self.tree = yaml_parser_engine.parse(self.source_code)
        self.root_node = self.tree.root_node

    # ──────────────────────────────────────────────────────────
    # MAIN ENTRY POINT
    # ──────────────────────────────────────────────────────────

    def run_inspection(self) -> YamlStateLedger:
        print(f"[*] Tier 0 Checkpoint: Inspecting {Path(self.file_path).name}")

        self._gate_1_context_analyst()
        self._gate_2_iam_analyst()
        self._gate_3_infrastructure_analyst()
        self._gate_4_supply_chain_analyst()
        self._gate_5_input_router()
        self._gate_6_memory_bridge()
        self._scan_env_to_run_flows()   # Phase 2
        self._gate_7_final_arbiter()    # triggers component scanner

        return self.ledger

    # ──────────────────────────────────────────────────────────
    # GATES 1–3 (unchanged)
    # ──────────────────────────────────────────────────────────

    def _gate_1_context_analyst(self):
        """Extracts the 'on:' triggers to establish the baseline threat context."""
        query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key_name
                (#eq? @key_name "on")
                value: (_) @trigger_val
            )
        """)
        captures = QueryCursor(query).captures(self.root_node)

        for node in captures.get('trigger_val', []):
            trigger_text = self.source_code[node.start_byte:node.end_byte].decode('utf8')

            if "pull_request_target" in trigger_text:
                self.ledger.trigger_event = "pull_request_target"
                self.ledger.is_high_risk_context = True
                self.ledger.heuristic_score += 3
            elif "issue_comment" in trigger_text:
                self.ledger.trigger_event = "issue_comment"
                self.ledger.is_high_risk_context = True
                self.ledger.heuristic_score += 3

        if self.ledger.is_high_risk_context:
            print(f"[!] Gate 1: High-risk context established ({self.ledger.trigger_event})")

    def _gate_2_iam_analyst(self):
        """Extracts 'permissions:' and correlates them with the Context Ledger."""
        query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key_name
                (#eq? @key_name "permissions")
                value: (_) @perms_val
            )
        """)
        captures = QueryCursor(query).captures(self.root_node)

        for node in captures.get('perms_val', []):
            perms_text = self.source_code[node.start_byte:node.end_byte].decode('utf8')

            if "read-all" in perms_text:
                self.ledger.privilege_risk = "SAFE"
                print("[+] Gate 2: Explicit read-all token. Privilege threat neutralized.")
            elif "write-all" in perms_text:
                self.ledger.privilege_risk = "CRITICAL"
                self.ledger.critical_violations.append("God-mode token (write-all) granted.")
                self.ledger.heuristic_score += 4
                print("[!!!] Gate 2: God-mode permissions detected.")
            else:
                if self.ledger.is_high_risk_context and "write" in perms_text:
                    self.ledger.privilege_risk = "ELEVATED"
                    self.ledger.heuristic_score += 2
                    print("[-] Gate 2: Elevated token permissions in high-risk context.")

    def _gate_3_infrastructure_analyst(self):
        """Extracts 'runs-on:' and evaluates runner trust."""
        query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key_name
                (#eq? @key_name "runs-on")
                value: (_) @runner_val
            )
        """)
        captures = QueryCursor(query).captures(self.root_node)

        for node in captures.get('runner_val', []):
            runner_text = self.source_code[node.start_byte:node.end_byte].decode('utf8')

            if "${{" in runner_text:
                self.ledger.runner_trust = "UNKNOWN"
                self.ledger.heuristic_score += 1
                print("[-] Gate 3: Dynamic matrix runner. Trust: UNKNOWN.")
            elif "self-hosted" in runner_text:
                self.ledger.runner_trust = "DIRTY"
                self.ledger.heuristic_score += 3
                print("[!!!] Gate 3: Persistent self-hosted runner detected.")

    # ──────────────────────────────────────────────────────────
    # GATE 4: Supply Chain + Component Collector
    # ──────────────────────────────────────────────────────────

    def _gate_4_supply_chain_analyst(self):
        """
        Checks SHA pinning on uses: references AND collects them with
        their enriched input_taint_map (including workflow line numbers)
        for the cross-component scanner in Gate 7.
        """
        uses_query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key
                (#eq? @key "uses")
                value: (flow_node) @uses_val
            )
        """)
        uses_captures = QueryCursor(uses_query).captures(self.root_node)

        workflow_rel_path = self._workflow_rel_path()

        for uses_node in uses_captures.get('uses_val', []):
            action_text = self.source_code[
                uses_node.start_byte:uses_node.end_byte
            ].decode('utf8').strip()

            # ── SHA pinning check (original) ──────────────────────
            if "@" in action_text:
                vendor, tag = action_text.split("@", 1)
                if len(tag) != 40:
                    self.ledger.supply_chain_risk = "ELEVATED"
                    self.ledger.heuristic_score += 1
                    print(f"[-] Gate 4: Mutable tag in '{vendor}'.")

            # ── Find sibling with: block ───────────────────────────
            with_val_node = self._find_sibling_with_node(uses_node)
            input_taint_map = {}
            if with_val_node:
                input_taint_map = self._build_enriched_taint_map(
                    with_val_node, workflow_rel_path
                )

            self._uses_references.append({
                "uses": action_text,
                "input_taint_map": input_taint_map
            })

        print(f"[*] Gate 4: {len(self._uses_references)} component reference(s) collected.")

    def _find_sibling_with_node(self, uses_val_node):
        """
        Given the value node of a uses: pair, find the value node of the
        sibling with: pair in the same step mapping.
        """
        # uses_val_node → parent = uses block_mapping_pair
        # → parent = block_mapping (the step)
        uses_pair = uses_val_node.parent
        if not uses_pair:
            return None
        step_mapping = uses_pair.parent
        if not step_mapping:
            return None

        for child in step_mapping.children:
            if child.type != 'block_mapping_pair':
                continue
            key_node = child.child_by_field_name('key')
            if not key_node:
                continue
            key_text = self.source_code[
                key_node.start_byte:key_node.end_byte
            ].decode('utf8').strip()
            if key_text == 'with':
                return child.child_by_field_name('value')
        return None

    def _build_enriched_taint_map(self, with_val_node, workflow_rel_path: str) -> Dict:
        """
        Build input_taint_map from a with: block node.
        Stores workflow file + line number so Fix 2 can set the correct 'from' field.

        Returns:
          {
            "inputs.commit_message": {
              "source": "github.event.pull_request.title",
              "workflow_file": "train/workflows/xxx.yml",
              "workflow_line": 54
            }
          }
        """
        taint_map = {}
        if not with_val_node:
            return taint_map

        sub_query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key
                value: (_) @val
            )
        """)
        sub_captures = QueryCursor(sub_query).captures(with_val_node)

        keys = sub_captures.get('key', [])
        vals = sub_captures.get('val', [])

        for key_node, val_node in zip(keys, vals):
            val_text = self.source_code[val_node.start_byte:val_node.end_byte].decode('utf8')
            if '${{' not in val_text:
                continue

            for expr in EXPR_PATTERN.findall(val_text):
                tainted, matched_source = is_tainted_expression(
                    expr.strip(), self.untrusted_sources
                )
                if tainted:
                    input_name = self.source_code[
                        key_node.start_byte:key_node.end_byte
                    ].decode('utf8').strip()
                    line_num = key_node.start_point[0] + 1
                    taint_map[f"inputs.{input_name}"] = {
                        "source": matched_source,
                        "workflow_file": workflow_rel_path,
                        "workflow_line": line_num
                    }
                    break

        return taint_map

    # ──────────────────────────────────────────────────────────
    # GATE 5: Direct injection in workflow run: blocks
    # ──────────────────────────────────────────────────────────

    def _gate_5_input_router(self):
        """
        Scans run: blocks in the workflow file for DIRECT expression injection.
        Only scans run: (not with:) — with: inputs are handled by Gate 4 + component scanner.
        Uses dynamic 27-source list. Score inflation fixed: +5 at most once per workflow.
        Records findings with exact line numbers.
        """
        query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key_name
                (#eq? @key_name "run")
                value: (_) @val
            )
        """)
        captures = QueryCursor(query).captures(self.root_node)

        workflow_rel_path = self._workflow_rel_path()
        injection_scored = False

        for node in captures.get('val', []):
            text = self.source_code[node.start_byte:node.end_byte].decode('utf8')
            if '${{' not in text:
                continue

            for expr in EXPR_PATTERN.findall(text):
                tainted, matched_source = is_tainted_expression(
                    expr.strip(), self.untrusted_sources
                )
                if not tainted:
                    continue

                # Score once
                if not injection_scored:
                    self.ledger.execution_risk = "CRITICAL"
                    self.ledger.heuristic_score += 5
                    injection_scored = True
                    print("[!!!] Gate 5: Untrusted Context Injection in workflow run: block.")

                # Find exact line of expression in run block
                expr_line = self._expr_line_in_node(text, expr.strip(), node)

                self.component_findings.append({
                    "from": f"{workflow_rel_path}:{expr_line}",
                    "to":   f"{workflow_rel_path}:{expr_line}",
                    "explanation": (
                        f"Untrusted `{matched_source}` is used directly in a "
                        f"`run:` shell command in the workflow (direct injection)."
                    ),
                    "_source": matched_source,
                    "_file": workflow_rel_path
                })
                break  # one finding per run block

    # ──────────────────────────────────────────────────────────
    # GATE 6: Memory Bridge (unchanged)
    # ──────────────────────────────────────────────────────────

    def _gate_6_memory_bridge(self):
        """Maps env: block scopes for Tier 1 handoff."""
        query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key_name
                (#eq? @key_name "env")
                value: (block_node) @env_block
            )
        """)
        captures = QueryCursor(query).captures(self.root_node)

        for env_node in captures.get('env_block', []):
            sub_query = Query(YAML_LANGUAGE, """
                (block_mapping_pair
                    key: (flow_node) @var_name
                    value: (_) @var_val
                )
            """)
            sub_captures = QueryCursor(sub_query).captures(env_node)

            var_names = sub_captures.get('var_name', [])
            var_vals  = sub_captures.get('var_val', [])

            for name_node, val_node in zip(var_names, var_vals):
                val_text = self.source_code[val_node.start_byte:val_node.end_byte].decode('utf8')

                if "${{" not in val_text:
                    continue

                var_name = self.source_code[
                    name_node.start_byte:name_node.end_byte
                ].decode('utf8')

                scope, job_name = "workflow", "unknown_job"
                current = env_node
                while current:
                    if current.type == "block_mapping_pair":
                        key_node = current.child_by_field_name('key')
                        if key_node:
                            key_text = self.source_code[
                                key_node.start_byte:key_node.end_byte
                            ].decode('utf8')
                            if key_text == "steps":
                                scope = "step"
                            elif (current.parent and current.parent.parent
                                  and current.parent.parent.type == "block_mapping_pair"):
                                gp = current.parent.parent.child_by_field_name('key')
                                if gp:
                                    gp_key = self.source_code[
                                        gp.start_byte:gp.end_byte
                                    ].decode('utf8')
                                    if gp_key == "jobs":
                                        job_name = key_text
                                        if scope == "workflow":
                                            scope = "job"
                                        break
                    current = current.parent

                print(f"[-] Gate 6: Tainted bridge -> ${var_name} ({scope} scope in {job_name})")

                if scope == "workflow":
                    self.ledger.tainted_env_vars['workflow'].append(var_name)
                elif scope == "job":
                    self.ledger.tainted_env_vars['jobs'].setdefault(job_name, []).append(var_name)
                elif scope == "step":
                    self.ledger.tainted_env_vars['steps'].setdefault(job_name, {0: []}).setdefault(0, []).append(var_name)

    # ──────────────────────────────────────────────────────────
    # PHASE 2: ENV_TO_RUN SCANNER (all 3 fixes)
    # ──────────────────────────────────────────────────────────

    def _scan_env_to_run_flows(self):
        """
        Detects ENV_TO_RUN pattern: env var assigned from tainted source,
        used in a run: block in the SAME workflow file.

        Fix 1: also detects ${{ env.VAR }} syntax (not just $VAR)
        Fix 3: skips lines using bash parameter expansion ${VAR//...}
        Fix 4: reports only the FIRST run block per tainted variable
        """
        workflow_rel_path = self._workflow_rel_path()

        # ── Step 1: Collect tainted env var assignments ────────────────────
        env_query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key
                (#eq? @key "env")
                value: (block_node) @env_block
            )
        """)
        env_captures = QueryCursor(env_query).captures(self.root_node)

        # (var_name, taint_source, assignment_line)
        tainted_vars = []

        for env_node in env_captures.get('env_block', []):
            sub_query = Query(YAML_LANGUAGE, """
                (block_mapping_pair
                    key: (flow_node) @var_name
                    value: (_) @var_val
                )
            """)
            sub_captures = QueryCursor(sub_query).captures(env_node)

            for name_node, val_node in zip(
                sub_captures.get('var_name', []),
                sub_captures.get('var_val', [])
            ):
                val_text = self.source_code[val_node.start_byte:val_node.end_byte].decode('utf8')
                if '${{' not in val_text:
                    continue

                for expr in EXPR_PATTERN.findall(val_text):
                    tainted, matched_source = is_tainted_expression(
                        expr.strip(), self.untrusted_sources
                    )
                    if tainted:
                        var_name = self.source_code[
                            name_node.start_byte:name_node.end_byte
                        ].decode('utf8').strip()
                        assignment_line = name_node.start_point[0] + 1
                        tainted_vars.append((var_name, matched_source, assignment_line))
                        break

        if not tainted_vars:
            return

        # ── Step 2: Scan run blocks for tainted variable references ────────
        run_query = Query(YAML_LANGUAGE, """
            (block_mapping_pair
                key: (flow_node) @key
                (#eq? @key "run")
                value: (_) @run_val
            )
        """)
        run_captures = QueryCursor(run_query).captures(self.root_node)

        # Fix 4: track which vars already reported (first sink only)
        reported_vars = set()

        # Collect all run nodes sorted by line (to process in order)
        run_nodes = sorted(
            run_captures.get('run_val', []),
            key=lambda n: n.start_point[0]
        )

        for run_node in run_nodes:
            run_text = self.source_code[
                run_node.start_byte:run_node.end_byte
            ].decode('utf8')
            run_start_line = run_node.start_point[0] + 1

            for var_name, taint_source, assignment_line in tainted_vars:
                if var_name in reported_vars:
                    continue

                # Fix 3: patterns that indicate SANITIZED bash expansion — skip those lines
                BASH_SANITIZED_PATTERNS = [
                    f'${{{var_name}//',   # ${VAR//pattern/replacement}
                    f'${{{var_name}#',    # ${VAR#prefix}
                    f'${{{var_name}%',    # ${VAR%suffix}
                ]

                # Fix 1: regex to match ${{ env.VAR_NAME }} with any spacing
                env_expr_re = re.compile(
                    r'\$\{\{\s*env\.' + re.escape(var_name) + r'\s*\}\}'
                )

                found_line = None

                for line_offset, line in enumerate(run_text.splitlines()):
                    # Fix 3: skip sanitized forms
                    if any(pat in line for pat in BASH_SANITIZED_PATTERNS):
                        continue

                    # Bash variable forms: $VAR or ${VAR}
                    bash_hit = (
                        f'${var_name}' in line
                        and not f'${var_name}_' in line  # avoid partial matches
                    ) or f'${{{var_name}}}' in line

                    # Fix 1: ${{ env.VAR }} form
                    expr_hit = bool(env_expr_re.search(line))

                    if bash_hit or expr_hit:
                        found_line = run_start_line + line_offset
                        break

                if found_line:
                    self.component_findings.append({
                        "from": f"{workflow_rel_path}:{assignment_line}",
                        "to":   f"{workflow_rel_path}:{found_line}",
                        "explanation": (
                            f"Untrusted `{taint_source}` flows through env var "
                            f"`${var_name}` into a `run:` shell command (multi-hop)."
                        ),
                        "_source": taint_source,
                        "_file": workflow_rel_path,
                        "_pattern": "ENV_TO_RUN"
                    })
                    reported_vars.add(var_name)  # Fix 4: first sink only
                    print(
                        f"[!!!] ENV_TO_RUN: ${var_name} "
                        f"line {assignment_line} → line {found_line}"
                    )

    # ──────────────────────────────────────────────────────────
    # GATE 7: Final Arbiter + Component Scanner trigger
    # ──────────────────────────────────────────────────────────

    def _gate_7_final_arbiter(self):
        """Scores ledger AND triggers cross-component scanner."""
        THRESHOLD = 7

        # Trigger component scanner on all collected uses: references
        if self._uses_references:
            print(f"\n[*] Gate 7: Scanning {len(self._uses_references)} referenced component(s)...")
            component_hits = scan_all_referenced_components(
                uses_references=self._uses_references,
                dataset_base=self.dataset_base,
                competition_root=self.competition_root,
                untrusted_sources=self.untrusted_sources
            )
            self.component_findings.extend(component_hits)

        total = len(self.component_findings)
        if total > 0:
            print(f"[!!!] Gate 7: {total} total injection finding(s) across all components.")

        print(f"\n[*] Gate 7: Heuristic Score -> {self.ledger.heuristic_score} / {THRESHOLD}")

        if (self.ledger.heuristic_score >= THRESHOLD
                or "CRITICAL" in [self.ledger.privilege_risk, self.ledger.execution_risk]):
            print("[!!!] FACTORY HALT: YAML State is critically vulnerable.")
        else:
            print("[+] FACTORY GREEN: Handing ledger to Tier 1.")

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────

    def _workflow_rel_path(self) -> str:
        try:
            return str(Path(self.file_path).relative_to(self.competition_root))
        except ValueError:
            return self.file_path

    def _expr_line_in_node(self, node_text: str, expression: str, node) -> int:
        """Find exact 1-indexed line where an expression appears inside a node."""
        idx = node_text.find(expression)
        if idx < 0:
            idx = node_text.find(expression[:20]) if len(expression) >= 20 else -1
        if idx >= 0:
            lines_before = node_text[:idx].count('\n')
            return node.start_point[0] + lines_before + 1
        return node.start_point[0] + 1


if __name__ == "__main__":
    current_dir = Path(__file__).parent
    target_file = current_dir.parent / "data" / "vulnerable_pipeline.yml"

    tribunal = YamlTribunal(str(target_file))
    final_ledger = tribunal.run_inspection()
    print(f"[+] Findings: {len(tribunal.component_findings)}")
    for f in tribunal.component_findings:
        print(f"  {f['from']} -> {f['to']}")