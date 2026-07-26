import networkx as nx
import re
import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser

# Initialize the exact GitHub grammar
BASH_LANGUAGE = Language(tsbash.language())
parser = Parser(BASH_LANGUAGE)

def build_pipeline_map(script_text: str) -> nx.DiGraph:
    """
    The Enterprise AST Graph Builder.
    Reads Bash scripts via Tree-sitter and builds a Directed Data Flow Graph.
    """
    graph = nx.DiGraph()
    source_bytes = script_text.encode('utf8')
    tree = parser.parse(source_bytes)

    def get_text(node):
        return source_bytes[node.start_byte:node.end_byte].decode('utf8')

    def walk_ast(node):
        # 1. Variable Assignments (The Funnel)
        if node.type == 'variable_assignment':
            name_node = node.child_by_field_name('name')
            value_node = node.child_by_field_name('value')
            
            if name_node and value_node:
                var_name = get_text(name_node)
                graph.add_node(var_name, type='variable_declaration')
                
                # Precise extraction of the actual source
                def get_assignment_source(n):
                    if n.type == 'pipeline':
                        # In a pipe, only the last command outputs to the variable
                        cmds = [c for c in n.children if c.type == 'command']
                        if cmds: return get_text(cmds[-1])
                    elif n.type == 'command':
                        return get_text(n)
                    elif n.type in ['string', 'raw_string', 'word']:
                        return get_text(n)
                    
                    for c in n.children:
                        res = get_assignment_source(c)
                        if res: return res
                    return None

                source_val = get_assignment_source(value_node)
                if source_val:
                    if not graph.has_node(source_val):
                        graph.add_node(source_val, type='literal_or_command')
                    graph.add_edge(source_val, var_name, relation='assignment')

        # 2. Command Executions
        elif node.type == 'command':
            full_cmd = get_text(node)
            if not graph.has_node(full_cmd):
                graph.add_node(full_cmd, type='command')

            if full_cmd.startswith('./'):
                target_file = full_cmd.replace('./', '').strip()
                if not graph.has_node(target_file):
                    graph.add_node(target_file, type='literal_or_file')
                graph.add_edge(target_file, full_cmd, relation='execution')

            def find_inputs(n):
                if n.type in ['simple_expansion', 'expansion']:
                    var_node = get_text(n).replace('{', '').replace('}', '')
                    if not graph.has_node(var_node):
                        graph.add_node(var_node, type='variable_reference')
                    graph.add_edge(var_node, full_cmd, relation='argument_passed')
                
                elif n.type == 'word':
                    word_text = get_text(n)
                    if word_text not in ['cat', 'gh', 'release', 'upload', 'curl', '-s']:
                        if not graph.has_node(word_text):
                            graph.add_node(word_text, type='literal_or_file')
                        graph.add_edge(word_text, full_cmd, relation='argument_passed')

                for c in n.children:
                    find_inputs(c)
            find_inputs(node)

        # 3. Catch Pipelines (e.g., curl | bash)
        elif node.type == 'pipeline':
            commands_in_pipe = [c for c in node.children if c.type == 'command']
            
            for i in range(len(commands_in_pipe) - 1):
                left_cmd = get_text(commands_in_pipe[i])
                right_cmd = get_text(commands_in_pipe[i+1])
                
                if not graph.has_node(left_cmd):
                    graph.add_node(left_cmd, type='command')
                if not graph.has_node(right_cmd):
                    graph.add_node(right_cmd, type='command')
                
                # The Paint Flows: Left -> Right
                graph.add_edge(left_cmd, right_cmd, relation='pipe_flow')
                
                if right_cmd in ['bash', 'sh', 'eval']:
                    graph.nodes[right_cmd]['type'] = 'sink_command'
                    
            for cmd_node in commands_in_pipe:
                walk_ast(cmd_node)

        # 4. Catch GitHub Actions Environment Injections (e.g., echo "VAR=val" >> $GITHUB_ENV)
        elif node.type == 'redirected_statement':
            # This logic mirrors our taint_analyzer redirect, but handles GitHub's weird syntax
            body_node = node.child_by_field_name('body')
            target_file = None
            
            for child in node.children:
                if child.type == 'file_redirect':
                    dest_node = child.child_by_field_name('destination')
                    if dest_node:
                        target_file = get_text(dest_node)
            
            # If the hacker is injecting into GitHub's memory...
            if target_file == '$GITHUB_ENV' and body_node:
                body_text = get_text(body_node)
                
                # They usually use: echo "POISON=malware"
                # We use regex to extract the word 'POISON' and the 'malware' value
                match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)=(.+)', body_text)
                if match:
                    var_name = f"${match.group(1)}"  # Becomes $POISON
                    injected_value = match.group(2).replace('"', '').replace("'", "") # Becomes malware
                    
                    if not graph.has_node(var_name):
                        graph.add_node(var_name, type='variable_declaration')
                    if not graph.has_node(injected_value):
                        graph.add_node(injected_value, type='literal_or_file')
                        
                    # Paint Flows: Malware -> $POISON
                    graph.add_edge(injected_value, var_name, relation='github_env_injection')
        
        # Recurse down all branches of the Tree
        for child in node.children:
            walk_ast(child)

    # Start the X-ray scan at the root of the file
    walk_ast(tree.root_node)
    
    return graph

