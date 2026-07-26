import sys
from pathlib import Path
from ruamel.yaml import YAML

def extract_run_blocks(filepath: str) -> list[str]:
    """
    Extracts raw bash scripts from the 'run' steps in a GitHub Actions YAML.
    Now upgraded to scan dynamically across all jobs.
    """
    target_file = Path(filepath)
    
    if not target_file.exists():
        print(f"[!] Error: Target file not found at {filepath}", file=sys.stderr)
        sys.exit(1)

    # 'rt' (round-trip) mode preserves comments and spacing
    yaml = YAML(typ='rt') 
    
    with target_file.open('r') as f:
        try:
            # THIS is the payload that was missing!
            payload = yaml.load(f)
        except Exception as e:
            print(f"[!] YAML ingestion failed: {e}", file=sys.stderr)
            return []

    run_scripts = []
    
    # The upgraded semi-dynamic spider
    try:
        jobs = payload.get('jobs', {})
        for job_name, job_data in jobs.items():
            # Some YAML jobs might not have steps 
            steps = job_data.get('steps', []) if isinstance(job_data, dict) else []
            
            for step in steps:
                if 'run' in step:
                    run_scripts.append(step['run'])
    except AttributeError:
        print("[-] Warning: Malformed or unexpected YAML structure. Skipping.", file=sys.stderr)
        
    return run_scripts

