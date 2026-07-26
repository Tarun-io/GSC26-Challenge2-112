import json

def generate_sarif_report(all_vulnerabilities: list, output_file="results.sarif"):
    results = []
    
    for vuln in all_vulnerabilities:
        job = vuln['job']
        source = vuln['source']
        sink = vuln['sink']
        target_file = vuln.get('file', 'unknown_pipeline.yml') # <-- Dynamic file name
        path_str = " -> ".join(vuln['path'])
        
        results.append({
            "ruleId": "VAP-001",
            "level": "error",
            "message": {
                "text": f"Critical Code Injection in {job}: Untrusted data from '{source}' reached execution detonator '{sink}'."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"data/{target_file}" # <-- Dynamic URI
                        }
                    }
                }
            ],
            "properties": {
                "mathematical_data_flow": path_str
            }
        })

    sarif_log = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Titanium AST Vulnerability Scanner",
                        "version": "1.0.0",
                        "rules": [
                            {
                                "id": "VAP-001",
                                "shortDescription": {"text": "Stateful CI/CD Code Injection"}
                            }
                        ]
                    }
                },
                "results": results
            }
        ]
    }

    with open(output_file, 'w') as f:
        json.dump(sarif_log, f, indent=4)
        
    print(f"\n[+] Enterprise SARIF report successfully generated: {output_file}")
    