import subprocess
import tempfile
import os
from pathlib import Path
from typing import List, Dict
from core.storage.database import Database
from core.scanner_ingestion import nmap_parser, nikto_parser  # Add others as needed
from core.normalization.normalizer import normalize_vulnerabilities
from core.ml_engine.model_loader import ModelLoader

SCANNER_COMMANDS = {
    'nmap': {
        'cmd': ['nmap', '-sV', '-sC', '-oX', '{temp_path}', '{target}'],
        'parser': nmap_parser.parse_nmap,
        'file_ext': 'xml'
    },
    'nikto': {
        'cmd': ['nikto', '-h', '{target}', '-o', '{temp_path}'],
        'parser': nikto_parser.parse_nikto,
        'file_ext': 'txt'
    },
    'nuclei': {
        'cmd': ['nuclei', '-u', '{target}', '-o', '{temp_path}', '-silent'],
        'parser': lambda content: parse_nuclei(content),  # Stub - add parser
        'file_ext': 'json'
    }
    # Add Nessus/OpenVAS CLI if available
}

def parse_nuclei(content: str) -> List[Dict]:
    """Stub Nuclei parser - parse JSON output."""
    import json
    lines = content.strip().split('\\n')
    vulns = []
    for line in lines:
        if line:
            vuln = json.loads(line)
            vulns.append({
                'vulnerability_name': vuln.get('template-id', 'Nuclei Finding'),
                'severity': vuln.get('severity', 'medium'),
                'host': vuln.get('host', ''),
                'port': vuln.get('matched-at', '').split(':')[-1] if ':' in vuln.get('matched-at', '') else '',
                'cve_id': vuln.get('cve-id', ''),
                'description': vuln.get('info', {}).get('description', ''),
                'source_tools': ['nuclei']
            })
    return vulns

def run_live_scan(scanner: str, target: str, db: Database, options: Dict = None) -> str:
    """Run live scan, parse, normalize, store."""
    if scanner not in SCANNER_COMMANDS:
        raise ValueError(f"Unsupported scanner: {scanner}")
    
    config = SCANNER_COMMANDS[scanner].copy()
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=f'.{config["file_ext"]}', delete=False)
    temp_path = temp_file.name
    temp_file.close()
    
    cmd = config['cmd'].format(temp_path=temp_path, target=target)
    if options:
        cmd = cmd.split()[:-2] + options.get('extra_args', []) + cmd.split()[-2:]  # Flexible
    
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True) as proc:
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"Scan failed: {stderr}")
        
        with open(temp_path, 'r') as f:
            content = f.read()
        
        parser = config['parser']
        vulns = parser(content)
        
        for v in vulns:
            v['source_tools'] = [scanner]
        
        normalized = normalize_vulnerabilities(vulns)
        ml = ModelLoader()
        for v in normalized:
            try:
                v.exploit_likelihood = ml.predict(v)
            except:
                v.exploit_likelihood = 0.5
        
        for v in normalized:
            db.insert_vulnerability(v)
        
        return f"Success: Found {len(normalized)} vulns from {scanner} on {target}"
    
    finally:
        os.unlink(temp_path)

# Example usage
if __name__ == '__main__':
    db = Database()
    print(run_live_scan('nmap', 'scanme.nmap.org', db))

