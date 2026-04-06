from typing import List, Dict
from ..storage.models import Vulnerability

def generate_attack_paths(vulns: List[Vulnerability]) -> List[Dict]:
    """
    Generate rule-based attack paths from vulnerabilities.
    Returns list of paths, each with 'description' and 'steps'.
    """
    paths = []
    host_vulns = {}
    for vuln in vulns:
        if vuln.host not in host_vulns:
            host_vulns[vuln.host] = []
        host_vulns[vuln.host].append(vuln)

    for host, vulns_list in host_vulns.items():
        # Single vulnerability paths
        for vuln in vulns_list:
            if vuln.network_exposed and not vuln.authentication_required and vuln.exploit_available:
                path = {
                    "description": f"Direct exploitation of {vuln.vulnerability_name} on {host}:{vuln.port}",
                    "steps": [f"Exploit {vuln.vulnerability_name} ({vuln.cve_id or 'No CVE'})"]
                }
                paths.append(path)

        # Chained paths: e.g., exposed service -> privilege escalation
        ssh_vulns = [v for v in vulns_list if v.port == 22 and v.network_exposed]
        if ssh_vulns:
            weak_ssh = any(v for v in ssh_vulns if not v.authentication_required)
            if weak_ssh:
                path = {
                    "description": f"SSH compromise leading to privilege escalation on {host}",
                    "steps": [
                        "Exploit weak SSH configuration",
                        "Gain initial access",
                        "Privilege escalation to system compromise"
                    ]
                }
                paths.append(path)

        # Add more rules as needed, e.g., web server -> SQL injection -> data breach

    # Sort paths by severity (assume higher CVSS first)
    paths.sort(key=lambda p: max(v.cvss_score for v in vulns if v.host in p["description"]), reverse=True)
    return paths
