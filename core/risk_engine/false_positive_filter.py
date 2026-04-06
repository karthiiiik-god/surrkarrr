from typing import List
from ..storage.models import Vulnerability

def filter_false_positives(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Filter out potential false positives based on simple rules.
    - Ignore vulnerabilities with CVSS < 1.0
    - Ignore on localhost or private IPs if severity Low
    """
    filtered = []
    for vuln in vulns:
        if vuln.cvss_score < 1.0:
            continue
        if vuln.severity == "Low" and (vuln.host.startswith("127.") or vuln.host.startswith("192.168.") or vuln.host.startswith("10.")):
            continue
        filtered.append(vuln)
    return filtered
