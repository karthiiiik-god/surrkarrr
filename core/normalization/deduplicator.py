from typing import List, Dict, Tuple
from ..storage.models import Vulnerability

def deduplicate_vulnerabilities(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Deduplicate vulnerabilities based on host, port, and either CVE ID or vulnerability name.
    Merges duplicates by combining source_tool and taking the highest CVSS score.
    """
    grouped: Dict[Tuple[str, int, str], List[Vulnerability]] = {}

    for vuln in vulns:
        # Key: (host, port, cve_id or vulnerability_name)
        key = (vuln.host, vuln.port, vuln.cve_id if vuln.cve_id else vuln.vulnerability_name)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(vuln)

    deduplicated = []
    for group in grouped.values():
        if len(group) == 1:
            deduplicated.append(group[0])
        else:
            # Merge: take the one with highest cvss_score
            merged = max(group, key=lambda v: v.cvss_score)
            # Combine source_tool (take the first one, or list if multiple)
            merged.source_tool = group[0].source_tool  # Since single tool per vuln now
            # Keep other fields from the max cvss one
            deduplicated.append(merged)

    return deduplicated
