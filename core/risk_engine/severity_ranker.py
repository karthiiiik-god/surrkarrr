from typing import List
from ..storage.models import Vulnerability

def classify_severity(cvss_score: float) -> str:
    """
    Classify severity based on strict CVSS thresholds.
    """
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"

def rank_vulnerabilities(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Rank vulnerabilities deterministically: first by severity, then by CVSS score descending.
    """
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    return sorted(vulns, key=lambda v: (severity_order.get(v.severity, 0), v.cvss_score), reverse=True)
