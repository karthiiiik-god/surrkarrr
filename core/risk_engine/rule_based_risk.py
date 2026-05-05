from typing import List
from ..storage.models import Vulnerability

def assess_risk(vuln: Vulnerability) -> tuple[float, str]:
    """
    Custom risk score per spec: CVSS + Exposure + Exploitability.
    Exposure = +1 if port public (80,443,22,3389)
    Exploitability = +1 if CVSS > 8
    Labels: Low(0-4), Med(4-7), High(7-9), Crit(9+)
    """
    exposure = 1.0 if vuln.port in [80, 443, 22, 3389] else 0.0
    exploitability = 1.0 if vuln.cvss_score > 8 else 0.0
    score = vuln.cvss_score + exposure + exploitability
    vuln.risk_score = min(score, 10.0)
    
    if vuln.risk_score >= 9:
        risk_label = "Critical"
    elif vuln.risk_score >= 7:
        risk_label = "High"
    elif vuln.risk_score >= 4:
        risk_label = "Medium"
    else:
        risk_label = "Low"
    
    vuln.severity = risk_label
    return vuln.risk_score, risk_label

def rank_vulnerabilities_by_risk(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Rank vulnerabilities by calculated risk score.
    """
    for vuln in vulns:
        assess_risk(vuln)
    return sorted(vulns, key=lambda v: v.risk_score, reverse=True)
