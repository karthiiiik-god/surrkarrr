from typing import List
from ..storage.models import Vulnerability

def assess_risk(vuln: Vulnerability) -> float:
    """
    Assess risk score based on rule-based logic.
    Factors: CVSS, exposure, exploit availability, auth required.
    """
    score = vuln.cvss_score
    if vuln.network_exposed:
        score += 1.0
    if vuln.exploit_available:
        score += 1.0
    if not vuln.authentication_required:
        score += 1.0
    return min(score, 10.0)

def rank_vulnerabilities_by_risk(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Rank vulnerabilities by calculated risk score.
    """
    for vuln in vulns:
        vuln.risk_score = assess_risk(vuln)  # Assuming we add risk_score to model, but for now, use in ranking
    return sorted(vulns, key=lambda v: getattr(v, 'risk_score', v.cvss_score), reverse=True)
