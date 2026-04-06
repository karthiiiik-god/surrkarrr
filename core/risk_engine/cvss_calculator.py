from ..storage.models import Vulnerability

def calculate_cvss_fallback(vuln: Vulnerability) -> float:
    """
    Fallback CVSS calculation if score is not provided or is 0.
    Assigns a default score based on severity level.
    """
    if vuln.cvss_score > 0:
        return vuln.cvss_score
    # Fallback scores
    severity_scores = {
        "Critical": 9.5,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.0
    }
    return severity_scores.get(vuln.severity, 0.0)
