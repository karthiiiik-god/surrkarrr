from ..storage.models import Vulnerability

def build_features(vuln: Vulnerability) -> list:
    """
    Build feature vector for ML model.
    Features: CVSS score, network_exposed (0/1), authentication_required (0/1),
    service category (encoded), exploit_available (0/1), severity (encoded)
    """
    service_encoding = {'http': 0, 'ssh': 1, 'ftp': 2, 'smtp': 3, 'other': 4}.get(vuln.service.lower(), 4)
    severity_encoding = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}.get(vuln.severity, 0)
    return [
        vuln.cvss_score,
        int(vuln.network_exposed),
        int(vuln.authentication_required),
        service_encoding,
        int(vuln.exploit_available),
        severity_encoding
    ]
