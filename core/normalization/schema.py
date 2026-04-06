from ..storage.models import Vulnerability

# Unified schema for vulnerabilities
UNIFIED_SCHEMA = {
    "vuln_id": str,
    "host": str,
    "port": int,
    "service": str,
    "vulnerability_name": str,
    "description": str,
    "cve_id": str | None,
    "cvss_score": float,
    "severity": str,
    "network_exposed": bool,
    "authentication_required": bool,
    "exploit_available": bool,
    "source_tool": str,
    "timestamp": str
}

def validate_vulnerability(vuln: Vulnerability) -> bool:
    """Validate if a vulnerability matches the unified schema."""
    return (
        isinstance(vuln.vuln_id, str) and
        isinstance(vuln.host, str) and
        isinstance(vuln.port, int) and
        isinstance(vuln.service, str) and
        isinstance(vuln.vulnerability_name, str) and
        isinstance(vuln.description, str) and
        (isinstance(vuln.cve_id, str) or vuln.cve_id is None) and
        isinstance(vuln.cvss_score, float) and
        vuln.severity in ["Critical", "High", "Medium", "Low"] and
        isinstance(vuln.network_exposed, bool) and
        isinstance(vuln.authentication_required, bool) and
        isinstance(vuln.exploit_available, bool) and
        isinstance(vuln.source_tool, str) and
        isinstance(vuln.timestamp, str)
    )
