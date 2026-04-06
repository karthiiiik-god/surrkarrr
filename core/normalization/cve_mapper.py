from ..storage.models import Vulnerability

def map_cve(vuln: Vulnerability) -> Vulnerability:
    """
    Standardize CVE ID format if present.
    Ensures CVE IDs are in the format CVE-XXXX-XXXX.
    """
    if vuln.cve_id:
        cve = vuln.cve_id.strip().upper()
        if not cve.startswith('CVE-'):
            cve = f"CVE-{cve}"
        vuln.cve_id = cve
    return vuln
