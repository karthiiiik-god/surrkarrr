from typing import List
from .schema import validate_vulnerability
from .cve_mapper import map_cve
from .deduplicator import deduplicate_vulnerabilities
from .enrichment import enrich_vulnerability
from ..storage.models import Vulnerability

def normalize_vulnerabilities(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Normalize a list of vulnerabilities: validate, map CVE, enrich, deduplicate.
    """
    normalized = []
    for vuln in vulns:
        if validate_vulnerability(vuln):
            # Map CVE
            vuln = map_cve(vuln)
            # Enrich
            vuln = enrich_vulnerability(vuln)
            normalized.append(vuln)
    # Deduplicate
    return deduplicate_vulnerabilities(normalized)
