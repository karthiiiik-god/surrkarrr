from __future__ import annotations

from typing import Iterable

from .cve_mapper import map_cve
from .deduplicator import deduplicate_vulnerabilities
from .enrichment import enrich_vulnerability
from .schema import validate_vulnerability
from ..storage.models import Vulnerability


def normalize_vulnerabilities(vulns: Iterable[Vulnerability]) -> list[Vulnerability]:
    """
    Normalize a vulnerability collection into a deduplicated, enriched, validated list.
    """
    normalized: list[Vulnerability] = []
    for vuln in vulns:
        vuln = map_cve(vuln)
        vuln = enrich_vulnerability(vuln)
        if validate_vulnerability(vuln):
            normalized.append(vuln)
    return deduplicate_vulnerabilities(normalized)
