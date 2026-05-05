from __future__ import annotations

from typing import Dict, Tuple

from ..storage.models import Vulnerability


def deduplicate_vulnerabilities(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """
    Deduplicate by host/port/CVE-or-title while preserving the strongest signal.
    """
    grouped: Dict[Tuple[str, int, str], list[Vulnerability]] = {}
    for vuln in vulns:
        key = (vuln.host, vuln.port, vuln.cve_id or vuln.vulnerability_name.lower())
        grouped.setdefault(key, []).append(vuln)

    deduplicated: list[Vulnerability] = []
    for group in grouped.values():
        merged = max(group, key=lambda item: (item.risk_score, item.cvss_score))
        tools = sorted({item.source_tool for item in group if item.source_tool})
        merged.source_tool = ", ".join(tools) if tools else merged.source_tool
        merged.references = merged.references or "Merged parser evidence"
        deduplicated.append(merged)

    return sorted(deduplicated, key=lambda item: (item.risk_score, item.cvss_score), reverse=True)
