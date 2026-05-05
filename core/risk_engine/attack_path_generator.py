from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..storage.models import Vulnerability


def summarize_risk_path(vuln: Vulnerability) -> str:
    segments = []
    if vuln.network_exposed:
        segments.append("Internet-exposed service")
    if vuln.cvss_score >= 9.0:
        segments.append("critical technical weakness")
    elif vuln.cvss_score >= 7.0:
        segments.append("high-risk technical weakness")
    if vuln.authentication_required:
        segments.append("requires valid access before impact")
    else:
        segments.append("low-friction path to initial access")

    impact = "service compromise"
    if vuln.port in (80, 443):
        impact = "application compromise"
    elif vuln.port == 22:
        impact = "administrative access risk"
    elif vuln.port == 3389:
        impact = "remote desktop exposure"

    return f"{', '.join(segments)} could increase {impact} risk on {vuln.host}:{vuln.port}."


def generate_attack_paths(vulns: list[Vulnerability]) -> list[dict[str, Any]]:
    """
    Defensive risk-path summaries for grouped vulnerabilities.
    """
    paths: list[dict[str, Any]] = []
    grouped: dict[str, list[Vulnerability]] = defaultdict(list)
    for vuln in vulns:
        grouped[vuln.host].append(vuln)

    for host, host_vulns in grouped.items():
        sorted_vulns = sorted(host_vulns, key=lambda item: (item.risk_score, item.cvss_score), reverse=True)
        external = [item for item in sorted_vulns if item.network_exposed]
        privileged = [item for item in sorted_vulns if item.port in (22, 3389)]

        if external:
            paths.append(
                {
                    "description": f"External exposure on {host}",
                    "risk_level": external[0].severity,
                    "steps": [
                        "Review internet-facing services on the host.",
                        "Patch the highest-risk exposed findings first.",
                        "Validate segmentation and access controls after remediation.",
                    ],
                }
            )

        if external and privileged:
            paths.append(
                {
                    "description": f"Service exposure plus admin-plane risk on {host}",
                    "risk_level": max(
                        [item.severity for item in external + privileged],
                        key=lambda sev: ["Low", "Medium", "High", "Critical"].index(sev),
                    ),
                    "steps": [
                        "Reduce public exposure of application services.",
                        "Harden privileged access services such as SSH or RDP.",
                        "Prioritize controls that break lateral movement opportunities.",
                    ],
                }
            )

    return paths
