from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..storage.models import Vulnerability


SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _impact_for_port(vuln: Vulnerability) -> str:
    if vuln.port in (80, 443):
        return "application compromise"
    if vuln.port == 22:
        return "administrative access risk"
    if vuln.port == 3389:
        return "remote desktop exposure"
    return "service compromise"


def summarize_risk_path(vuln: Vulnerability) -> str:
    segments = []
    if vuln.network_exposed:
        segments.append("internet-facing service")
    if vuln.cvss_score >= 9.0:
        segments.append("critical technical weakness")
    elif vuln.cvss_score >= 7.0:
        segments.append("high-risk technical weakness")
    if vuln.authentication_required:
        segments.append("requires valid access before impact")
    else:
        segments.append("low-friction path to initial access")

    impact = _impact_for_port(vuln)
    return f"{', '.join(segments)} could increase {impact} on {vuln.host}:{vuln.port}; remediate this weakness to break the path."


def _priority_for_severity(severity: str) -> str:
    if severity == "Critical":
        return "Immediate"
    if severity == "High":
        return "High"
    if severity == "Medium":
        return "Planned"
    return "Routine"


def _build_risk_path(
    *,
    description: str,
    risk_level: str,
    reasoning: str,
    recommended_actions: list[str],
) -> dict[str, Any]:
    return {
        "description": description,
        "risk_level": risk_level,
        "reasoning": reasoning,
        "remediation_priority": _priority_for_severity(risk_level),
        "recommended_actions": recommended_actions,
        # Keep a compatibility alias for older UI/report code that still
        # iterates over `steps`.
        "steps": recommended_actions,
    }


def generate_risk_paths(vulns: list[Vulnerability]) -> list[dict[str, Any]]:
    """
    Build remediation-focused risk-path summaries from grouped findings.
    """
    paths: list[dict[str, Any]] = []
    grouped: dict[str, list[Vulnerability]] = defaultdict(list)
    for vuln in vulns:
        grouped[vuln.host].append(vuln)

    for host, host_vulns in grouped.items():
        sorted_vulns = sorted(host_vulns, key=lambda item: (item.risk_score, item.cvss_score), reverse=True)
        external = [item for item in sorted_vulns if item.network_exposed]
        privileged = [item for item in sorted_vulns if item.port in (22, 3389)]
        high_risk = [item for item in sorted_vulns if item.severity in ("Critical", "High")]

        if external:
            primary = external[0]
            paths.append(
                _build_risk_path(
                    description=f"External exposure on {host}",
                    risk_level=primary.severity,
                    reasoning=f"{host} has exposed services with high normalized risk, which can accelerate initial access and downstream impact.",
                    recommended_actions=[
                        "Reduce public exposure of the affected service where possible.",
                        "Patch the highest-risk exposed findings first.",
                        "Validate segmentation and compensating controls after remediation.",
                    ],
                )
            )

        if external and privileged:
            combined = external + privileged
            combined_level = max(
                [item.severity for item in combined],
                key=lambda sev: SEVERITY_ORDER.get(sev, 0),
            )
            paths.append(
                _build_risk_path(
                    description=f"Service exposure plus admin-plane risk on {host}",
                    risk_level=combined_level,
                    reasoning=f"{host} combines externally reachable services with administrative access surfaces, increasing the need to break privilege-escalation and lateral-movement opportunities.",
                    recommended_actions=[
                        "Harden privileged access services such as SSH or RDP.",
                        "Restrict direct administrative access behind MFA, VPN, or jump hosts.",
                        "Prioritize fixes that remove both initial-access and admin-plane weaknesses together.",
                    ],
                )
            )

        if len(high_risk) >= 2:
            anchor = high_risk[0]
            paths.append(
                _build_risk_path(
                    description=f"Multiple high-risk findings concentrated on {host}",
                    risk_level=anchor.severity,
                    reasoning=f"{host} has several high-priority findings, so remediation should be coordinated at the asset level instead of treating each item in isolation.",
                    recommended_actions=[
                        "Group remediation work by asset owner and maintenance window.",
                        "Retest the host after the patch set is applied to confirm risk reduction.",
                        "Update asset criticality and ownership metadata if this host is business-critical.",
                    ],
                )
            )

    return paths
