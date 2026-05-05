from __future__ import annotations

from ..risk_engine.risk_path_analyzer import summarize_risk_path
from ..risk_engine.rule_based_risk import assess_risk
from ..storage.models import Vulnerability
from .threat_intel import lookup_threat_intel, references_text


def _default_remediation(vuln: Vulnerability) -> str:
    if vuln.port in (80, 443):
        return "Patch the web stack, validate exposed components, and restrict public access where possible."
    if vuln.port == 22:
        return "Restrict SSH exposure, enforce strong authentication, and patch the service version."
    if vuln.port == 3389:
        return "Limit RDP exposure, require MFA or VPN access, and patch the remote access service."
    return "Patch the affected service, validate compensating controls, and retest after remediation."


def enrich_vulnerability(vuln: Vulnerability) -> Vulnerability:
    """
    Apply lightweight offline-safe enrichment so the pipeline stays runnable
    even when external threat intelligence lookups are unavailable.
    """
    if vuln.cve_id:
        cve_id = vuln.cve_id.strip().upper()
        vuln.cve_id = cve_id
        threat_intel = lookup_threat_intel(cve_id)
        if threat_intel:
            data = threat_intel
            vuln.nvd_description = data["description"]
            vuln.cvss_score = max(float(vuln.cvss_score), float(data["cvss"]))
            vuln.epss_score = max(float(vuln.epss_score), float(data["epss"]))
            vuln.references = references_text(data)
            vuln.remediation = data["remediation"]

    if not vuln.nvd_description:
        vuln.nvd_description = vuln.description
    if not vuln.references:
        vuln.references = "Local parser evidence"
    if not vuln.remediation:
        vuln.remediation = _default_remediation(vuln)

    vuln.risk_path = summarize_risk_path(vuln)
    assess_risk(vuln)
    return vuln
