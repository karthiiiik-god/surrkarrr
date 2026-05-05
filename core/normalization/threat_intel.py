from __future__ import annotations

from typing import Any


THREAT_INTEL_CATALOG: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "description": "Apache Log4j remote code execution exposure affecting internet-facing services.",
        "cvss": 10.0,
        "epss": 0.97,
        "references": ["NVD", "Vendor advisories"],
        "remediation": "Upgrade Log4j to a fixed version and remove vulnerable JndiLookup usage.",
    },
    "CVE-2018-15473": {
        "description": "OpenSSH username enumeration issue that can support reconnaissance against SSH services.",
        "cvss": 5.0,
        "epss": 0.23,
        "references": ["NVD", "OpenSSH advisory"],
        "remediation": "Upgrade OpenSSH and restrict unnecessary SSH exposure.",
    },
    "CVE-2017-0144": {
        "description": "SMB remote code execution issue commonly known as EternalBlue.",
        "cvss": 9.8,
        "epss": 0.95,
        "references": ["NVD", "Microsoft advisory"],
        "remediation": "Apply MS17-010, disable SMBv1, and segment exposed Windows assets.",
    },
}


def lookup_threat_intel(cve_id: str | None) -> dict[str, Any] | None:
    if not cve_id:
        return None
    return THREAT_INTEL_CATALOG.get(cve_id.strip().upper())


def references_text(threat_intel: dict[str, Any]) -> str:
    references = threat_intel.get("references", [])
    if isinstance(references, str):
        return references
    return "; ".join(str(item) for item in references)


def build_threat_intel_citation(cve_id: str | None) -> dict[str, str] | None:
    threat_intel = lookup_threat_intel(cve_id)
    if not threat_intel or not cve_id:
        return None

    return {
        "label": f"{cve_id} threat profile",
        "source_type": "threat-intel",
        "reference": f"threat-intel:{cve_id}",
        "snippet": threat_intel["description"],
        "details": f"Sources: {references_text(threat_intel)}",
    }
