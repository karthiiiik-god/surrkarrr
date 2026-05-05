from __future__ import annotations

import xml.etree.ElementTree as ET

from ..storage.models import Vulnerability


def _severity_from_cvss(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "Critical"
    if cvss_score >= 7.0:
        return "High"
    if cvss_score >= 4.0:
        return "Medium"
    return "Low"


def parse_nessus(xml_content: str) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return vulnerabilities

    report = root.find("Report")
    if report is None:
        return vulnerabilities

    for host_elem in report.findall("ReportHost"):
        host = host_elem.get("name", "unknown")
        for item in host_elem.findall("ReportItem"):
            severity_level = int(item.get("severity", 0))
            if severity_level <= 0:
                continue

            port = int(item.get("port", 0))
            service = item.get("svc_name", "unknown")
            plugin_name = item.get("pluginName", "Unknown Vulnerability")
            description = item.findtext("description", default="No description available")
            cve_id = item.findtext("cve")
            cvss_score = float(item.findtext("cvss_base_score", default="0") or 0)

            if cvss_score == 0.0:
                fallback_scores = {4: 9.0, 3: 7.0, 2: 5.0, 1: 3.0}
                cvss_score = fallback_scores.get(severity_level, 0.0)

            vulnerabilities.append(
                Vulnerability.new(
                    host=host,
                    port=port,
                    service=service,
                    vulnerability_name=plugin_name,
                    description=description,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=_severity_from_cvss(cvss_score),
                    source_tool="nessus",
                    network_exposed=port in (80, 443, 22, 3389),
                    authentication_required="auth" in description.lower(),
                    exploit_available=cvss_score >= 7.0,
                )
            )

    return vulnerabilities
