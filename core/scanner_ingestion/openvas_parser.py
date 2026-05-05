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


def parse_openvas(xml_content: str) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return vulnerabilities

    report = root if root.tag == "report" else root.find("report")
    results = report.find("results") if report is not None else None
    if results is None:
        return vulnerabilities

    for result in results.findall("result"):
        host = result.findtext("host", default="unknown")
        port_text = result.findtext("port", default="0/tcp")
        port = int(port_text.split("/")[0]) if "/" in port_text else 0
        service = port_text.split("/")[1] if "/" in port_text else "unknown"
        nvt = result.find("nvt")
        if nvt is None:
            continue

        cvss_score = float(nvt.findtext("cvss_base", default="0") or 0)
        description = nvt.findtext("description", default="No description available")
        vulnerabilities.append(
            Vulnerability.new(
                host=host,
                port=port,
                service=service,
                vulnerability_name=nvt.findtext("name", default="OpenVAS finding"),
                description=description,
                cve_id=nvt.findtext("cve"),
                cvss_score=cvss_score,
                severity=_severity_from_cvss(cvss_score),
                source_tool="openvas",
                network_exposed=port in (80, 443, 22, 3389),
                authentication_required="auth" in description.lower(),
                exploit_available=cvss_score >= 7.0,
            )
        )

    return vulnerabilities
