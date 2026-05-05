from __future__ import annotations

import json
import re

from ..storage.models import Vulnerability


def _severity_from_cvss(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "Critical"
    if cvss_score >= 7.0:
        return "High"
    if cvss_score >= 4.0:
        return "Medium"
    return "Low"


def parse_nikto(content: str) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []
    try:
        data = json.loads(content)
        items = data if isinstance(data, list) else data.get("vulnerabilities", [])
        for item in items:
            cvss_score = float(item.get("cvss", 5.0) or 5.0)
            port = int(item.get("port", 80))
            description = item.get("msg", "Nikto finding")
            vulnerabilities.append(
                Vulnerability.new(
                    host=item.get("host", "unknown"),
                    port=port,
                    service=item.get("service", "http"),
                    vulnerability_name=item.get("msg", "Nikto finding"),
                    description=description,
                    cve_id=item.get("cve"),
                    cvss_score=cvss_score,
                    severity=_severity_from_cvss(cvss_score),
                    source_tool="nikto",
                    network_exposed=port in (80, 443, 22, 3389),
                    authentication_required="auth" in description.lower(),
                    exploit_available=cvss_score >= 7.0,
                )
            )
        return vulnerabilities
    except json.JSONDecodeError:
        pass

    current_host = "unknown"
    current_port = 80
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("+ Target IP:") or line.startswith("+ Target Hostname:"):
            current_host = line.split(":", 1)[1].strip()
        elif line.startswith("+ Target Port:"):
            try:
                current_port = int(line.split(":", 1)[1].strip())
            except ValueError:
                current_port = 80
        elif line.startswith("- "):
            cve_match = re.search(r"(CVE-\d{4}-\d+)", line)
            description = line[2:].strip()
            vulnerabilities.append(
                Vulnerability.new(
                    host=current_host,
                    port=current_port,
                    service="http",
                    vulnerability_name=f"Nikto: {description[:80]}",
                    description=description,
                    cve_id=cve_match.group(1) if cve_match else None,
                    cvss_score=5.0,
                    severity="Medium",
                    source_tool="nikto",
                    network_exposed=current_port in (80, 443, 22, 3389),
                    authentication_required="auth" in description.lower(),
                    exploit_available=False,
                )
            )

    return vulnerabilities
