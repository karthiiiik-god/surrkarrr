from __future__ import annotations

import re
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


def parse_nmap(xml_content: str) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return vulnerabilities

    for host in root.findall("host"):
        address = host.find("address")
        host_addr = address.get("addr", "unknown") if address is not None else "unknown"

        for port in host.findall("ports/port"):
            port_id = int(port.get("portid", 0))
            service_elem = port.find("service")
            service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

            for script in port.findall("script"):
                script_id = script.get("id", "").lower()
                if "vuln" not in script_id and "vulner" not in script_id:
                    continue

                output = script.get("output", "")
                lines = [line.strip() for line in output.splitlines() if "CVE-" in line]

                script_vulns: list[Vulnerability] = []

                # Prefer explicit CVE tables when present.
                for table in script.findall("table"):
                    cve_id = table.get("key")
                    cvss_elem = table.find("./elem[@key='cvss']")
                    is_exploit_elem = table.find("./elem[@key='is_exploit']")
                    cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else 0.0
                    script_vulns.append(
                        Vulnerability.new(
                            host=host_addr,
                            port=port_id,
                            service=service,
                            vulnerability_name=f"Nmap finding on {service}",
                            description=f"Nmap detected {cve_id} on {service}.",
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            severity=_severity_from_cvss(cvss_score),
                            source_tool="nmap",
                            network_exposed=port_id in (80, 443, 22, 3389),
                            authentication_required="auth" in output.lower(),
                            exploit_available=(is_exploit_elem is not None and is_exploit_elem.text == "true") or cvss_score >= 7.0,
                        )
                    )

                if script_vulns:
                    vulnerabilities.extend(script_vulns)
                    continue

                for line in lines:
                    match = re.search(r"(CVE-\d{4}-\d+)\s+(\d+(?:\.\d+)?)", line)
                    if not match:
                        continue
                    cve_id = match.group(1)
                    cvss_score = float(match.group(2))
                    description = line.replace(match.group(0), "").strip() or "Vulnerability detected by Nmap."
                    vulnerabilities.append(
                        Vulnerability.new(
                            host=host_addr,
                            port=port_id,
                            service=service,
                            vulnerability_name=f"Nmap finding on {service}",
                            description=description,
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            severity=_severity_from_cvss(cvss_score),
                            source_tool="nmap",
                            network_exposed=port_id in (80, 443, 22, 3389),
                            authentication_required="auth" in description.lower(),
                            exploit_available=cvss_score >= 7.0,
                        )
                    )

    return vulnerabilities
