import xml.etree.ElementTree as ET
from typing import List
from ..storage.models import Vulnerability
import uuid
import datetime

def parse_nmap(xml_content: str) -> List[Vulnerability]:
    vulnerabilities = []
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall('host'):
            host_addr = host.find('address').get('addr') if host.find('address') else 'unknown'
            for port in host.findall('ports/port'):
                port_id = int(port.get('portid'))
                service = port.find('service').get('name') if port.find('service') else 'unknown'
                for script in port.findall('script'):
                    script_id = script.get('id', '').lower()
                    if 'vuln' in script_id or 'vulners' in script_id:

                        output = script.find('output').text if script.find('output') is not None else ''
                        lines = output.split('\n')
                        for line in lines:
                            if 'CVE-' in line:
                                parts = line.split()
                                cve = parts[0] if 'CVE-' in parts[0] else None
                                cvss = float(parts[1]) if len(parts) > 1 and parts[1].replace('.', '').isdigit() else 0.0
                                desc = ' '.join(parts[2:]) if len(parts) > 2 else 'Vulnerability detected'
                                vuln_name = f"Nmap vuln on {service}"
                                severity = "Low"
                                if cvss >= 9.0:
                                    severity = "Critical"
                                elif cvss >= 7.0:
                                    severity = "High"
                                elif cvss >= 4.0:
                                    severity = "Medium"
                                # Enrichment fields
                                network_exposed = port_id in [80, 443, 22, 3389]
                                authentication_required = "auth" in desc.lower()
                                exploit_available = cvss >= 7.0
                                vuln = Vulnerability(
                                    vuln_id=str(uuid.uuid4()),
                                    host=host_addr,
                                    port=port_id,
                                    service=service,
                                    vulnerability_name=vuln_name,
                                    description=desc,
                                    cve_id=cve,
                                    cvss_score=cvss,
                                    severity=severity,
                                    network_exposed=network_exposed,
                                    authentication_required=authentication_required,
                                    exploit_available=exploit_available,
                                    source_tool="nmap",
                                    timestamp=datetime.datetime.now().isoformat()
                                )
                                vulnerabilities.append(vuln)
    except ET.ParseError:
        pass
    return vulnerabilities
