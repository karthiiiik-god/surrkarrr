import xml.etree.ElementTree as ET
from typing import List
from ..storage.models import Vulnerability
import uuid
import datetime

def parse_openvas(xml_content: str) -> List[Vulnerability]:
    vulnerabilities = []
    try:
        root = ET.fromstring(xml_content)
        if root.tag == 'report':
            report = root
        else:
            report = root.find('report')
            if report is None:
                return vulnerabilities
        results = report.find('results')
        if results is None:
            return vulnerabilities
        for result in results.findall('result'):
            host_elem = result.find('host')
            host = host_elem.text if host_elem is not None else 'unknown'
            port_elem = result.find('port')
            port_str = port_elem.text if port_elem is not None else '0'
            port = int(port_str.split('/')[0]) if '/' in port_str else 0
            service = port_str.split('/')[1] if '/' in port_str else 'unknown'
            nvt = result.find('nvt')
            if nvt is not None:
                name_elem = nvt.find('name')
                vuln_name = name_elem.text if name_elem is not None else 'Unknown Vulnerability'
                cvss_base_elem = nvt.find('cvss_base')
                cvss_score = float(cvss_base_elem.text) if cvss_base_elem is not None and cvss_base_elem.text else 0.0
                severity = "Low"
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                cve_elem = nvt.find('cve')
                cve_id = cve_elem.text if cve_elem is not None else None
                desc_elem = nvt.find('description')
                description = desc_elem.text if desc_elem is not None else 'No description available'
                threat_elem = result.find('threat')
                if threat_elem is not None and threat_elem.text in ['High', 'Medium', 'Low', 'Log']:
                    # Enrichment fields
                    network_exposed = port in [80, 443, 22, 3389]
                    authentication_required = "auth" in description.lower()
                    exploit_available = cvss_score >= 7.0
                    vuln = Vulnerability(
                        vuln_id=str(uuid.uuid4()),
                        host=host,
                        port=port,
                        service=service,
                        vulnerability_name=vuln_name,
                        description=description,
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        severity=severity,
                        network_exposed=network_exposed,
                        authentication_required=authentication_required,
                        exploit_available=exploit_available,
                        source_tool="openvas",
                        timestamp=datetime.datetime.now().isoformat()
                    )
                    vulnerabilities.append(vuln)
    except ET.ParseError:
        pass
    return vulnerabilities
