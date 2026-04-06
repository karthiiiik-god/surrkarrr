import xml.etree.ElementTree as ET
from typing import List
from ..storage.models import Vulnerability
import uuid
import datetime

def parse_nessus(xml_content: str) -> List[Vulnerability]:
    vulnerabilities = []
    try:
        root = ET.fromstring(xml_content)
        report = root.find('Report')
        if report is None:
            return vulnerabilities
        for host_elem in report.findall('ReportHost'):
            host = host_elem.get('name', 'unknown')
            for item in host_elem.findall('ReportItem'):
                port = int(item.get('port', 0))
                svc_name = item.get('svc_name', 'unknown')
                plugin_name = item.get('pluginName', 'Unknown Vulnerability')
                severity_level = int(item.get('severity', 0))
                cvss_base = item.find('cvss_base_score')
                cvss_score = float(cvss_base.text) if cvss_base is not None and cvss_base.text else 0.0
                if cvss_score == 0.0:
                    # Fallback based on severity
                    if severity_level == 4:
                        cvss_score = 9.0
                    elif severity_level == 3:
                        cvss_score = 7.0
                    elif severity_level == 2:
                        cvss_score = 5.0
                    elif severity_level == 1:
                        cvss_score = 3.0
                    else:
                        cvss_score = 0.0
                severity = "Low"
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                cve_elem = item.find('cve')
                cve_id = cve_elem.text if cve_elem is not None else None
                desc_elem = item.find('description')
                description = desc_elem.text if desc_elem is not None else 'No description available'
                # Enrichment fields
                network_exposed = port in [80, 443, 22, 3389]
                authentication_required = "auth" in description.lower()
                exploit_available = cvss_score >= 7.0
                if severity_level > 0:  # Skip info level
                    vuln = Vulnerability(
                        vuln_id=str(uuid.uuid4()),
                        host=host,
                        port=port,
                        service=svc_name,
                        vulnerability_name=plugin_name,
                        description=description,
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        severity=severity,
                        network_exposed=network_exposed,
                        authentication_required=authentication_required,
                        exploit_available=exploit_available,
                        source_tool="nessus",
                        timestamp=datetime.datetime.now().isoformat()
                    )
                    vulnerabilities.append(vuln)
    except ET.ParseError:
        pass
    return vulnerabilities
