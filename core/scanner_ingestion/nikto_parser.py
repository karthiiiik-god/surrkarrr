import json
from typing import List
from ..storage.models import Vulnerability
import uuid
import datetime

def parse_nikto(content: str) -> List[Vulnerability]:
    vulnerabilities = []
    try:
        # Try parsing as JSON
        data = json.loads(content)
        if isinstance(data, list):
            items = data
        else:
            items = data.get('vulnerabilities', [])
        for item in items:
            host = item.get('host', 'unknown')
            port = item.get('port', 80)
            service = item.get('service', 'http')
            vuln_name = item.get('msg', 'Nikto finding')
            description = item.get('msg', '')
            cve_id = item.get('cve')
            cvss_score = item.get('cvss', 0.0)
            severity = "Low"
            if cvss_score >= 9.0:
                severity = "Critical"
            elif cvss_score >= 7.0:
                severity = "High"
            elif cvss_score >= 4.0:
                severity = "Medium"
            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                host=host,
                port=port,
                service=service,
                vulnerability_name=vuln_name,
                description=description,
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                source_tools=["nikto"],
                timestamp=datetime.datetime.now().isoformat()
            )
            vulnerabilities.append(vuln)
    except json.JSONDecodeError:
        # Parse as TXT
        lines = content.split('\n')
        current_host = 'unknown'
        current_port = 80
        for line in lines:
            line = line.strip()
            if line.startswith('+ Target IP:'):
                current_host = line.split(':', 1)[1].strip()
            elif line.startswith('+ Target Hostname:'):
                current_host = line.split(':', 1)[1].strip()
            elif line.startswith('+ Target Port:'):
                try:
                    current_port = int(line.split(':', 1)[1].strip())
                except ValueError:
                    current_port = 80
            elif line.startswith('- ') and 'CVE-' in line:
                parts = line[2:].split()
                cve_id = None
                for part in parts:
                    if part.startswith('CVE-'):
                        cve_id = part
                        break
                msg = ' '.join(parts)
                vuln_name = f"Nikto: {msg}"
                description = msg
                cvss_score = 5.0  # Default CVSS for Nikto findings without score
                severity = "Medium"
                # Enrichment fields
                network_exposed = current_port in [80, 443, 22, 3389]
                authentication_required = "auth" in description.lower()
                exploit_available = cvss_score >= 7.0
                vuln = Vulnerability(
                    vuln_id=str(uuid.uuid4()),
                    host=current_host,
                    port=current_port,
                    service='http',
                    vulnerability_name=vuln_name,
                    description=description,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    network_exposed=network_exposed,
                    authentication_required=authentication_required,
                    exploit_available=exploit_available,
                    source_tool="nikto",
                    timestamp=datetime.datetime.now().isoformat()
                )
                vulnerabilities.append(vuln)
    return vulnerabilities
