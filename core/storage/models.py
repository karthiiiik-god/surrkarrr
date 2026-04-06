from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Vulnerability:
    vuln_id: str
    host: str
    port: int
    service: str
    vulnerability_name: str
    description: str
    cvss_score: float
    severity: str
    source_tool: str
    timestamp: str
    cve_id: Optional[str] = None
    network_exposed: bool = False
    authentication_required: bool = False
    exploit_available: bool = False
    epss_score: float = 0.0
    nvd_description: str = ""

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


@dataclass
class Remediation:
    id: str
    vuln_id: str
    assigned_to: str
    status: str = "Open"
    priority: str = "High"
    due_date: str = ""
    notes: str = ""
    created_at: str = ""

