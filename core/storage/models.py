from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    risk_score: float = 0.0
    exploit_prob: float = 0.0
    risk_path: str = ""
    references: str = ""
    remediation: str = ""
    asset_id: Optional[str] = None

    @classmethod
    def new(
        cls,
        *,
        host: str,
        port: int,
        service: str,
        vulnerability_name: str,
        description: str,
        cvss_score: float,
        severity: str,
        source_tool: str,
        cve_id: Optional[str] = None,
        network_exposed: bool = False,
        authentication_required: bool = False,
        exploit_available: bool = False,
        epss_score: float = 0.0,
        nvd_description: str = "",
        risk_score: float = 0.0,
        exploit_prob: float = 0.0,
        risk_path: str = "",
        attack_path: str = "",
        references: str = "",
        remediation: str = "",
        asset_id: Optional[str] = None,
    ) -> "Vulnerability":
        return cls(
            vuln_id=str(uuid4()),
            host=host,
            port=int(port),
            service=service,
            vulnerability_name=vulnerability_name,
            description=description,
            cvss_score=float(cvss_score),
            severity=severity,
            source_tool=source_tool,
            timestamp=_now_iso(),
            cve_id=cve_id,
            network_exposed=network_exposed,
            authentication_required=authentication_required,
            exploit_available=exploit_available,
            epss_score=float(epss_score),
            nvd_description=nvd_description,
            risk_score=float(risk_score),
            exploit_prob=float(exploit_prob),
            risk_path=risk_path or attack_path,
            references=references,
            remediation=remediation,
            asset_id=asset_id,
        )

    @classmethod
    def from_row(cls, row: Any) -> "Vulnerability":
        if row is None:
            raise ValueError("Cannot build Vulnerability from empty row")
        data = dict(row)
        return cls(
            vuln_id=data["vuln_id"],
            host=data["host"],
            port=int(data["port"]),
            service=data["service"],
            vulnerability_name=data["vulnerability_name"],
            description=data["description"],
            cvss_score=float(data["cvss_score"]),
            severity=data["severity"],
            source_tool=data["source_tool"],
            timestamp=data["timestamp"],
            cve_id=data.get("cve_id"),
            network_exposed=bool(data.get("network_exposed", 0)),
            authentication_required=bool(data.get("authentication_required", 0)),
            exploit_available=bool(data.get("exploit_available", 0)),
            epss_score=float(data.get("epss_score", 0.0)),
            nvd_description=data.get("nvd_description", ""),
            risk_score=float(data.get("risk_score", 0.0)),
            exploit_prob=float(data.get("exploit_prob", 0.0)),
            risk_path=data.get("risk_path", data.get("attack_path", "")),
            references=data.get("reference_links", data.get("references", "")),
            remediation=data.get("remediation", ""),
            asset_id=data.get("asset_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Preserve a legacy alias for downstream consumers that still expect
        # the historical field name.
        data["attack_path"] = self.risk_path
        return data

    @property
    def attack_path(self) -> str:
        return self.risk_path

    @attack_path.setter
    def attack_path(self, value: str) -> None:
        self.risk_path = value


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

    @classmethod
    def new(
        cls,
        *,
        vuln_id: str,
        assigned_to: str,
        priority: str = "High",
        due_date: str = "",
        notes: str = "",
    ) -> "Remediation":
        return cls(
            id=str(uuid4()),
            vuln_id=vuln_id,
            assigned_to=assigned_to,
            priority=priority,
            due_date=due_date,
            notes=notes,
            created_at=_now_iso(),
        )


@dataclass
class ScanJob:
    id: str
    scanner: str
    mode: str
    target: str
    profile: str
    status: str
    command: str = ""
    artifact_path: str = ""
    findings_count: int = 0
    started_at: str = ""
    finished_at: str = ""
    error_message: str = ""
    asset_id: Optional[str] = None
    created_by: str = ""

    @classmethod
    def new(
        cls,
        *,
        scanner: str,
        mode: str,
        target: str,
        profile: str,
        status: str = "Queued",
        command: str = "",
        artifact_path: str = "",
        asset_id: Optional[str] = None,
        created_by: str = "",
    ) -> "ScanJob":
        return cls(
            id=str(uuid4()),
            scanner=scanner,
            mode=mode,
            target=target,
            profile=profile,
            status=status,
            command=command,
            artifact_path=artifact_path,
            started_at=_now_iso(),
            asset_id=asset_id,
            created_by=created_by,
        )


@dataclass
class Asset:
    asset_id: str
    target: str
    display_name: str
    owner_username: str = ""
    environment: str = "production"
    criticality: str = "Medium"
    tags: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def new(
        cls,
        *,
        target: str,
        display_name: str,
        owner_username: str = "",
        environment: str = "production",
        criticality: str = "Medium",
        tags: str = "",
        notes: str = "",
    ) -> "Asset":
        timestamp = _now_iso()
        return cls(
            asset_id=str(uuid4()),
            target=target,
            display_name=display_name,
            owner_username=owner_username,
            environment=environment,
            criticality=criticality,
            tags=tags,
            notes=notes,
            created_at=timestamp,
            updated_at=timestamp,
        )

    @classmethod
    def from_row(cls, row: Any) -> "Asset":
        if row is None:
            raise ValueError("Cannot build Asset from empty row")
        data = dict(row)
        return cls(
            asset_id=data["asset_id"],
            target=data["target"],
            display_name=data["display_name"],
            owner_username=data.get("owner_username", ""),
            environment=data.get("environment", "production"),
            criticality=data.get("criticality", "Medium"),
            tags=data.get("tags", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class ReportSnapshot:
    id: str
    title: str
    format_type: str
    content: str
    created_by: str = ""
    created_at: str = ""

    @classmethod
    def new(
        cls,
        *,
        title: str,
        format_type: str,
        content: str,
        created_by: str = "",
    ) -> "ReportSnapshot":
        return cls(
            id=str(uuid4()),
            title=title,
            format_type=format_type,
            content=content,
            created_by=created_by,
            created_at=_now_iso(),
        )
