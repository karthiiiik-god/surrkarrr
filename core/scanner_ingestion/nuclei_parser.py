from __future__ import annotations

import json
from urllib.parse import urlparse

from ..storage.models import Vulnerability


def _severity_from_text(severity: str) -> str:
    severity_normalized = (severity or "").strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Low",
    }
    return mapping.get(severity_normalized, "Medium")


def _cvss_from_severity(severity: str) -> float:
    return {
        "Critical": 9.5,
        "High": 8.0,
        "Medium": 5.5,
        "Low": 2.5,
    }.get(severity, 5.5)


def parse_nuclei(content: str) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        severity = _severity_from_text(info.get("severity", item.get("severity", "medium")))
        target = item.get("host") or item.get("matched-at") or item.get("url") or "unknown"
        matched = item.get("matched-at", "")
        parsed = urlparse(matched if "://" in matched else "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host_value = parsed.hostname or target

        vulnerabilities.append(
            Vulnerability.new(
                host=host_value,
                port=port,
                service="http",
                vulnerability_name=item.get("template-id", "Nuclei finding"),
                description=info.get("description", item.get("matcher-name", "Nuclei matched a template")),
                cve_id=(info.get("classification") or {}).get("cve-id"),
                cvss_score=_cvss_from_severity(severity),
                severity=severity,
                source_tool="nuclei",
                network_exposed=True,
                authentication_required=False,
                exploit_available=severity in ("Critical", "High"),
                references=", ".join(info.get("reference", [])) if info.get("reference") else "",
            )
        )

    return vulnerabilities
