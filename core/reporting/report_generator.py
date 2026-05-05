from __future__ import annotations

import json
from io import BytesIO
from typing import Iterable

from ..risk_engine.attack_path_generator import generate_attack_paths
from ..storage.models import Vulnerability


def _severity_counts(vulns: list[Vulnerability]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for vuln in vulns:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
    return counts


def generate_markdown_report(vulns: list[Vulnerability]) -> str:
    severity_counts = _severity_counts(vulns)
    top_risks = sorted(vulns, key=lambda item: (item.risk_score, item.cvss_score), reverse=True)[:10]
    risk_paths = generate_attack_paths(vulns)[:5]

    lines = [
        "# SurrKarr Vulnerability Report",
        "",
        "## Summary",
        f"- Total vulnerabilities: {len(vulns)}",
        f"- Critical: {severity_counts['Critical']}",
        f"- High: {severity_counts['High']}",
        f"- Medium: {severity_counts['Medium']}",
        f"- Low: {severity_counts['Low']}",
        "",
        "## Top Findings",
    ]
    for vuln in top_risks:
        lines.extend(
            [
                f"- {vuln.vulnerability_name} on {vuln.host}:{vuln.port}",
                f"  CVE: {vuln.cve_id or 'N/A'} | CVSS: {vuln.cvss_score:.1f} | Risk: {vuln.risk_score:.1f}",
                f"  Remediation: {vuln.remediation}",
            ]
        )

    lines.extend(["", "## Risk Paths"])
    if risk_paths:
        for path in risk_paths:
            lines.append(f"- {path['description']}: {' '.join(path['steps'])}")
    else:
        lines.append("- No multi-step risk paths identified from current data.")

    return "\n".join(lines)


def generate_json_report(vulns: Iterable[Vulnerability]) -> str:
    return json.dumps([vuln.to_dict() for vuln in vulns], indent=2)


def generate_pdf_report(vulns: list[Vulnerability]) -> bytes:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        # Fallback keeps tests and offline usage working even if reportlab is unavailable.
        return generate_markdown_report(vulns).encode("utf-8")

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50

    for line in generate_markdown_report(vulns).splitlines():
        pdf.drawString(50, y, line[:110])
        y -= 16
        if y < 50:
            pdf.showPage()
            y = height - 50

    pdf.save()
    buffer.seek(0)
    return buffer.getvalue()


def generate_report(vulns: list[Vulnerability], format_type: str = "markdown") -> str | bytes:
    format_normalized = format_type.lower()
    if format_normalized == "markdown":
        return generate_markdown_report(vulns)
    if format_normalized == "pdf":
        return generate_pdf_report(vulns)
    if format_normalized == "json":
        return generate_json_report(vulns)
    raise ValueError(f"Unsupported format: {format_type}")
