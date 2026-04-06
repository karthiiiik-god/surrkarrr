from typing import List
from ..storage.models import Vulnerability
from ..risk_engine.attack_path_generator import generate_attack_paths
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

def generate_report(vulns: List[Vulnerability], format_type: str) -> str | bytes:
    """
    Generate a report in Markdown or PDF format.
    Includes summary, severity breakdown, top risks, and recommendations.
    """
    # Summary
    total = len(vulns)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for vuln in vulns:
        severity_counts[vuln.severity] += 1
    
    # Top risks: top 10 by CVSS descending
    sorted_vulns = sorted(vulns, key=lambda v: v.cvss_score, reverse=True)
    top_risks = sorted_vulns[:10]

    # Top attack paths
    attack_paths = generate_attack_paths(vulns)
    top_paths = attack_paths[:3]  # Top 3

    # Recommendations
    recommendations = [
        "Prioritize patching Critical and High severity vulnerabilities.",
        "Review and mitigate Medium severity issues within the next sprint.",
        "Monitor Low severity vulnerabilities for potential escalation.",
        "Ensure all systems are up-to-date with the latest security patches.",
        "Conduct regular vulnerability scans and reviews."
    ]
    # Add path-specific recommendations
    for path in top_paths:
        recommendations.append(f"Mitigate attack path: {path['description']} - {path['steps'][-1]}")
    
    if format_type == "markdown":
        report = f"# Vulnerability Report\n\n"
        report += f"## Summary\n\n"
        report += f"Total Vulnerabilities: {total}\n\n"
        report += "## Severity Breakdown\n\n"
        for sev, count in severity_counts.items():
            report += f"- {sev}: {count}\n"
        report += "\n## Top Risks\n\n"
        for i, vuln in enumerate(top_risks, 1):
            report += f"{i}. {vuln.vulnerability_name} on {vuln.host}:{vuln.port} (CVSS: {vuln.cvss_score}, Severity: {vuln.severity})\n"
        report += "\n## Recommendations\n\n"
        for rec in recommendations:
            report += f"- {rec}\n"
        return report
    elif format_type == "pdf":
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        y = height - 50
        c.drawString(50, y, "Vulnerability Report")
        y -= 30
        
        c.drawString(50, y, f"Total Vulnerabilities: {total}")
        y -= 20
        
        c.drawString(50, y, "Severity Breakdown:")
        y -= 20
        for sev, count in severity_counts.items():
            c.drawString(70, y, f"{sev}: {count}")
            y -= 15
        
        c.drawString(50, y, "Top Risks:")
        y -= 20
        for i, vuln in enumerate(top_risks, 1):
            text = f"{i}. {vuln.vulnerability_name} on {vuln.host}:{vuln.port} (CVSS: {vuln.cvss_score})"
            c.drawString(70, y, text)
            y -= 15
            if y < 50:
                c.showPage()
                y = height - 50
        
        c.drawString(50, y, "Recommendations:")
        y -= 20
        for rec in recommendations:
            c.drawString(70, y, rec)
            y -= 15
            if y < 50:
                c.showPage()
                y = height - 50
        
        c.save()
        buffer.seek(0)
        return buffer.getvalue()
    else:
        raise ValueError("Unsupported format")
