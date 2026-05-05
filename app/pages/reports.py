from __future__ import annotations

import json

import streamlit as st

from app.pages.login import current_user, role_allows
from core.reporting.report_generator import generate_report
from core.storage.database import Database
from core.storage.models import ReportSnapshot


def show(db: Database) -> None:
    user = current_user()
    st.title("Reports")

    vulns = db.get_all_vulnerabilities(user["username"], user["role"])
    if not vulns:
        st.info("No findings available for reporting.")
        return

    summary = db.get_summary(user["username"], user["role"])
    scan_jobs = db.list_scan_jobs(limit=10, username=user["username"], role=user["role"])
    snapshots = db.list_report_snapshots(limit=10, username=user["username"], role=user["role"])

    st.write(f"Findings in scope: {summary['total']}")
    st.write(f"Recorded scan jobs: {summary['scan_count']}")
    st.write(f"Saved report snapshots: {summary['report_count']}")

    format_type = st.selectbox("Report format", ["markdown", "pdf", "json"])
    report_title = st.text_input("Report title", value="SurrKarr Security Snapshot")
    content = generate_report(vulns, format_type)
    can_save = role_allows("admin", "analyst")

    if format_type == "json":
        payload = {
            "summary": summary,
            "recent_scan_jobs": scan_jobs,
            "findings": json.loads(content),
        }
        rendered = json.dumps(payload, indent=2)
        if can_save and st.button("Save Snapshot", key="save_json_snapshot"):
            db.save_report_snapshot(
                ReportSnapshot.new(
                    title=report_title,
                    format_type="json",
                    content=rendered,
                    created_by=user["username"],
                )
            )
            db.log_action(user["username"], "report-save", report_title)
            st.success("Report snapshot saved.")
        st.subheader("Preview")
        st.code(rendered[:5000], language="json")
        st.download_button(
            "Download report",
            rendered.encode("utf-8"),
            file_name="surrkarr_report.json",
            mime="application/json",
        )
        return

    if isinstance(content, str):
        rendered = (
            f"# {report_title}\n\n"
            f"- Total findings: {summary['total']}\n"
            f"- Scan jobs recorded: {summary['scan_count']}\n"
            f"- Unique assets: {summary['unique_assets']}\n\n"
            f"{content}"
        )
        if can_save and st.button("Save Snapshot", key="save_markdown_snapshot"):
            db.save_report_snapshot(
                ReportSnapshot.new(
                    title=report_title,
                    format_type="markdown",
                    content=rendered,
                    created_by=user["username"],
                )
            )
            db.log_action(user["username"], "report-save", report_title)
            st.success("Report snapshot saved.")
        st.subheader("Preview")
        st.code(rendered[:5000], language="markdown")
        st.download_button(
            "Download report",
            rendered.encode("utf-8"),
            file_name="surrkarr_report.md",
            mime="text/markdown",
        )
    else:
        if can_save and st.button("Save Snapshot", key="save_pdf_snapshot"):
            markdown_shadow = generate_report(vulns, "markdown")
            db.save_report_snapshot(
                ReportSnapshot.new(
                    title=report_title,
                    format_type="pdf",
                    content=markdown_shadow if isinstance(markdown_shadow, str) else "",
                    created_by=user["username"],
                )
            )
            db.log_action(user["username"], "report-save", report_title)
            st.success("PDF snapshot index saved.")
        st.info("PDF report generated.")
        st.download_button(
            "Download PDF report",
            content,
            file_name="surrkarr_report.pdf",
            mime="application/pdf",
        )

    st.subheader("Saved Snapshots")
    if snapshots:
        st.dataframe(snapshots, use_container_width=True, hide_index=True)
    else:
        st.info("No saved report snapshots yet.")
