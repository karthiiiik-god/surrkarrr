from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from app.pages.login import current_user
from core.risk_engine.attack_path_generator import generate_attack_paths
from core.scanner.live_scanner import get_scanner_inventory
from core.storage.database import Database


def _build_dataframe(vulns):
    return pd.DataFrame(
        [
            {
                "Host": vuln.host,
                "Port": vuln.port,
                "Service": vuln.service,
                "Finding": vuln.vulnerability_name,
                "Severity": vuln.severity,
                "CVSS": vuln.cvss_score,
                "Risk": vuln.risk_score,
                "Source": vuln.source_tool,
                "CVE": vuln.cve_id or "N/A",
                "Timestamp": vuln.timestamp,
            }
            for vuln in vulns
        ]
    )


def show(db: Database) -> None:
    user = current_user()
    st.title("SurrKarr Command Dashboard")
    st.caption("Centralized vulnerability visibility, scan coverage, and operational readiness.")

    summary = db.get_summary(user["username"], user["role"])
    vulns = db.get_all_vulnerabilities(user["username"], user["role"])
    scan_jobs = db.list_scan_jobs(limit=20, username=user["username"], role=user["role"])

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Findings", summary["total"])
    col2.metric("Critical", summary["severity_counts"]["Critical"])
    col3.metric("Assets", summary["unique_assets"])
    col4.metric("Scan Jobs", summary["scan_count"])
    col5.metric("Open Remediations", summary["open_remediations"])

    scanner_inventory = pd.DataFrame(get_scanner_inventory())
    inventory_col, status_col = st.columns([1.3, 1])
    with inventory_col:
        st.subheader("Scanner Health")
        st.dataframe(scanner_inventory, use_container_width=True, hide_index=True)
    with status_col:
        st.subheader("Platform Status")
        st.write("- File import pipeline: ready")
        st.write("- Scan history persistence: ready")
        st.write("- Live scan execution: depends on installed binaries")
        st.write("- Latest scan: " + (summary["latest_scan_at"] or "No scans yet"))

    if not vulns:
        st.info("No findings yet. Import a sample or run an authorized scan to populate the dashboard.")
        return

    df = _build_dataframe(vulns)

    chart1, chart2 = st.columns(2)
    with chart1:
        severity_counts = df["Severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]
        fig = px.pie(
            severity_counts,
            values="Count",
            names="Severity",
            title="Severity Distribution",
            color="Severity",
            color_discrete_map={
                "Critical": "#cf2e2e",
                "High": "#f59e0b",
                "Medium": "#2563eb",
                "Low": "#16a34a",
            },
        )
        st.plotly_chart(fig, use_container_width=True)

    with chart2:
        source_counts = df["Source"].value_counts().reset_index()
        source_counts.columns = ["Source", "Count"]
        fig = px.bar(source_counts, x="Source", y="Count", title="Findings by Source Tool")
        st.plotly_chart(fig, use_container_width=True)

    chart3, chart4 = st.columns(2)
    with chart3:
        host_counts = df["Host"].value_counts().head(10).reset_index()
        host_counts.columns = ["Host", "Count"]
        fig = px.bar(host_counts, x="Host", y="Count", title="Top Assets by Finding Count")
        st.plotly_chart(fig, use_container_width=True)
    with chart4:
        service_counts = df["Service"].value_counts().head(10).reset_index()
        service_counts.columns = ["Service", "Count"]
        fig = px.bar(service_counts, x="Service", y="Count", title="Service Exposure Overview")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Recent Findings")
    st.dataframe(df.head(25), use_container_width=True, hide_index=True)

    st.subheader("Recent Scan Jobs")
    if scan_jobs:
        st.dataframe(pd.DataFrame(scan_jobs), use_container_width=True, hide_index=True)
    else:
        st.info("No scan jobs recorded yet.")

    st.subheader("Risk Paths")
    for path in generate_attack_paths(vulns)[:5]:
        with st.expander(path["description"], expanded=False):
            st.write(f"Risk level: {path['risk_level']}")
            for step in path["steps"]:
                st.write(f"- {step}")
