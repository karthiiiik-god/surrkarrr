from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from app.pages.login import current_user
from app.ui import CHART_COLORS, info_cards, page_hero, stat_tiles, style_figure
from core.risk_engine.risk_path_analyzer import generate_risk_paths
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
    summary = db.get_summary(user["username"], user["role"])
    vulns = db.get_all_vulnerabilities(user["username"], user["role"])
    scan_jobs = db.list_scan_jobs(limit=20, username=user["username"], role=user["role"])
    scanner_inventory = pd.DataFrame(get_scanner_inventory())
    online_scanners = int(scanner_inventory["available"].sum()) if not scanner_inventory.empty else 0
    top_host = summary["top_hosts"][0][0] if summary["top_hosts"] else "No dominant asset yet"
    top_host_count = summary["top_hosts"][0][1] if summary["top_hosts"] else 0

    page_hero(
        "SurrKarr Command Dashboard",
        "Centralized visibility into normalized findings, scan readiness, asset concentration, and remediation-focused risk paths.",
        kicker="Operational Overview",
        pills=[
            f"Role {user['role'].title()}",
            f"Findings {summary['total']}",
            f"Assets {summary['unique_assets']}",
            f"Reports {summary['report_count']}",
        ],
    )

    stat_tiles(
        [
            ("Total Findings", str(summary["total"]), "Current findings in your visible scope."),
            ("Critical", str(summary["severity_counts"]["Critical"]), "Highest-priority issues requiring immediate attention."),
            ("Assets", str(summary["unique_assets"]), "Distinct systems currently tracked."),
            ("Scan Jobs", str(summary["scan_count"]), "Uploaded or live scan executions recorded."),
            ("Open Remediations", str(summary["open_remediations"]), "Tasks still active across the scope."),
        ]
    )

    st.subheader("Executive Brief")
    info_cards(
        [
            (
                "Risk Posture",
                f"The current scope contains {summary['severity_counts']['Critical']} critical findings across {summary['unique_assets']} assets. The most concentrated asset is {top_host} with {top_host_count} stored findings.",
            ),
            (
                "Immediate Priority",
                "Focus first on internet-facing critical findings, then break any combined service-exposure and admin-plane risk paths before moving into broad hygiene work.",
            ),
            (
                "Collection Readiness",
                f"{online_scanners} of {len(scanner_inventory)} live scanner adapters are online. Artifact import remains available even when scanner binaries are offline.",
            ),
        ]
    )

    inventory_col, status_col = st.columns([1.3, 1])
    with inventory_col:
        st.subheader("Scanner Health")
        st.dataframe(scanner_inventory, use_container_width=True, hide_index=True)
    with status_col:
        info_cards(
            [
                (
                    "Platform Status",
                    "File-import normalization and scan history persistence are ready. Live scan execution depends on locally installed scanner binaries.",
                ),
                (
                    "Latest Activity",
                    f"Latest scan time: {summary['latest_scan_at'] or 'No scans yet'}. Keep sample imports handy for fast demonstrations.",
                ),
            ]
        )

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
            color_discrete_map=CHART_COLORS,
            hole=0.45,
        )
        st.plotly_chart(style_figure(fig), use_container_width=True)

    with chart2:
        source_counts = df["Source"].value_counts().reset_index()
        source_counts.columns = ["Source", "Count"]
        fig = px.bar(
            source_counts,
            x="Source",
            y="Count",
            title="Findings by Source Tool",
            color="Count",
            color_continuous_scale=["#dff4ef", "#0f7b6c"],
        )
        st.plotly_chart(style_figure(fig), use_container_width=True)

    chart3, chart4 = st.columns(2)
    with chart3:
        host_counts = df["Host"].value_counts().head(10).reset_index()
        host_counts.columns = ["Host", "Count"]
        fig = px.bar(
            host_counts,
            x="Host",
            y="Count",
            title="Top Assets by Finding Count",
            color="Count",
            color_continuous_scale=["#fff0df", "#f4a261"],
        )
        st.plotly_chart(style_figure(fig), use_container_width=True)
    with chart4:
        service_counts = df["Service"].value_counts().head(10).reset_index()
        service_counts.columns = ["Service", "Count"]
        fig = px.bar(
            service_counts,
            x="Service",
            y="Count",
            title="Service Exposure Overview",
            color="Count",
            color_continuous_scale=["#e5eefc", "#4f83cc"],
        )
        st.plotly_chart(style_figure(fig), use_container_width=True)

    st.subheader("Recent Findings")
    st.dataframe(
        df.head(25),
        use_container_width=True,
        hide_index=True,
        column_config={
            "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "Risk": st.column_config.NumberColumn("Risk", format="%.1f"),
        },
    )

    st.subheader("Recent Scan Jobs")
    if scan_jobs:
        st.dataframe(
            pd.DataFrame(scan_jobs),
            use_container_width=True,
            hide_index=True,
            column_config={
                "findings_count": st.column_config.NumberColumn("findings_count", format="%d"),
            },
        )
    else:
        st.info("No scan jobs recorded yet.")

    st.subheader("Risk Paths")
    for path in generate_risk_paths(vulns)[:5]:
        with st.expander(path["description"], expanded=False):
            st.write(f"Risk level: {path['risk_level']}")
            st.write(path.get("reasoning", ""))
            st.write(f"Remediation priority: {path.get('remediation_priority', 'Planned')}")
            for step in path.get("recommended_actions", path.get("steps", [])):
                st.write(f"- {step}")
