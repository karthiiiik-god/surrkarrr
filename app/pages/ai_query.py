from __future__ import annotations

import streamlit as st

from app.pages.login import current_user
from app.ui import info_cards, page_hero
from core.ai_query.query_executor import QueryExecutor
from core.storage.database import Database


def show(db: Database) -> None:
    user = current_user()
    page_hero(
        "AI Query Assistant",
        "Ask grounded questions over findings, assets, scan jobs, saved reports, and local threat-intel context.",
        kicker="Evidence First",
        pills=["Grounded retrieval", "Citation aware", "Remediation focused"],
    )

    info_cards(
        [
            (
                "Example Questions",
                "Critical vulnerabilities on port 22. Top risky hosts. Risk path for ssh. Assets owned by analyst. Report summary for log4j. Tag live-scan.",
            ),
            (
                "Response Shape",
                "Each answer is designed to show a summary, supporting evidence, risk reasoning, remediation guidance, and citations when available.",
            ),
        ]
    )

    query = st.text_input("Ask a grounded question")
    if not query:
        return

    executor = QueryExecutor(db, user["username"], user["role"])
    result = executor.execute_query(query)

    response = result.get("response", {})
    st.subheader("Grounded Response")
    st.write(response.get("summary") or result.get("answer") or result.get("explanation", "No answer generated."))

    evidence = response.get("evidence", [])
    if evidence:
        with st.expander("Evidence", expanded=True):
            for item in evidence:
                st.write(f"- {item}")

    if response.get("risk_reasoning"):
        st.subheader("Risk Reasoning")
        st.write(response["risk_reasoning"])

    if response.get("remediation_guidance"):
        st.subheader("Remediation Guidance")
        st.write(response["remediation_guidance"])

    citations = response.get("citations") or result.get("citations", [])
    if citations:
        with st.expander("Citations", expanded=True):
            for citation in citations:
                if isinstance(citation, dict):
                    label = citation.get("label", citation.get("reference", "reference"))
                    snippet = citation.get("snippet", "")
                    details = citation.get("details", "")
                    line = f"- [{citation.get('source_type', 'source')}] {label}"
                    if snippet:
                        line += f" | {snippet}"
                    if details:
                        line += f" | {details}"
                    st.write(line)
                else:
                    st.write(f"- {citation}")

    results = result.get("results", [])
    if not results:
        st.info("No matching results found.")
        return

    mode = result.get("mode", "")
    if mode == "hosts":
        for host, risk in results:
            st.write(f"- {host}: {risk:.1f}")
        return

    if mode == "paths":
        for item in results:
            with st.expander(item["description"], expanded=False):
                st.write(f"Risk level: {item['risk_level']}")
                st.write(item.get("reasoning", ""))
                st.write(f"Remediation priority: {item.get('remediation_priority', 'Planned')}")
                for step in item.get("recommended_actions", item.get("steps", [])):
                    st.write(f"- {step}")
        return

    if mode == "vulnerabilities":
        for vuln in results:
            with st.expander(f"{vuln.severity} | {vuln.host}:{vuln.port} | {vuln.vulnerability_name}", expanded=False):
                st.write(vuln.description)
                st.write(f"CVE: {vuln.cve_id or 'N/A'}")
                st.write(f"CVSS: {vuln.cvss_score:.1f} | Risk: {vuln.risk_score:.1f}")
                st.write(f"Risk path: {vuln.risk_path}")
                st.write(f"Remediation: {vuln.remediation}")
        return

    for item in results:
        if isinstance(item, dict):
            with st.expander(item.get("title", item.get("label", "Result")), expanded=False):
                st.write(item.get("snippet", ""))
                st.caption(item.get("reference", ""))
