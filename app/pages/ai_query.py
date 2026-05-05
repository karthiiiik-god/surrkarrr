from __future__ import annotations

import streamlit as st

from app.pages.login import current_user
from core.ai_query.query_executor import QueryExecutor
from core.storage.database import Database


def show(db: Database) -> None:
    user = current_user()
    st.title("AI Query Assistant")
    st.caption("Grounded retrieval over findings, assets, scan jobs, and saved reports.")

    st.write("Examples:")
    st.write("- Critical vulnerabilities on port 22")
    st.write("- Top risky hosts")
    st.write("- Attack path for ssh")
    st.write("- Assets owned by analyst")
    st.write("- Report summary for log4j")
    st.write("- Tag live-scan")

    query = st.text_input("Ask a grounded question")
    if not query:
        return

    executor = QueryExecutor(db, user["username"], user["role"])
    result = executor.execute_query(query)

    st.subheader("Answer")
    st.write(result.get("answer") or result.get("explanation", "No answer generated."))
    if result.get("explanation"):
        st.caption(result["explanation"])

    citations = result.get("citations", [])
    if citations:
        with st.expander("Citations", expanded=True):
            for citation in citations:
                if isinstance(citation, dict):
                    st.write(f"- [{citation.get('source_type', 'source')}] {citation.get('label', citation.get('reference', 'reference'))}")
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
                for step in item["steps"]:
                    st.write(f"- {step}")
        return

    if mode == "vulnerabilities":
        for vuln in results:
            with st.expander(f"{vuln.severity} | {vuln.host}:{vuln.port} | {vuln.vulnerability_name}", expanded=False):
                st.write(vuln.description)
                st.write(f"CVE: {vuln.cve_id or 'N/A'}")
                st.write(f"CVSS: {vuln.cvss_score:.1f} | Risk: {vuln.risk_score:.1f}")
                st.write(f"Remediation: {vuln.remediation}")
        return

    for item in results:
        if isinstance(item, dict):
            with st.expander(item.get("title", item.get("label", "Result")), expanded=False):
                st.write(item.get("snippet", ""))
                st.caption(item.get("reference", ""))
