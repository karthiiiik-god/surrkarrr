import streamlit as st
from core.storage.database import Database
from core.reporting.report_generator import generate_report

def show():
    st.title("📋 Structured Security Reports (Phase 2)")
    st.markdown("Generate enriched reports with CVE, CVSS, attack paths & remediation.")
    
    db = Database()
    vulns = db.get_all_vulnerabilities()
    
    if not vulns:
        st.info("📤 No data - run scans first!")
        return
    
    col1, col2 = st.columns(2)
    with col1:
        report_type = st.selectbox("Report Type", ["Full Report", "Executive Summary", "Attack Paths"])
    with col2:
        format_type = st.selectbox("Format", ["Markdown", "PDF"])
    
    if st.button("🛠️ Generate Report", type="primary"):
        with st.spinner("Generating enriched report..."):
            report_md = generate_report(vulns)  # Enhance backend if needed
            # Add Phase 2 enrichments
            enriched = f"# Phase 2 Report\\n\\n## Key Metrics\\n- Total: {len(vulns)}\\n"
            for v in vulns[:5]:  # Preview
                enriched += f"### {v.vulnerability_name}\\nCVSS: {v.cvss_score}\\nAttack Path: {getattr(v, 'attack_path', 'Generated')}\\nCVE: {v.cve_id}\\n\\n"
            report_content = enriched + report_md
        
        st.markdown("### Preview")
        st.markdown(report_content)
        
        st.download_button(
            "📥 Download Report",
            report_content,
            f"surrkarr_report_{report_type.lower().replace(' ', '_')}.{format_type.lower()}",
            mime="text/markdown" if format_type == "Markdown" else "application/pdf"
        )
    
    # Charts
    severity_counts = pd.Series([v.severity for v in vulns]).value_counts()
    fig = px.pie(severity_counts, names=severity_counts.index, title="Vuln Distribution")
    st.plotly_chart(fig)
