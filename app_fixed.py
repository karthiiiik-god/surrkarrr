import streamlit as st
import pandas as pd
import plotly.express as px
from core.storage.database import Database
from core.scanner.live_scanner import run_live_scan
from core.reporting.report_generator import generate_report

# AI/ML stub
def execute_query(query: str, vulns):
    if 'high' in query.lower():
        high_vulns = [v for v in vulns if v.severity == 'High']
        return f"Found {len(high_vulns)} high severity vulns."
    return "Query processed - check results."

st.set_page_config(page_title="SurrKarr - Complete Vuln Platform", page_icon="🛡️", layout="wide")

# Light simple theme - Streamlit default

if "user_role" not in st.session_state:
    st.session_state.user_role = None
    st.session_state.username = None

def simple_login():
    if st.session_state.user_role is None:
        st.title("🔐 Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            db = Database()
            user = db.authenticate_user(username, password)
            if user:
                st.session_state.user_role = user.role
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Wrong credentials")
        st.stop()
    return True

def logout():
    st.session_state.user_role = None
    st.session_state.username = None
    st.rerun()

simple_login()

db = Database()
vulns = db.get_all_vulnerabilities()
    
st.sidebar.success(f"Logged in: {st.session_state.username} ({st.session_state.user_role})")
if st.sidebar.button("Logout"):
    logout()

# Sidebar Nav
st.sidebar.title("🛡️ SurrKarr")
page = st.sidebar.radio("Navigate", ["📊 Dashboard", "🔍 Live Scan", "👁️ Vuln View", "🤖 AI/ML", "📋 Reports"])

if page == "📊 Dashboard":
    st.header("🛡️ Dashboard")
    col1, col2, col3, col4, col5 = st.columns(5)
    total = len(vulns)
    critical = sum(1 for v in vulns if v.severity == 'Critical')
    high = sum(1 for v in vulns if v.severity == 'High')
    with col1:
        st.metric("Total Vulns", total)
    with col2:
        st.metric("Critical", critical)
    # More metrics...
    severity_counts = pd.Series([v.severity for v in vulns]).value_counts()
    fig = px.pie(severity_counts, names=severity_counts.index)
    st.plotly_chart(fig, use_container_width=True)

st.session_state.user_role == "admin"
    if page == "🔍 Live Scan":
        st.header("🔍 Live Scanning")
        col1, col2 = st.columns(2)
        with col1:
            target = st.text_input("Target", "scanme.nmap.org")
            scanner = st.selectbox("Scanner", ["nmap", "nikto", "nuclei"])
        with col2:
            options = st.text_input("Options", "-sV -sC")
        if st.button("🚀 Scan", type="primary"):
            with st.spinner("Scanning..."):
                try:
                    result = run_live_scan(scanner, target, db, {"extra_args": options.split()})
                    st.success(result)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
elif page == "👁️ Vuln View":
    st.header("Vuln Intelligence")
    if vulns:
        df = pd.DataFrame([vars(v) for v in vulns])
        st.dataframe(df[['host', 'severity', 'cvss_score', 'cve_id', 'vulnerability_name']], use_container_width=True)
        csv = df.to_csv(index=False)
        st.download_button("Export CSV", csv, "vulns.csv")
    else:
        st.info("Scan first!")

if page == "🤖 AI/ML":
    st.header("AI/ML Assistant")
    query = st.text_input("Ask about vulns (e.g., 'high severity on host')")
    if st.button("Query") and query:
        with st.spinner("AI analyzing..."):
            response = execute_query(query, vulns)
            st.write(response)

if page == "📋 Reports":
    st.header("Reports")
    if st.button("Generate"):
        report = generate_report(vulns)
        st.markdown(report)
        st.download_button("Download MD", report, "report.md")

st.sidebar.info("✅ SurrKarr Complete")
