import streamlit as st
from core.storage.database import Database
from app.pages.upload_scans import show as show_scans
from app.pages.dashboard import show as show_dashboard
from app.pages.ai_query import show as show_ai_query
from app.pages.reports import show as show_reports

st.set_page_config(page_title="SurrKarr", layout="wide")

db = Database()
vulns = db.get_all_vulnerabilities()

st.sidebar.title("🛡️ SurrKarr")
page = st.sidebar.radio("Pages", ["Dashboard", "Scans", "Remediation", "AI Query", "Reports"])

if page == "Dashboard":
    show_dashboard()
elif page == "Scans":
    show_scans()
elif page == "AI Query":
    show_ai_query()
elif page == "Remediation":
    from app.pages.remediation import show as show_remediation
    show_remediation()
elif page == "Reports":
    show_reports()


