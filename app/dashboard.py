import streamlit as st
from app.pages.upload_scans import show as show_scans
from app.pages.vulnerability_view import show_vulnerability_view
from app.pages.ai_query import show_ai_query
from app.pages.reports import show_reports
from app.pages.dashboard import show as show_dashboard  # Simple light dashboard

st.set_page_config(
    page_title="SurrKarr - Vulnerability Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Light simple theme - Streamlit default

st.sidebar.title("🛡️ Navigation")
page = st.sidebar.radio("Select Page", ["Overview", "Scans", "Vulns", "AI/ML Query", "Reports"])

if page == "Overview":
    st.markdown('<h1 class="main-header">Dashboard Overview</h1>', unsafe_allow_html=True)
    show_dashboard()
elif page == "Scans":
    st.markdown('<h1 class="main-header">Scan Management</h1>', unsafe_allow_html=True)
    show_scans()
elif page == "Vulns":
    st.markdown('<h1 class="main-header">Vuln Intelligence</h1>', unsafe_allow_html=True)
    show_vulnerability_view(Database())
elif page == "AI/ML Query":
    st.markdown('<h1 class="main-header">AI/ML Assistant</h1>', unsafe_allow_html=True)
    show_ai_query(Database())
elif page == "Reports":
    st.markdown('<h1 class="main-header">Reports</h1>', unsafe_allow_html=True)
    show_reports(Database())

