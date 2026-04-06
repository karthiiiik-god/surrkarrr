import streamlit as st
import pandas as pd
import plotly.express as px
from core.storage.database import Database

st.set_page_config(page_title="SurrKarr Dashboard", layout="wide")

st.title("🛡️ SurrKarr - Simple Vulnerability Dashboard")

db = Database()
vulns = db.get_all_vulnerabilities()

col1, col2 = st.columns(2)
total = len(vulns)
st.metric("Total Vulnerabilities", total)

if vulns:
    severity_counts = pd.Series([v.severity for v in vulns]).value_counts()
    fig = px.pie(severity_counts, names=severity_counts.index, title="Severity Distribution")
    st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Recent Vulnerabilities")
    df = pd.DataFrame([vars(v) for v in vulns[:10]])
    st.dataframe(df, use_container_width=True)
else:
    st.info("No vulnerabilities. Upload scans to populate.")

st.sidebar.header("Actions")
if st.sidebar.button("Live Scan (nmap scanme.nmap.org)"):
    st.rerun()

st.sidebar.info("Light simple UI - no dark colors")
