import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from core.storage.database import Database
from core.risk_engine.attack_path_generator import generate_attack_paths
import plotly.graph_objects as go

def show():
# Simple light theme - default Streamlit

    st.title("🛡️ Vulnerability Intelligence Dashboard")
    st.write("Real-time insights into your security posture")

    db = Database()
    vulns = db.get_all_vulnerabilities()

    if not vulns:
        st.markdown("""
        <div style="text-align: center; padding: 50px;">
            <h2 style="color: #666;">🔍 No Vulnerabilities Found</h2>
            <p style="font-size: 1.1rem; color: #888;">Upload some scan results to populate the dashboard</p>
            <div style="margin: 30px 0;">
                <img src="https://via.placeholder.com/400x250/1f77b4/ffffff?text=Upload+Scan+Results" style="border-radius: 10px; opacity: 0.8;">
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Enhanced metrics with gradient cards
    total = len(vulns)
    critical = sum(1 for v in vulns if v.severity == "Critical")
    high = sum(1 for v in vulns if v.severity == "High")
    medium = sum(1 for v in vulns if v.severity == "Medium")
    low = sum(1 for v in vulns if v.severity == "Low")

    st.subheader("📊 Key Security Metrics")

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Vulnerabilities", total)
    with col2:
        st.metric("Critical", critical)
    with col3:
        st.metric("High", high)
    with col4:
        st.metric("Medium", medium)
    with col5:
        st.metric("Low", low)

    # Charts section
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.subheader("📈 Severity Distribution")
        severity_counts = pd.Series([v.severity for v in vulns]).value_counts()
        fig = px.pie(severity_counts, values=severity_counts.values, names=severity_counts.index,
                     color_discrete_sequence=['#ff6b6b', '#feca57', '#48cae4', '#52b788'],
                     hole=0.4)
        fig.update_layout(showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.subheader("🎯 CVSS Score Distribution")
        cvss_scores = [v.cvss_score for v in vulns]
        fig2 = go.Figure()
        fig2.add_trace(go.Histogram(x=cvss_scores, nbinsx=20,
                                   marker_color='#667eea',
                                   opacity=0.7))
        fig2.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="Frequency",
            bargap=0.1
        )
        st.plotly_chart(fig2, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Top vulnerable hosts
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.subheader("🏠 Top Vulnerable Hosts")
    host_counts = pd.Series([v.host for v in vulns]).value_counts().head(10)
    fig3 = px.bar(host_counts, x=host_counts.index, y=host_counts.values,
                  labels={'x': 'Host IP', 'y': 'Vulnerability Count'},
                  color=host_counts.values,
                  color_continuous_scale='Reds')
    fig3.update_layout(xaxis_tickangle=-45)
    st.plotly_chart(fig3, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Recent vulnerabilities with enhanced table
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.subheader("🕒 Recent Vulnerabilities")
    recent_vulns = vulns[-10:]  # Last 10
    df = pd.DataFrame([{
        "Host": v.host,
        "Port": v.port,
        "Service": v.service,
        "Vulnerability": v.vulnerability_name[:50] + "..." if len(v.vulnerability_name) > 50 else v.vulnerability_name,
        "Severity": v.severity,
        "CVSS": f"{v.cvss_score:.1f}",
"Source": v.source_tool,
        "Timestamp": v.timestamp[:19]
    } for v in recent_vulns])

    def color_severity(val):
        color = {'Critical': '#ff6b6b', 'High': '#feca57', 'Medium': '#48cae4', 'Low': '#52b788'}.get(val, '')
        return f'background-color: {color}; color: white; font-weight: bold;' if color else ''

    styled_df = df.style.applymap(color_severity, subset=['Severity'])
    st.dataframe(styled_df, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Risk summary
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.subheader("⚠️ Risk Assessment Summary")
    risk_levels = {
        "High Risk": sum(1 for v in vulns if v.cvss_score >= 7.0),
        "Medium Risk": sum(1 for v in vulns if 4.0 <= v.cvss_score < 7.0),
        "Low Risk": sum(1 for v in vulns if v.cvss_score < 4.0)
    }
    fig4 = px.bar(x=list(risk_levels.keys()), y=list(risk_levels.values()),
                  color=list(risk_levels.keys()),
                  color_discrete_map={'High Risk': '#ff6b6b', 'Medium Risk': '#feca57', 'Low Risk': '#52b788'})
    fig4.update_layout(xaxis_title="Risk Level", yaxis_title="Count")
    st.plotly_chart(fig4, use_container_width=True)

    # Attack Path Analysis
    with st.expander("⚡ Attack Path Analysis", expanded=True):
        paths = generate_attack_paths(vulns)
        if paths:
            st.success(f"Found {len(paths)} potential attack paths")
            for i, path in enumerate(paths[:5], 1):
                with st.expander(f"Path {i}: {path['description']}", expanded=False):
                    st.json(path['steps'], expanded=True)
                    
                    # Simple sankey graph for path
                    labels = ['Start'] + path['steps']
                    source = [0, 0, 1, 2]
                    target = [1, 2, 3, 3]
                    value = [1, 1, 1, 1]
                    fig_path = go.Figure(data=[go.Sankey(
                        node = dict(label = labels, color = "#ff6b6b"),
                        link = dict(source = source, target = target, value = value)
                    )])
                    fig_path.update_layout(title_text="Attack Path Flow", font_size=12)
                    st.plotly_chart(fig_path, use_container_width=True)
        else:
            st.info("No attack paths identified (needs vulns with exploit_available)")

