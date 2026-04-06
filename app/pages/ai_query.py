import streamlit as st
from core.storage.database import Database
from core.ai_query.query_executor import QueryExecutor

def show():
    st.title("AI Query Interface")
    st.write("Ask natural language questions about vulnerabilities.")

    db = Database()
    executor = QueryExecutor(db)

    query = st.text_input("Enter your query (e.g., 'Critical vulnerabilities on port 22')")

    if st.button("Execute Query") and query:
        with st.spinner("Processing query..."):
            result = executor.execute_query(query)
        
        st.write("**Explanation:**", result["explanation"])
        
        if "results" in result:
            if isinstance(result["results"], list) and result["results"]:
                if isinstance(result["results"][0], tuple):  # Top hosts
                    st.write("**Top Risky Hosts:**")
                    for host, risk in result["results"]:
                        st.write(f"- {host}: {risk:.2f}")
                elif isinstance(result["results"][0], dict):  # Attack paths
                    st.write("**Attack Paths:**")
                    for path in result["results"]:
                        st.write(f"- {path}")
                else:  # Vulnerabilities
                    st.write("**Results:**")
                    for vuln in result["results"]:
                        st.write(f"- {vuln.vulnerability_name} on {vuln.host}:{vuln.port} (Severity: {vuln.severity})")
            else:
                st.write("No results found.")
