import streamlit as st
from core.storage.database import Database
from core.storage.models import Remediation
from datetime import datetime
import uuid

def show():
    st.header("🔧 Remediation Workflow")
    st.write("Assign, track and manage vulnerability remediation.")

    db = Database()
    
    # Vulns table with remediation status
    vulns = db.get_all_vulnerabilities()
    if not vulns:
        st.info("No vulnerabilities. Upload scans first.")
        return

    # Show vulns with remediation options
    for vuln in vulns:
        with st.expander(f"{vuln.severity}: {vuln.vulnerability_name} ({vuln.host}:{vuln.port})"):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("CVSS", vuln.cvss_score)
            with col2:
                st.metric("EPSS", f"{vuln.epss_score*100:.1f}%")
            with col3:
                priority = st.selectbox("Priority", ["High", "Medium", "Low"], key=f"pri_{vuln.vuln_id}")
            
            assigned = st.text_input("Assigned To", key=f"assign_{vuln.vuln_id}")
            due_date = st.date_input("Due Date", key=f"due_{vuln.vuln_id}")
            notes = st.text_area("Notes", key=f"notes_{vuln.vuln_id}")
            
            if st.button("Create Remediation Task", key=f"create_{vuln.vuln_id}"):
                rem_id = str(uuid.uuid4())
                db.conn.execute("""
                    INSERT INTO remediations (id, vuln_id, assigned_to, status, priority, due_date, notes, created_at)
                    VALUES (?, ?, ?, 'Open', ?, ?, ?, ?)
                """, (rem_id, vuln.vuln_id, assigned, priority, str(due_date), notes, datetime.now().isoformat()))
                db.conn.commit()
                st.success("Remediation task created!")
                st.rerun()
    
    # Remediation dashboard
    st.subheader("📋 Active Remediations")
    cursor = db.conn.execute("SELECT * FROM remediations WHERE status != 'Closed' ORDER BY priority DESC, due_date")
    rems = cursor.fetchall()
    if rems:
        df = pd.DataFrame(rems, columns=['id', 'vuln_id', 'assigned_to', 'status', 'priority', 'due_date', 'notes', 'created_at'])
        st.dataframe(df)
    else:
        st.info("No active remediations.")

    # Update status
    st.subheader("Update Status")
    rem_id = st.text_input("Remediation ID")
    new_status = st.selectbox("Status", ["Open", "In Progress", "Closed"])
    if st.button("Update") and rem_id:
        db.conn.execute("UPDATE remediations SET status = ? WHERE id = ?", (new_status, rem_id))
        db.conn.commit()
        st.success("Status updated!")

