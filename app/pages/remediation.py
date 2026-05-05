from __future__ import annotations

from datetime import date

import pandas as pd
import streamlit as st

from app.pages.login import current_user, require_roles
from core.storage.database import Database
from core.storage.models import Remediation


def show(db: Database) -> None:
    user = current_user()
    st.title("Remediation Tracking")

    if not require_roles("admin", "analyst"):
        return

    vulns = db.get_all_vulnerabilities(user["username"], user["role"])
    if not vulns:
        st.info("No findings available to remediate yet.")
        return

    selected = st.selectbox(
        "Create task for finding",
        vulns,
        format_func=lambda vuln: f"{vuln.severity} | {vuln.host}:{vuln.port} | {vuln.vulnerability_name}",
    )
    col1, col2 = st.columns(2)
    assigned_to = col1.text_input("Assigned to")
    priority = col2.selectbox("Priority", ["Critical", "High", "Medium", "Low"], index=1)
    due_date = st.date_input("Due date", value=date.today())
    notes = st.text_area("Notes", value=selected.remediation)

    if st.button("Create remediation task", type="primary"):
        db.create_remediation(
            Remediation.new(
                vuln_id=selected.vuln_id,
                assigned_to=assigned_to or user["username"] or "Unassigned",
                priority=priority,
                due_date=str(due_date),
                notes=notes,
            )
        )
        db.log_action(user["username"], "remediation-create", selected.vuln_id)
        st.success("Remediation task created.")

    st.subheader("Current Tasks")
    remediations = db.list_remediations(username=user["username"], role=user["role"])
    if not remediations:
        st.info("No remediation tasks created yet.")
        return

    st.dataframe(pd.DataFrame(remediations), use_container_width=True, hide_index=True)

    remediation_ids = [item["id"] for item in remediations]
    rem_id = st.selectbox("Update task", remediation_ids)
    new_status = st.selectbox("New status", ["Open", "In Progress", "Closed"])
    if st.button("Update remediation status"):
        db.update_remediation_status(rem_id, new_status)
        db.log_action(user["username"], "remediation-update", rem_id)
        st.success("Status updated.")
