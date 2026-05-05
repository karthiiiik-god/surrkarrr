from __future__ import annotations

from datetime import date

import pandas as pd
import streamlit as st

from app.pages.login import current_user, require_roles
from app.ui import info_cards, page_hero, stat_tiles
from core.storage.database import Database
from core.storage.models import Remediation


def show(db: Database) -> None:
    user = current_user()
    page_hero(
        "Remediation Tracking",
        "Convert high-priority findings into accountable work items and show progress clearly during the demo.",
        kicker="Action Queue",
        pills=["Task ownership", "Status visibility", "Closure tracking"],
    )

    if not require_roles("admin", "analyst"):
        return

    vulns = db.get_all_vulnerabilities(user["username"], user["role"])
    if not vulns:
        st.info("No findings available to remediate yet.")
        return

    remediations = db.list_remediations(username=user["username"], role=user["role"])
    stat_tiles(
        [
            ("Open", str(sum(1 for item in remediations if item["status"] == "Open")), "Tasks not yet started."),
            ("In Progress", str(sum(1 for item in remediations if item["status"] == "In Progress")), "Tasks currently being worked."),
            ("Closed", str(sum(1 for item in remediations if item["status"] == "Closed")), "Tasks already completed."),
            ("Findings Ready", str(len(vulns)), "Findings available to convert into work."),
        ]
    )

    form_col, queue_col = st.columns([1.05, 1], gap="large")
    with form_col:
        selected = st.selectbox(
            "Create task for finding",
            vulns,
            format_func=lambda vuln: f"{vuln.severity} | {vuln.host}:{vuln.port} | {vuln.vulnerability_name}",
        )
        col1, col2 = st.columns(2)
        assigned_to = col1.text_input("Assigned to", value=user["username"])
        priority = col2.selectbox("Priority", ["Critical", "High", "Medium", "Low"], index=1)
        due_date = st.date_input("Due date", value=date.today())
        notes = st.text_area("Notes", value=selected.remediation)

        if st.button("Create remediation task", type="primary", use_container_width=True):
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
            st.rerun()

    with queue_col:
        info_cards(
            [
                (
                    "Demo Talking Point",
                    "This page shows that SurrKarr does not stop at detection. It turns prioritized findings into tracked remediation work with owners and closure state.",
                ),
                (
                    "Best Sequence",
                    "Create a task from one critical finding, show it in the queue, then update the status to demonstrate end-to-end defensive workflow coverage.",
                ),
            ]
        )

    st.subheader("Current Tasks")
    if not remediations:
        st.info("No remediation tasks created yet.")
        return

    status_filter, priority_filter = st.columns(2)
    selected_status = status_filter.selectbox("Filter by status", ["All", "Open", "In Progress", "Closed"])
    selected_priority = priority_filter.selectbox("Filter by priority", ["All", "Critical", "High", "Medium", "Low"])
    filtered_tasks = [
        item
        for item in remediations
        if (selected_status == "All" or item["status"] == selected_status)
        and (selected_priority == "All" or item["priority"] == selected_priority)
    ]

    st.dataframe(
        pd.DataFrame(filtered_tasks),
        use_container_width=True,
        hide_index=True,
        column_config={
            "notes": st.column_config.TextColumn("notes", width="large"),
        },
    )

    remediation_ids = [item["id"] for item in filtered_tasks] or [item["id"] for item in remediations]
    rem_id = st.selectbox("Update task", remediation_ids)
    new_status = st.selectbox("New status", ["Open", "In Progress", "Closed"])
    if st.button("Update remediation status", use_container_width=True):
        db.update_remediation_status(rem_id, new_status)
        db.log_action(user["username"], "remediation-update", rem_id)
        st.success("Status updated.")
        st.rerun()
