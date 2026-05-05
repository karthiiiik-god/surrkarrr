from __future__ import annotations

import pandas as pd
import streamlit as st

from app.pages.login import current_user, role_allows
from core.storage.database import Database
from core.storage.models import Asset


def show(db: Database) -> None:
    user = current_user()
    assets = db.list_assets(user["username"], user["role"])
    vulns = db.get_all_vulnerabilities(user["username"], user["role"])
    scan_jobs = db.list_scan_jobs(limit=200, username=user["username"], role=user["role"])

    st.title("Asset Inventory")
    st.caption("Track ownership, criticality, and tags for discovered or managed targets.")

    asset_rows = []
    for asset in assets:
        finding_count = sum(1 for vuln in vulns if vuln.asset_id == asset.asset_id)
        scan_count = sum(1 for job in scan_jobs if job.get("asset_id") == asset.asset_id)
        asset_rows.append(
            {
                "Asset": asset.display_name,
                "Target": asset.target,
                "Owner": asset.owner_username or "Unassigned",
                "Environment": asset.environment,
                "Criticality": asset.criticality,
                "Tags": asset.tags,
                "Findings": finding_count,
                "Scan Jobs": scan_count,
                "Updated": asset.updated_at,
            }
        )

    if asset_rows:
        st.dataframe(pd.DataFrame(asset_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No assets are registered yet.")

    if not role_allows("admin", "analyst"):
        st.caption("Viewer role is read-only for asset inventory.")
        return

    st.subheader("Register or Update Asset")
    existing_labels = ["Create New"] + [f"{asset.display_name} ({asset.target})" for asset in assets]
    selection = st.selectbox("Asset record", existing_labels)

    selected_asset = None
    if selection != "Create New":
        selected_asset = assets[existing_labels.index(selection) - 1]

    target = st.text_input("Target", value=selected_asset.target if selected_asset else "")
    display_name = st.text_input("Display name", value=selected_asset.display_name if selected_asset else "")
    owner_username = st.text_input("Owner username", value=selected_asset.owner_username if selected_asset else user["username"])
    environment = st.selectbox(
        "Environment",
        ["production", "staging", "development", "lab"],
        index=["production", "staging", "development", "lab"].index(selected_asset.environment) if selected_asset else 0,
    )
    criticality = st.selectbox(
        "Criticality",
        ["Low", "Medium", "High", "Critical"],
        index=["Low", "Medium", "High", "Critical"].index(selected_asset.criticality) if selected_asset else 1,
    )
    tags = st.text_input("Tags (comma-separated)", value=selected_asset.tags if selected_asset else "")
    notes = st.text_area("Notes", value=selected_asset.notes if selected_asset else "")

    if st.button("Save Asset", type="primary"):
        if not target.strip():
            st.error("Target is required.")
            return
        asset = selected_asset or Asset.new(
            target=target.strip(),
            display_name=display_name.strip() or target.strip(),
            owner_username=owner_username.strip(),
            environment=environment,
            criticality=criticality,
            tags=tags,
            notes=notes,
        )
        if selected_asset:
            asset.target = target.strip()
            asset.display_name = display_name.strip() or target.strip()
            asset.owner_username = owner_username.strip()
            asset.environment = environment
            asset.criticality = criticality
            asset.tags = tags
            asset.notes = notes
        db.upsert_asset(asset)
        if user["username"]:
            db.log_action(user["username"], "asset-save", target.strip())
        st.success("Asset saved.")
        st.rerun()
