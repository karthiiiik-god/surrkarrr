from __future__ import annotations

import pandas as pd
import streamlit as st

from app.pages import admin, ai_query, assets, dashboard, login, remediation, reports, upload_scans, vulnerability_view
from core.scanner.live_scanner import get_scanner_inventory
from core.storage.database import Database


ROLE_PAGES = {
    "viewer": {
        "Dashboard": dashboard.show,
        "Asset Inventory": assets.show,
        "Findings Explorer": vulnerability_view.show,
        "AI Query": ai_query.show,
        "Reports": reports.show,
    },
    "analyst": {
        "Dashboard": dashboard.show,
        "Scan Operations": upload_scans.show,
        "Asset Inventory": assets.show,
        "Findings Explorer": vulnerability_view.show,
        "AI Query": ai_query.show,
        "Reports": reports.show,
        "Remediation": remediation.show,
    },
    "admin": {
        "Dashboard": dashboard.show,
        "Scan Operations": upload_scans.show,
        "Asset Inventory": assets.show,
        "Findings Explorer": vulnerability_view.show,
        "AI Query": ai_query.show,
        "Reports": reports.show,
        "Remediation": remediation.show,
        "Administration": admin.show,
    },
}


def _available_pages_for_role(role: str) -> dict[str, callable]:
    return ROLE_PAGES.get(role, ROLE_PAGES["viewer"])


def main() -> None:
    st.set_page_config(
        page_title="SurrKarr",
        layout="wide",
    )

    db = Database()
    login.ensure_session_state()
    login.bootstrap_default_users(db)

    if not login.is_authenticated():
        login.show_login_panel(db)
        return

    user = login.current_user()
    summary = db.get_summary(user["username"], user["role"])

    st.sidebar.title("SurrKarr")
    st.sidebar.caption("Role-based vulnerability intelligence and defensive scanning.")
    st.sidebar.success(f"{user['username']} ({user['role']})")
    if st.sidebar.button("Logout"):
        login.logout()

    pages = _available_pages_for_role(user["role"])
    page_name = st.sidebar.radio("Navigate", list(pages))

    st.sidebar.markdown("---")
    st.sidebar.write("Scope Snapshot")
    st.sidebar.write(f"- Findings: {summary['total']}")
    st.sidebar.write(f"- Assets: {summary['unique_assets']}")
    st.sidebar.write(f"- Scan jobs: {summary['scan_count']}")
    st.sidebar.write(f"- Reports: {summary['report_count']}")

    st.sidebar.markdown("---")
    st.sidebar.write("Scanner Availability")
    inventory = pd.DataFrame(get_scanner_inventory())
    for _, row in inventory.iterrows():
        status = "online" if row["available"] else "offline"
        st.sidebar.write(f"- {row['scanner']}: {status}")

    pages[page_name](db)


if __name__ == "__main__":
    main()
