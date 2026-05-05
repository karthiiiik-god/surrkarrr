from __future__ import annotations

import pandas as pd
import streamlit as st

from app.pages import admin, ai_query, assets, dashboard, login, remediation, reports, upload_scans, vulnerability_view
from app.ui import apply_theme, sidebar_brand
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
        initial_sidebar_state="expanded",
    )
    apply_theme()

    db = Database()
    login.ensure_session_state()
    login.bootstrap_default_users(db)

    if not login.is_authenticated():
        login.show_login_panel(db)
        return

    user = login.current_user()
    summary = db.get_summary(user["username"], user["role"])
    inventory = get_scanner_inventory()

    sidebar_brand(user, summary, inventory)
    st.sidebar.success(f"Active scope: {user['username']} ({user['role']})")
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
    inventory_frame = pd.DataFrame(inventory)
    online_count = int(inventory_frame["available"].sum()) if not inventory_frame.empty else 0
    st.sidebar.caption(f"Live scanner readiness: {online_count}/{len(inventory)} online")

    pages[page_name](db)


if __name__ == "__main__":
    main()
