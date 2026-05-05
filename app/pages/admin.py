from __future__ import annotations

import pandas as pd
import streamlit as st

from app.pages.login import current_user, hash_password, require_roles
from app.ui import info_cards, page_hero, stat_tiles
from core.storage.database import Database


def show(db: Database) -> None:
    user = current_user()
    page_hero(
        "Administration",
        "Manage account roles, activation state, and platform access posture from one bright operations panel.",
        kicker="Access Governance",
        pills=["User management", "Role control", "Admin only"],
    )

    if not require_roles("admin"):
        return

    users = db.list_users()
    stat_tiles(
        [
            ("Total Users", str(len(users)), "Accounts currently registered."),
            ("Admins", str(sum(1 for entry in users if entry["role"] == "admin")), "Highest-privilege users."),
            ("Analysts", str(sum(1 for entry in users if entry["role"] == "analyst")), "Operational users."),
            ("Active", str(sum(1 for entry in users if entry["is_active"])), "Accounts enabled for sign-in."),
        ]
    )
    info_cards(
        [
            (
                "Presentation Tip",
                "Use this page briefly to show that SurrKarr supports role-based access control, which matters for multi-user vulnerability operations.",
            )
        ]
    )

    st.dataframe(
        pd.DataFrame(users),
        use_container_width=True,
        hide_index=True,
        column_config={
            "is_active": st.column_config.CheckboxColumn("is_active"),
        },
    )

    create_col, update_col = st.columns(2, gap="large")
    with create_col:
        st.subheader("Create User")
        col1, col2 = st.columns(2)
        username = col1.text_input("Username")
        full_name = col2.text_input("Full name")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["viewer", "analyst", "admin"])

        if st.button("Create User", type="primary", use_container_width=True):
            if not username.strip() or not password:
                st.error("Username and password are required.")
            else:
                db.create_user(
                    username.strip(),
                    hash_password(password),
                    role,
                    full_name=full_name.strip(),
                    is_active=True,
                )
                db.log_action(user["username"], "user-create", username.strip())
                st.success("User created.")
                st.rerun()

    usernames = [entry["username"] for entry in users]
    if not usernames:
        return

    with update_col:
        st.subheader("Update User")
        selected_username = st.selectbox("User", usernames)
        selected_user = next(entry for entry in users if entry["username"] == selected_username)
        new_role = st.selectbox(
            "New role",
            ["viewer", "analyst", "admin"],
            index=["viewer", "analyst", "admin"].index(selected_user["role"]),
        )
        active = st.checkbox("Active", value=bool(selected_user["is_active"]))
        reset_password = st.text_input("Reset password", type="password")

        if st.button("Apply User Changes", use_container_width=True):
            db.update_user_role(selected_username, new_role)
            db.set_user_active(selected_username, active)
            if reset_password:
                db.update_user_password(selected_username, hash_password(reset_password))
            db.log_action(user["username"], "user-update", selected_username)
            st.success("User updated.")
            st.rerun()
