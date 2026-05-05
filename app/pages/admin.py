from __future__ import annotations

import pandas as pd
import streamlit as st

from app.pages.login import current_user, hash_password, require_roles
from core.storage.database import Database


def show(db: Database) -> None:
    user = current_user()
    st.title("Administration")

    if not require_roles("admin"):
        return

    st.caption("Manage users and account roles.")

    users = db.list_users()
    st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)

    st.subheader("Create User")
    col1, col2 = st.columns(2)
    username = col1.text_input("Username")
    full_name = col2.text_input("Full name")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["viewer", "analyst", "admin"])

    if st.button("Create User", type="primary"):
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

    st.subheader("Update User")
    usernames = [entry["username"] for entry in users]
    if not usernames:
        return

    selected_username = st.selectbox("User", usernames)
    selected_user = next(entry for entry in users if entry["username"] == selected_username)
    new_role = st.selectbox(
        "New role",
        ["viewer", "analyst", "admin"],
        index=["viewer", "analyst", "admin"].index(selected_user["role"]),
    )
    active = st.checkbox("Active", value=bool(selected_user["is_active"]))
    reset_password = st.text_input("Reset password", type="password")

    if st.button("Apply User Changes"):
        db.update_user_role(selected_username, new_role)
        db.set_user_active(selected_username, active)
        if reset_password:
            db.update_user_password(selected_username, hash_password(reset_password))
        db.log_action(user["username"], "user-update", selected_username)
        st.success("User updated.")
        st.rerun()
