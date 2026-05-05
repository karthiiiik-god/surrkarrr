from __future__ import annotations

from hashlib import sha256

import streamlit as st

from core.storage.database import Database

try:
    from passlib.context import CryptContext
except Exception:
    CryptContext = None


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto") if CryptContext else None
DEFAULT_BOOTSTRAP_USERS = [
    ("admin", "admin123", "admin", "Platform Administrator"),
    ("analyst", "analyst123", "analyst", "Security Analyst"),
    ("viewer", "viewer123", "viewer", "Read Only User"),
]


def hash_password(password: str) -> str:
    if pwd_context:
        return pwd_context.hash(password)
    return sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    if pwd_context:
        return pwd_context.verify(password, password_hash)
    return sha256(password.encode("utf-8")).hexdigest() == password_hash


def ensure_session_state() -> None:
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("username", "")
    st.session_state.setdefault("user_role", "viewer")
    st.session_state.setdefault("full_name", "")


def bootstrap_default_users(db: Database) -> None:
    if db.count_users() > 0:
        return
    for username, password, role, full_name in DEFAULT_BOOTSTRAP_USERS:
        db.create_user(
            username,
            hash_password(password),
            role,
            full_name=full_name,
            is_active=True,
        )


def current_user() -> dict[str, str]:
    return {
        "username": st.session_state.get("username", ""),
        "role": st.session_state.get("user_role", "viewer"),
        "full_name": st.session_state.get("full_name", ""),
    }


def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def logout() -> None:
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""
    st.session_state["user_role"] = "viewer"
    st.session_state["full_name"] = ""
    st.rerun()


def role_allows(*allowed_roles: str) -> bool:
    return st.session_state.get("user_role") in allowed_roles


def require_roles(*allowed_roles: str) -> bool:
    if role_allows(*allowed_roles):
        return True
    st.warning("Your role does not allow this action.")
    return False


def show_login_panel(db: Database) -> None:
    st.title("SurrKarr Access Portal")
    st.caption("Role-based access for vulnerability operations and reporting.")

    with st.expander("Bootstrap Credentials", expanded=False):
        st.write("These are created automatically when the database has no users:")
        for username, password, role, _ in DEFAULT_BOOTSTRAP_USERS:
            st.write(f"- {username} / {password} ({role})")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login", type="primary"):
        user = db.get_user(username)
        if not user or not user.get("is_active"):
            st.error("Invalid or inactive account.")
            return
        if verify_password(password, user["password_hash"]):
            st.session_state["authenticated"] = True
            st.session_state["username"] = user["username"]
            st.session_state["user_role"] = user["role"]
            st.session_state["full_name"] = user.get("full_name", "")
            db.log_action(user["username"], "login", "interactive-session")
            st.rerun()
        else:
            st.error("Invalid credentials")
