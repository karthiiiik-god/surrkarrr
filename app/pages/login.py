import streamlit as st
from core.storage.database import Database
from passlib.context import CryptContext

try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except:
    from hashlib import sha256
    pwd_context = None

def hash_password(password):
    if pwd_context:
        return pwd_context.hash(password)
    return sha256(password.encode()).hexdigest()

if "user_role" not in st.session_state:
    st.session_state.user_role = None
    st.session_state.username = None

def login():
    db = Database()
    tab1, tab2 = st.tabs(["Login", "Register (Admin only)"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            user = db.get_user(username)
            if user and pwd_context.verify(password, user['password_hash']):
                st.session_state.user_role = user['role']
                st.session_state.username = username
                st.success(f"Logged in as {username} ({user['role']})")
                st.rerun()
            else:
                st.error("Invalid credentials")

    with tab2:
        if st.session_state.user_role != "admin":
            st.warning("Register only for admins")
        else:
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            role = st.selectbox("Role", ["admin", "analyst"])
            if st.button("Create User"):
                hash_pass = hash_password(new_pass)
                db.create_user(new_user, hash_pass, role)
                st.success("User created")
                st.rerun()

def logout():
    st.session_state.user_role = None
    st.session_state.username = None
    st.rerun()

if st.session_state.user_role is None:
    st.title("🔐 Login Required")
    login()
else:
    st.sidebar.success(f"Logged in as {st.session_state.username} ({st.session_state.user_role})")
    if st.sidebar.button("Logout"):
        logout()
