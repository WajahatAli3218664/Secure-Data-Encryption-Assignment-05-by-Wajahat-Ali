import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
import time

# --- Simplified Constants ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
MAX_ATTEMPTS = 3
MASTER_PASS = os.getenv("MASTER_PASS", "admin123")  # Use environment variable in production

# --- Optimized Helper Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

# Initialize cipher suite
cipher = Fernet(load_key())

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# --- Streamlit UI Configuration ---
st.set_page_config(
    page_title="Secure Vault",
    page_icon="🔒",
    layout="centered"
)

# --- Session Management ---
if "auth" not in st.session_state:
    st.session_state.auth = {
        "is_logged_in": False,
        "failed_attempts": 0,
        "stored_data": load_data()
    }

# --- Authentication ---
def login_page():
    st.title("🔒 Secure Login")
    password = st.text_input("Master Password:", type="password")
    
    if st.button("Login"):
        if password == MASTER_PASS:
            st.session_state.auth.update({
                "is_logged_in": True,
                "failed_attempts": 0
            })
            st.success("Login successful!")
            time.sleep(0.5)
            st.rerun()
        else:
            st.session_state.auth["failed_attempts"] += 1
            attempts_left = MAX_ATTEMPTS - st.session_state.auth["failed_attempts"]
            
            if attempts_left > 0:
                st.error(f"Wrong password! Attempts left: {attempts_left}")
            else:
                st.error("🚫 Account locked. Too many failed attempts.")
                time.sleep(2)
                st.stop()

# --- Main App ---
def main_app():
    st.sidebar.title("🔐 Secure Vault")
    menu = st.sidebar.radio("Menu", ["Home", "Store Data", "Retrieve Data", "Logout"])
    
    if menu == "Home":
        st.title("Secure Data Vault")
        st.write("""
        ### Welcome to your secure data vault!
        Store and retrieve sensitive information with military-grade encryption.
        """)
    
    elif menu == "Store Data":
        st.title("💾 Store Data")
        with st.form("store_form"):
            label = st.text_input("Data Label:")
            data = st.text_area("Data to Encrypt:")
            passkey = st.text_input("Passkey:", type="password")
            
            if st.form_submit_button("Encrypt & Save"):
                if len(label) < 3 or len(passkey) < 8 or not data.strip():
                    st.error("Label (min 3 chars) and Passkey (min 8 chars) required!")
                else:
                    if label in st.session_state.auth["stored_data"]:
                        st.error("Label already exists!")
                    else:
                        st.session_state.auth["stored_data"][label] = {
                            "data": encrypt_data(data),
                            "passkey": hash_passkey(passkey),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        save_data(st.session_state.auth["stored_data"])
                        st.success("✅ Data encrypted and stored!")
    
    elif menu == "Retrieve Data":
        st.title("🔍 Retrieve Data")
        with st.form("retrieve_form"):
            label = st.text_input("Enter Label:")
            passkey = st.text_input("Enter Passkey:", type="password")
            
            if st.form_submit_button("Decrypt"):
                if label in st.session_state.auth["stored_data"]:
                    if hash_passkey(passkey) == st.session_state.auth["stored_data"][label]["passkey"]:
                        decrypted = decrypt_data(st.session_state.auth["stored_data"][label]["data"])
                        st.text_area("Decrypted Data:", decrypted, height=200)
                    else:
                        st.session_state.auth["failed_attempts"] += 1
                        if st.session_state.auth["failed_attempts"] >= MAX_ATTEMPTS:
                            st.session_state.auth["is_logged_in"] = False
                            st.error("Too many attempts! Logging out...")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Wrong passkey!")
                else:
                    st.error("Label not found!")
    
    elif menu == "Logout":
        st.session_state.auth["is_logged_in"] = False
        st.success("Logged out successfully!")
        time.sleep(0.5)
        st.rerun()

# --- Run App ---
if not st.session_state.auth["is_logged_in"]:
    login_page()
else:
    main_app()
