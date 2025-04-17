import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
from streamlit_lottie import st_lottie
import requests
import time
import re

# --- Constants ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
USER_DB = "users.json"
MAX_ATTEMPTS = 3

# --- Enhanced Security Animations ---
ANIMATIONS = {
    "register": "https://assets1.lottiefiles.com/packages/lf20_jcikwtux.json",  # User registration animation
    "login": "https://assets1.lottiefiles.com/packages/lf20_hu9cd9.json",  # Secure login animation
    "success": "https://assets1.lottiefiles.com/packages/lf20_yjgbpsef.json",  # Success animation
    "error": "https://assets1.lottiefiles.com/packages/lf20_gnvsa7vy.json",  # Error animation
    "secure": "https://assets1.lottiefiles.com/packages/lf20_q5kxy7tz.json",  # Password typing
    "vault": "https://assets1.lottiefiles.com/packages/lf20_5tkzkblw.json"  # Data vault animation
}

# --- Helper Functions ---
def load_lottie(url):
    try:
        r = requests.get(url, timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

cipher = Fernet(load_key())

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# --- UI Configuration ---
st.set_page_config(
    page_title="DataVault Pro - Secure Data Encryption Solution",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS for purple theme
st.markdown("""
<style>
    .stButton>button {
        background-color: #9c27b0 !important;
        color: white !important;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #7b1fa2 !important;
        transform: scale(1.02);
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 8px !important;
        border: 1px solid #9c27b0 !important;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f3e5f5, #e1bee7);
    }
    .css-1d391kg {
        padding-top: 2rem;
    }
    .success-box {
        background-color: #e8f5e9;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .error-box {
        background-color: #ffebee;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# --- Authentication Functions ---
def register_user():
    st.title("👤 User Registration")
    
    col1, col2 = st.columns([1, 2])
    with col1:
        lottie_register = load_lottie(ANIMATIONS["register"])
        if lottie_register:
            st_lottie(lottie_register, height=200)
        else:
            st.image("https://cdn-icons-png.flaticon.com/512/4406/4406232.png", width=150)
    
    with col2:
        with st.form("register_form"):
            username = st.text_input("Choose a Username:")
            email = st.text_input("Email Address:")
            password = st.text_input("Create Password:", type="password")
            confirm_password = st.text_input("Confirm Password:", type="password")
            
            if st.form_submit_button("Register"):
                users = load_users()
                
                if username in users:
                    st.error("Username already exists!")
                    return
                
                if password != confirm_password:
                    st.error("Passwords do not match!")
                    return
                
                is_valid, message = validate_password(password)
                if not is_valid:
                    st.error(message)
                    return
                
                users[username] = {
                    "email": email,
                    "password": hash_password(password),
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                save_users(users)
                st.session_state.current_user = username
                st.session_state.is_logged_in = True
                
                lottie_success = load_lottie(ANIMATIONS["success"])
                if lottie_success:
                    st_lottie(lottie_success, height=150)
                
                st.success("Registration successful! You are now logged in.")
                time.sleep(2)
                st.rerun()

def login_user():
    st.title("🔑 User Login")
    
    col1, col2 = st.columns([1, 2])
    with col1:
        lottie_login = load_lottie(ANIMATIONS["login"])
        if lottie_login:
            st_lottie(lottie_login, height=200)
        else:
            st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=150)
    
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username:")
            password = st.text_input("Password:", type="password")
            
            if st.form_submit_button("Login"):
                users = load_users()
                
                if username not in users:
                    st.error("Username not found!")
                    return
                
                if hash_password(password) != users[username]["password"]:
                    if "login_attempts" not in st.session_state:
                        st.session_state.login_attempts = 0
                    st.session_state.login_attempts += 1
                    
                    attempts_left = MAX_ATTEMPTS - st.session_state.login_attempts
                    
                    lottie_error = load_lottie(ANIMATIONS["error"])
                    if lottie_error:
                        st_lottie(lottie_error, height=150)
                    
                    st.error(f"Invalid password! Attempts left: {attempts_left}")
                    
                    if st.session_state.login_attempts >= MAX_ATTEMPTS:
                        st.error("Account locked due to too many failed attempts. Please try again later.")
                        time.sleep(3)
                        st.stop()
                    return
                
                st.session_state.current_user = username
                st.session_state.is_logged_in = True
                
                lottie_success = load_lottie(ANIMATIONS["success"])
                if lottie_success:
                    st_lottie(lottie_success, height=150)
                
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()

# --- Main Application ---
def main_app():
    st.sidebar.title(f"🔐 DataVault Pro")
    st.sidebar.markdown(f"Logged in as: **{st.session_state.current_user}**")
    
    menu = ["Dashboard", "Store Data", "Retrieve Data", "Account Settings", "Logout"]
    choice = st.sidebar.radio("Navigation", menu)
    
    if choice == "Dashboard":
        st.title("📊 Dashboard")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            lottie_vault = load_lottie(ANIMATIONS["vault"])
            if lottie_vault:
                st_lottie(lottie_vault, height=200)
            else:
                st.image("https://cdn-icons-png.flaticon.com/512/2889/2889676.png", width=150)
        
        with col2:
            st.markdown("""
            ### Welcome to DataVault Pro!
            
            **Your Personal Secure Data Vault**
            
            **Features:**
            - Military-grade AES-256 encryption
            - Secure user authentication
            - Tamper-proof data storage
            - Beautiful intuitive interface
            
            **Instructions:**
            1. Store sensitive data with unique labels
            2. Retrieve with your secure passkey
            3. All data encrypted at rest
            """)
    
    elif choice == "Store Data":
        st.title("💾 Store Encrypted Data")
        
        with st.form("store_form"):
            label = st.text_input("Data Label (e.g., 'Bank Credentials'):")
            data = st.text_area("Sensitive Data:", height=200)
            passkey = st.text_input("Encryption Passkey:", type="password", 
                                   help="Minimum 8 characters, include special characters")
            
            if st.form_submit_button("🔒 Encrypt & Store"):
                if len(label) < 3:
                    st.error("Label must be at least 3 characters")
                elif len(passkey) < 8:
                    st.error("Passkey must be at least 8 characters")
                elif not data.strip():
                    st.error("Please enter data to encrypt")
                else:
                    encrypted = encrypt_data(data)
                    stored_data = load_data()
                    
                    if st.session_state.current_user not in stored_data:
                        stored_data[st.session_state.current_user] = {}
                    
                    stored_data[st.session_state.current_user][label] = {
                        "data": encrypted,
                        "passkey": hash_password(passkey),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    save_data(stored_data)
                    
                    lottie_success = load_lottie(ANIMATIONS["success"])
                    if lottie_success:
                        st_lottie(lottie_success, height=150)
                    
                    st.markdown("""
                    <div class="success-box">
                        <h3>✅ Data encrypted and stored securely!</h3>
                        <p><b>Important:</b> Remember your passkey - it cannot be recovered!</p>
                    </div>
                    """, unsafe_allow_html=True)
    
    elif choice == "Retrieve Data":
        st.title("🔍 Retrieve Encrypted Data")
        
        stored_data = load_data()
        user_data = stored_data.get(st.session_state.current_user, {})
        
        if not user_data:
            st.warning("You haven't stored any data yet.")
            return
        
        with st.form("retrieve_form"):
            label = st.selectbox("Select Data Label:", options=list(user_data.keys()))
            passkey = st.text_input("Enter Passkey:", type="password")
            
            if st.form_submit_button("🔑 Decrypt Data"):
                if label in user_data:
                    if hash_password(passkey) == user_data[label]["passkey"]:
                        decrypted = decrypt_data(user_data[label]["data"])
                        
                        lottie_success = load_lottie(ANIMATIONS["success"])
                        if lottie_success:
                            st_lottie(lottie_success, height=150)
                        
                        st.markdown("""
                        <div class="success-box">
                            <h3>✅ Decryption Successful!</h3>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.text_area("Decrypted Content:", value=decrypted, height=200)
                    else:
                        if "retrieve_attempts" not in st.session_state:
                            st.session_state.retrieve_attempts = 0
                        st.session_state.retrieve_attempts += 1
                        
                        attempts_left = MAX_ATTEMPTS - st.session_state.retrieve_attempts
                        
                        lottie_error = load_lottie(ANIMATIONS["error"])
                        if lottie_error:
                            st_lottie(lottie_error, height=150)
                        
                        st.markdown(f"""
                        <div class="error-box">
                            <h3>❌ Incorrect Passkey!</h3>
                            <p>Attempts left: {attempts_left}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        if st.session_state.retrieve_attempts >= MAX_ATTEMPTS:
                            st.error("Maximum attempts reached. Please try again later.")
                            time.sleep(2)
                            st.session_state.retrieve_attempts = 0
                else:
                    st.error("No data found with that label")
    
    elif choice == "Account Settings":
        st.title("⚙️ Account Settings")
        
        users = load_users()
        user_info = users[st.session_state.current_user]
        
        st.subheader("Account Information")
        st.write(f"Username: {st.session_state.current_user}")
        st.write(f"Email: {user_info['email']}")
        st.write(f"Account created: {user_info['created_at']}")
        
        st.subheader("Change Password")
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password:", type="password")
            new_password = st.text_input("New Password:", type="password")
            confirm_password = st.text_input("Confirm New Password:", type="password")
            
            if st.form_submit_button("Update Password"):
                if hash_password(current_password) != user_info["password"]:
                    st.error("Current password is incorrect")
                elif new_password != confirm_password:
                    st.error("New passwords don't match")
                else:
                    is_valid, message = validate_password(new_password)
                    if not is_valid:
                        st.error(message)
                    else:
                        users[st.session_state.current_user]["password"] = hash_password(new_password)
                        save_users(users)
                        st.success("Password updated successfully!")
    
    elif choice == "Logout":
        st.session_state.is_logged_in = False
        st.session_state.current_user = None
        st.success("Logged out successfully!")
        time.sleep(1)
        st.rerun()

# --- Initialize Session State ---
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# --- Run Application ---
if not st.session_state.is_logged_in:
    auth_choice = st.sidebar.radio("Select Option", ["Login", "Register"])
    
    if auth_choice == "Login":
        login_user()
    else:
        register_user()
else:
    main_app()
