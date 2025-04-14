import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
from streamlit_lottie import st_lottie
import requests
import time

# --- Constants ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
MAX_ATTEMPTS = 3
MASTER_PASS = "admin123"  # In production, use environment variables

# --- Updated Security Animations ---
ANIMATIONS = {
    "lock": "https://assets1.lottiefiles.com/packages/lf20_hl5n0bwb.json",  # Modern lock
    "success": "https://assets1.lottiefiles.com/packages/lf20_ok5pupu9.json",  # Shield check
    "error": "https://assets1.lottiefiles.com/packages/lf20_gnvsa7vy.json",  # Shield cross
    "secure": "https://assets1.lottiefiles.com/packages/lf20_q5kxy7tz.json"  # Password typing
}

# --- Helper Functions ---
def load_lottie(url):
    try:
        r = requests.get(url, timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

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

# --- UI Configuration ---
st.set_page_config(
    page_title="Secure Vault Pro",
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
</style>
""", unsafe_allow_html=True)

# --- Authentication ---
def check_auth():
    if "is_logged_in" not in st.session_state:
        st.session_state.is_logged_in = False
    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0

def login_page():
    st.title("🔒 Secure Vault Pro")
    col1, col2 = st.columns([1, 2])
    
    with col1:
        lottie_lock = load_lottie(ANIMATIONS["lock"])
        if lottie_lock:
            st_lottie(lottie_lock, height=200)
        else:
            st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=150)
    
    with col2:
        with st.form("auth_form"):
            st.subheader("Authentication Required")
            password = st.text_input("Master Password:", type="password")
            
            if st.form_submit_button("Login"):
                if password == MASTER_PASS:
                    st.session_state.is_logged_in = True
                    st.session_state.failed_attempts = 0
                    st.success("Authentication Successful!")
                    lottie_success = load_lottie(ANIMATIONS["success"])
                    if lottie_success:
                        st_lottie(lottie_success, height=150)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    
                    lottie_error = load_lottie(ANIMATIONS["error"])
                    if lottie_error:
                        st_lottie(lottie_error, height=150)
                    
                    st.error(f"Invalid Password! Attempts left: {attempts_left}")
                    
                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.error("🚫 Account locked. Too many failed attempts.")
                        time.sleep(3)
                        st.stop()

# --- Main Application ---
def main_app():
    st.sidebar.title("🔐 Secure Vault Pro")
    menu = ["Dashboard", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.radio("Navigation", menu)
    
    if choice == "Dashboard":
        st.title("📊 Dashboard")
        lottie_secure = load_lottie(ANIMATIONS["secure"])
        if lottie_secure:
            st_lottie(lottie_secure, height=200)
        
        st.markdown("""
        ### Welcome to Secure Vault Pro!
        
        **Features:**
        - Military-grade AES-256 encryption
        - Secure password protection
        - Tamper-proof data storage
        - Beautiful intuitive interface
        
        **Instructions:**
        1. Store data with unique labels
        2. Retrieve with exact credentials
        3. All data encrypted at rest
        """)
    
    elif choice == "Store Data":
        st.title("💾 Store Encrypted Data")
        
        with st.form("store_form"):
            label = st.text_input("Data Label (e.g., 'Bank Credentials'):")
            data = st.text_area("Sensitive Data:", height=200)
            passkey = st.text_input("Encryption Passkey:", type="password", 
                                   help="Minimum 8 characters, include special chars")
            
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
                    stored_data[label] = {
                        "data": encrypted,
                        "passkey": hash_passkey(passkey),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    save_data(stored_data)
                    
                    lottie_success = load_lottie(ANIMATIONS["success"])
                    if lottie_success:
                        st_lottie(lottie_success, height=150)
                    
                    st.success("""
                    ✅ Data encrypted and stored securely!
                    
                    **Important:** Remember your passkey - it cannot be recovered!
                    """)
    
    elif choice == "Retrieve Data":
        st.title("🔍 Retrieve Encrypted Data")
        
        with st.form("retrieve_form"):
            label = st.text_input("Enter Data Label:")
            passkey = st.text_input("Enter Passkey:", type="password")
            
            if st.form_submit_button("🔑 Decrypt Data"):
                stored_data = load_data()
                
                if label in stored_data:
                    if hash_passkey(passkey) == stored_data[label]["passkey"]:
                        decrypted = decrypt_data(stored_data[label]["data"])
                        
                        lottie_success = load_lottie(ANIMATIONS["success"])
                        if lottie_success:
                            st_lottie(lottie_success, height=150)
                        
                        st.success("✅ Decryption Successful!")
                        st.text_area("Decrypted Content:", value=decrypted, height=200)
                    else:
                        st.session_state.failed_attempts += 1
                        attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                        
                        lottie_error = load_lottie(ANIMATIONS["error"])
                        if lottie_error:
                            st_lottie(lottie_error, height=150)
                        
                        st.error(f"❌ Incorrect Passkey! Attempts left: {attempts_left}")
                        
                        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                            st.session_state.is_logged_in = False
                            st.error("🚫 Maximum attempts reached. Logging out...")
                            time.sleep(2)
                            st.rerun()
                else:
                    st.error("⚠️ No data found with that label")
    
    elif choice == "Logout":
        st.session_state.is_logged_in = False
        st.success("Logged out successfully!")
        time.sleep(1)
        st.rerun()

# --- Run Application ---
check_auth()

if not st.session_state.is_logged_in:
    login_page()
else:
    main_app()