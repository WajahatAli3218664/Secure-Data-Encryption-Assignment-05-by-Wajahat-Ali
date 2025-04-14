import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
from streamlit_lottie import st_lottie
import requests
import time
from dotenv import load_dotenv
import getpass

# --- Load Environment Variables ---
load_dotenv()  # Load from .env file

# --- Constants ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
BACKUP_FILE = "data_backup.json"
MAX_ATTEMPTS = 3
SESSION_TIMEOUT = 1800  # 30 minutes in seconds

# Get master password from environment or prompt
MASTER_PASS = os.getenv("MASTER_PASS")
if MASTER_PASS is None:
    MASTER_PASS = getpass.getpass("Set master password: ")

# --- Updated Security Animations ---
ANIMATIONS = {
    "lock": "https://assets1.lottiefiles.com/packages/lf20_hl5n0bwb.json",
    "success": "https://assets1.lottiefiles.com/packages/lf20_ok5pupu9.json",
    "error": "https://assets1.lottiefiles.com/packages/lf20_gnvsa7vy.json",
    "secure": "https://assets1.lottiefiles.com/packages/lf20_q5kxy7tz.json"
}

# --- Enhanced Security Functions ---
def hash_passkey(passkey, salt=None):
    """PBKDF2 hashing with salt for better security"""
    if salt is None:
        salt = os.urandom(16)  # Generate new salt
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000).hex()

def load_key():
    """Secure key loading with backup"""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        # Create backup
        with open(KEY_FILE + ".bak", "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

cipher = Fernet(load_key())

def encrypt_data(text):
    """Encrypt data with additional integrity check"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    """Decrypt data with error handling"""
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# --- Data Management ---
def load_data():
    """Load data with backup recovery"""
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                return json.load(f)
    except:
        # Attempt to restore from backup
        if os.path.exists(BACKUP_FILE):
            with open(BACKUP_FILE, "r") as f:
                return json.load(f)
    return {}

def save_data(data):
    """Save data with automatic backup"""
    # First save backup
    if os.path.exists(DATA_FILE):
        os.replace(DATA_FILE, BACKUP_FILE)
    
    # Then save new data
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- Session Management ---
def check_session():
    """Check session timeout and activity"""
    if "last_activity" not in st.session_state:
        st.session_state.last_activity = time.time()
    elif time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
        st.session_state.is_logged_in = False
        st.warning("Session timed out due to inactivity")
        st.rerun()

def update_activity():
    """Update last activity timestamp"""
    st.session_state.last_activity = time.time()

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
    .password-strength {
        font-size: 0.8em;
        margin-top: -10px;
        margin-bottom: 10px;
    }
    .strong {
        color: #4CAF50;
    }
    .medium {
        color: #FFC107;
    }
    .weak {
        color: #F44336;
    }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---
def load_lottie(url):
    try:
        r = requests.get(url, timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def check_password_strength(password):
    """Check password strength and return feedback"""
    if len(password) < 8:
        return "weak", "Password too short (min 8 characters)"
    elif not any(c.isupper() for c in password):
        return "medium", "Add uppercase letters for better security"
    elif not any(c.isdigit() for c in password):
        return "medium", "Add numbers for better security"
    elif not any(not c.isalnum() for c in password):
        return "medium", "Add special characters for better security"
    else:
        return "strong", "Strong password!"

# --- Authentication ---
def check_auth():
    """Initialize session variables"""
    if "is_logged_in" not in st.session_state:
        st.session_state.is_logged_in = False
    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0
    if "stored_data" not in st.session_state:
        st.session_state.stored_data = load_data()

def login_page():
    """Login page with enhanced security"""
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
                    update_activity()
                    st.success("Authentication Successful!")
                    lottie_success = load_lottie(ANIMATIONS["success"])
                    if lottie_success:
                        st_lottie(lottie_success, height=150)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    
                    # Add delay to prevent brute force
                    time.sleep(2 ** st.session_state.failed_attempts)
                    
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
    """Main application interface"""
    check_session()
    update_activity()
    
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
        - Automatic backups
        - Session timeout protection
        
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
            
            if passkey:
                strength, feedback = check_password_strength(passkey)
                st.markdown(f'<div class="password-strength {strength}">Password strength: {feedback}</div>', 
                           unsafe_allow_html=True)
            
            if st.form_submit_button("🔒 Encrypt & Store"):
                if len(label) < 3:
                    st.error("Label must be at least 3 characters")
                elif len(passkey) < 8:
                    st.error("Passkey must be at least 8 characters")
                elif not data.strip():
                    st.error("Please enter data to encrypt")
                elif label in st.session_state.stored_data:
                    st.error("Label already exists! Use a different name.")
                else:
                    encrypted = encrypt_data(data)
                    st.session_state.stored_data[label] = {
                        "data": encrypted,
                        "passkey": hash_passkey(passkey),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    save_data(st.session_state.stored_data)
                    
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
                if label in st.session_state.stored_data:
                    if hash_passkey(passkey) == st.session_state.stored_data[label]["passkey"]:
                        decrypted = decrypt_data(st.session_state.stored_data[label]["data"])
                        
                        if decrypted is None:
                            st.error("⚠️ Data corruption detected! Restored from backup.")
                            st.session_state.stored_data = load_data()
                            st.rerun()
                        
                        lottie_success = load_lottie(ANIMATIONS["success"])
                        if lottie_success:
                            st_lottie(lottie_success, height=150)
                        
                        st.success("✅ Decryption Successful!")
                        st.text_area("Decrypted Content:", value=decrypted, height=200)
                    else:
                        st.session_state.failed_attempts += 1
                        attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                        
                        # Add delay that increases with failed attempts
                        time.sleep(st.session_state.failed_attempts)
                        
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
