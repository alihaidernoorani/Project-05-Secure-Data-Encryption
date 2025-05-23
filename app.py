import streamlit as st
import hashlib
from cryptography.fernet import Fernet

st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔐",    
    layout="centered" 
)

# =======================
# In-Memory Database
# =======================
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# =======================
# Generate Encryption Key
# =======================
if "cipher" not in st.session_state:
    key = Fernet.generate_key()
    st.session_state.cipher = Fernet(key)

cipher = st.session_state.cipher

# =======================
# Helper Functions
# =======================
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# =======================
# Streamlit UI
# =======================
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Secret", "Retrieve Secret", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# -----------------------
# HOME PAGE
# -----------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# -----------------------
# STORE SECRET
# -----------------------
elif choice == "Store Secret":
    st.subheader("📂 Store New Secret")

    label = st.text_input("Label (Unique ID): ")
    secret = st.text_area("Enter Secret:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and secret and passkey:
            if label in st.session_state.stored_data:
                st.error("❌ Label already exists. Please choose a unique one.")
            else:
                encrypted = encrypt_data(secret)
                hashed_key = hash_passkey(passkey)
                st.session_state.stored_data[label] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed_key
                }
                st.success("✅ Secret encrypted and stored securely!")
        else:
            st.warning("⚠️ All fields are required!")

# -----------------------
# RETRIEVE SECRET
# -----------------------
elif choice == "Retrieve Secret":
    st.subheader("🔍 Retrieve Your Secret")

    label = st.text_input("Enter Label (Unique ID):")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            entry = st.session_state.stored_data.get(label)
            if entry:
                hashed_input = hash_passkey(passkey)
                if hashed_input == entry["passkey"]:
                    decrypted = decrypt_data(entry["encrypted_text"])
                    st.session_state.failed_attempts = 0
                    st.success(f"✅ Your secret: {decrypted}")
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Label not found.")

            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                st.experimental_rerun()
        else:
            st.error("⚠️ All fields are required!")

# -----------------------
# LOGIN TO RESET
# -----------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # In production, hash this too!
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")
