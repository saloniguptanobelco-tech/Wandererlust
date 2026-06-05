import streamlit as st
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib
import pandas as pd
import json
import os
import base64
import io
import secrets
import string

# Define Vault filename
VAULT_FILE = ".vault"

# Set page configuration
st.set_page_config(
    page_title="Wanderlust Diaries | Travel Blog",
    page_icon="🧭",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Initialize Session State variables
if "vault_unlocked" not in st.session_state:
    st.session_state.vault_unlocked = False
if "menu_option" not in st.session_state:
    st.session_state.menu_option = "All Passwords"
if "auto_lock_timeout" not in st.session_state:
    st.session_state.auto_lock_timeout = "5 Minutes"
if "last_activity" not in st.session_state:
    import time
    st.session_state.last_activity = time.time()
if "secret_phrase" not in st.session_state:
    st.session_state.secret_phrase = ""
if "vault_data" not in st.session_state:
    st.session_state.vault_data = {"entries": []}
if "shown_passwords" not in st.session_state:
    st.session_state.shown_passwords = set()
if "editing_entry" not in st.session_state:
    st.session_state.editing_entry = None
if "deleting_entry" not in st.session_state:
    st.session_state.deleting_entry = None
if "copied_password" not in st.session_state:
    st.session_state.copied_password = ""
if "copied_site" not in st.session_state:
    st.session_state.copied_site = ""

# ----------------------------------------------------
# 🔐 Security & Cryptography Helpers
# ----------------------------------------------------
def sha256_hash(phrase: str) -> str:
    """Hash the secret phrase using SHA-256 for fast verification."""
    return hashlib.sha256(phrase.encode('utf-8')).hexdigest()

def derive_key(phrase: str, salt: bytes) -> bytes:
    """Derive a Fernet AES key from the secret phrase using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(phrase.encode('utf-8')))

def init_vault(phrase: str):
    """Create a new local .vault file with salt, phrase hash, and empty entries."""
    salt = os.urandom(16)
    phrase_hash = sha256_hash(phrase)
    key = derive_key(phrase, salt)
    
    # Empty vault entries
    vault_data = {"entries": []}
    f = Fernet(key)
    ciphertext = f.encrypt(json.dumps(vault_data).encode('utf-8'))
    
    payload = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "phrase_hash": phrase_hash,
        "ciphertext": ciphertext.decode('utf-8')
    }
    
    with open(VAULT_FILE, "w") as file:
        json.dump(payload, file)

def verify_phrase(phrase: str) -> bool:
    """Verify if the entered phrase matches the stored hash."""
    if not os.path.exists(VAULT_FILE):
        return False
    try:
        with open(VAULT_FILE, "r") as file:
            payload = json.load(file)
        phrase_hash = sha256_hash(phrase)
        return phrase_hash == payload["phrase_hash"]
    except Exception:
        return False

def decrypt_vault(phrase: str) -> dict:
    """Decrypt the entire vault entries from .vault file."""
    if not os.path.exists(VAULT_FILE):
        return {"entries": []}
    with open(VAULT_FILE, "r") as file:
        payload = json.load(file)
    
    salt = base64.b64decode(payload["salt"].encode('utf-8'))
    ciphertext = payload["ciphertext"].encode('utf-8')
    
    key = derive_key(phrase, salt)
    f = Fernet(key)
    decrypted_bytes = f.decrypt(ciphertext)
    return json.loads(decrypted_bytes.decode('utf-8'))

def save_vault(phrase: str, vault_data: dict):
    """Encrypt and save the updated vault data to the .vault file."""
    if not os.path.exists(VAULT_FILE):
        return
    with open(VAULT_FILE, "r") as file:
        payload = json.load(file)
        
    salt = base64.b64decode(payload["salt"].encode('utf-8'))
    key = derive_key(phrase, salt)
    
    f = Fernet(key)
    ciphertext = f.encrypt(json.dumps(vault_data).encode('utf-8'))
    
    payload["ciphertext"] = ciphertext.decode('utf-8')
    with open(VAULT_FILE, "w") as file:
        json.dump(payload, file)

def check_password_strength(password: str) -> tuple[int, str, str]:
    """Calculate password strength score, label, and color."""
    if not password:
        return 0, "Empty", "#E5E5E5"
    if len(password) < 8:
        return 20, "Weak (Too Short)", "#FF4B4B"
    
    score = 30
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_num = any(c.isdigit() for c in password)
    has_spec = any(not c.isalnum() for c in password)
    
    if has_upper:
        score += 15
    if has_lower:
        score += 15
    if has_num:
        score += 15
    if has_spec:
        score += 15
    if len(password) >= 12:
        score += 10
        
    if score < 60:
        return score, "Weak", "#FF4B4B"
    elif score < 85:
        return score, "Medium", "#FFB703"
    else:
        return score, "Strong", "#00C896"

def lock_vault():
    """Wipe all session state variables and lock the vault."""
    st.session_state.clear()
    st.rerun()

# ----------------------------------------------------
# 🎨 Global Styling (Streamlit Custom Overrides)
# ----------------------------------------------------
def inject_custom_styles(is_dark_theme=False):
    if not is_dark_theme:
        # Decoy Travel Blog Theme (Cream #FAF7F2, Charcoal #2C2C2C, Terracotta #C4622D)
        style_css = """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,300;0,400;0,700;1,300;1,400&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400;1,600&display=swap');
        
        #MainMenu, footer, header, [data-testid="stHeader"] {
            visibility: hidden;
            height: 0;
        }
        
        html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
            background-color: #FAF7F2 !important;
            color: #2C2C2C !important;
            font-family: 'Lato', sans-serif !important;
        }
        
        .block-container {
            padding-top: 20px !important;
            padding-bottom: 50px !important;
            max-width: 1200px !important;
        }
        
        h1, h2, h3, h4, h5, h6 {
            font-family: 'Playfair Display', serif !important;
            color: #2C2C2C !important;
            font-weight: 700;
        }
        
        a {
            text-decoration: none !important;
            color: #C4622D !important;
            transition: color 0.3s ease;
        }
        
        a:hover {
            color: #2C2C2C !important;
        }
        
        /* Sticky top navigation bar */
        .sticky-nav {
            background-color: #ffffff;
            border-bottom: 1px solid #EAE6DF;
            padding: 15px 40px;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.02);
        }
        
        .nav-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .nav-logo {
            font-family: 'Playfair Display', serif;
            font-size: 24px;
            font-weight: 700;
            color: #2C2C2C;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .nav-links {
            display: flex;
            gap: 20px;
        }
        
        .nav-links a {
            font-family: 'Lato', sans-serif;
            color: #555555 !important;
            font-weight: 600;
            font-size: 15px;
        }
        
        .nav-links a:hover {
            color: #C4622D !important;
        }
        
        /* Hero section styling */
        .hero-banner {
            position: relative;
            background-image: linear-gradient(rgba(0,0,0,0.45), rgba(0,0,0,0.45)), url('https://images.unsplash.com/photo-1469854523086-cc02fe5d8800?auto=format&fit=crop&q=80&w=1200');
            background-size: cover;
            background-position: center;
            height: 400px;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            color: white;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .hero-banner h1 {
            color: #ffffff !important;
            font-size: 42px;
            margin-bottom: 12px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.4);
        }
        
        .hero-banner p {
            font-size: 17px;
            max-width: 600px;
            text-shadow: 0 1px 3px rgba(0,0,0,0.4);
            font-weight: 300;
            margin-bottom: 0px;
        }
        
        /* Custom styled input text fields (Search box and Newsletter signup) */
        div[data-testid="stTextInput"] input {
            background-color: #ffffff !important;
            color: #2C2C2C !important;
            border: 1px solid #EAE6DF !important;
            border-radius: 30px !important;
            padding: 10px 20px !important;
            font-size: 15px !important;
            box-shadow: 0 4px 10px rgba(0,0,0,0.03) !important;
            transition: all 0.3s ease !important;
        }
        
        div[data-testid="stTextInput"] input:focus {
            border-color: #C4622D !important;
            box-shadow: 0 4px 12px rgba(196, 98, 45, 0.15) !important;
            outline: none !important;
        }
        
        .search-subtext {
            text-align: center;
            font-size: 12px;
            color: #777777;
            margin-top: -5px;
            margin-bottom: 25px;
        }
        
        .search-subtext i {
            color: #C4622D;
        }
        
        /* Destination cards grid */
        .destination-card {
            background-color: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.03);
            overflow: hidden;
            border: 1px solid #EAE6DF;
            margin-bottom: 25px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            display: flex;
            flex-direction: column;
            height: 440px;
        }
        
        .destination-card:hover {
            transform: translateY(-6px);
            box-shadow: 0 12px 24px rgba(196, 98, 45, 0.12);
        }
        
        .destination-card img {
            width: 100%;
            height: 200px;
            object-fit: cover;
        }
        
        .card-content {
            padding: 18px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            flex-grow: 1;
        }
        
        .card-content h3 {
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 18px;
        }
        
        .card-content p {
            font-size: 13.5px;
            color: #666666;
            line-height: 1.5;
            margin-bottom: 15px;
        }
        
        .read-more-btn {
            color: #C4622D !important;
            font-weight: 700;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: auto;
        }
        
        /* Travel Tips */
        .tip-card {
            background-color: #ffffff;
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.03);
            border: 1px solid #EAE6DF;
            height: 190px;
        }
        
        .tip-icon {
            font-size: 36px;
            margin-bottom: 12px;
        }
        
        .tip-card h4 {
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 17px;
        }
        
        .tip-card p {
            font-size: 13px;
            color: #666666;
            line-height: 1.4;
        }
        
        /* Blog posts cards */
        .blog-card {
            background-color: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.03);
            overflow: hidden;
            border: 1px solid #EAE6DF;
            display: flex;
            flex-direction: column;
            height: 360px;
            transition: transform 0.3s ease;
        }
        
        .blog-card:hover {
            transform: translateY(-4px);
        }
        
        .blog-card img {
            width: 100%;
            height: 150px;
            object-fit: cover;
        }
        
        .blog-card-content {
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            flex-grow: 1;
        }
        
        .blog-card-meta {
            font-size: 11px;
            color: #999999;
            margin-bottom: 6px;
        }
        
        .blog-card-content h4 {
            margin-top: 0;
            margin-bottom: 6px;
            font-size: 16px;
        }
        
        .blog-card-excerpt {
            font-size: 12.5px;
            color: #666666;
            line-height: 1.4;
            margin-bottom: 10px;
        }
        
        .blog-read-more {
            font-size: 12.5px;
            font-weight: 700;
            color: #C4622D !important;
        }
        
        /* Newsletter Banner */
        .newsletter-banner {
            background-color: #FAF7F2;
            border-radius: 12px;
            padding: 35px;
            text-align: center;
            margin: 40px 0;
            border: 2px dashed #C4622D;
        }
        
        .newsletter-banner h3 {
            margin-top: 0;
            margin-bottom: 8px;
            color: #2C2C2C;
        }
        
        .newsletter-banner p {
            font-size: 14px;
            color: #666666;
            margin-bottom: 20px;
        }
        
        /* Streamlit CTA buttons */
        div[data-testid="stButton"] button {
            background-color: #C4622D !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 30px !important;
            padding: 8px 24px !important;
            font-weight: 700 !important;
            font-size: 14px !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 6px rgba(196, 98, 45, 0.15) !important;
        }
        
        div[data-testid="stButton"] button:hover {
            background-color: #2C2C2C !important;
            box-shadow: 0 4px 12px rgba(44, 44, 44, 0.2) !important;
            color: #ffffff !important;
        }
        
        /* Footer */
        .footer-section {
            border-top: 1px solid #EAE6DF;
            padding: 35px 0 20px 0;
            margin-top: 50px;
            text-align: center;
        }
        
        .footer-links {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 12px;
        }
        
        .footer-links a {
            color: #666666 !important;
            font-size: 13.5px;
            font-weight: 500;
        }
        
        .footer-links a:hover {
            color: #C4622D !important;
        }
        
        .footer-copyright {
            font-size: 12.5px;
            color: #999999;
            margin-bottom: 4px;
        }
        
        .footer-tagline {
            font-size: 11.5px;
            color: #C4622D;
            font-weight: 500;
        }
        </style>
        """
        st.markdown(style_css, unsafe_allow_html=True)
    else:
        # Dark Sleek Theme for Hidden Vault Dashboard (#0D1B2A, #1B263B, #00C896)
        style_css = """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,300;0,400;0,700;1,300;1,400&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400;1,600&display=swap');
        
        #MainMenu, footer, header, [data-testid="stHeader"] {
            visibility: hidden;
            height: 0;
        }
        
        html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
            background-color: #0D1B2A !important;
            color: #E0E1DD !important;
            font-family: 'Lato', sans-serif !important;
        }
        
        [data-testid="stSidebar"] {
            background-color: #1B263B !important;
            border-right: 1px solid #415A77 !important;
        }
        
        .block-container {
            padding-top: 30px !important;
            padding-bottom: 50px !important;
            max-width: 1100px !important;
        }
        
        h1, h2, h3, h4, h5, h6, [data-testid="stMarkdownContainer"] h1, [data-testid="stMarkdownContainer"] h2 {
            font-family: 'Playfair Display', serif !important;
            color: #00C896 !important;
            font-weight: 700;
        }
        
        label, p, span, li {
            color: #E0E1DD !important;
        }
        
        a {
            color: #00C896 !important;
            text-decoration: none !important;
        }
        
        a:hover {
            color: #ffffff !important;
        }
        
        /* Styled credentials cards */
        .vault-card {
            background-color: #1B263B;
            border: 1px solid #415A77;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        
        .vault-card:hover {
            transform: translateY(-2px);
            border-color: #00C896;
        }
        
        .badge {
            background-color: #415A77;
            color: #E0E1DD;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11.5px;
            font-weight: 600;
        }
        
        /* Inputs in dark theme */
        div[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea, div[data-testid="stSelectbox"] select {
            background-color: #1B263B !important;
            color: #E0E1DD !important;
            border: 1px solid #415A77 !important;
            border-radius: 6px !important;
        }
        
        div[data-testid="stTextInput"] input:focus, div[data-testid="stTextArea"] textarea:focus {
            border-color: #00C896 !important;
            box-shadow: 0 0 10px rgba(0, 200, 150, 0.2) !important;
            outline: none !important;
        }
        
        /* Selection box overrides */
        [data-baseweb="select"] > div {
            background-color: #1B263B !important;
            color: #E0E1DD !important;
            border-color: #415A77 !important;
        }
        
        /* Dark theme buttons */
        div[data-testid="stButton"] button {
            background-color: #415A77 !important;
            color: #E0E1DD !important;
            border: 1px solid #415A77 !important;
            border-radius: 6px !important;
            padding: 6px 16px !important;
            font-weight: 600 !important;
            font-size: 13.5px !important;
            transition: all 0.2s ease !important;
            box-shadow: none !important;
        }
        
        div[data-testid="stButton"] button:hover {
            background-color: #00C896 !important;
            color: #0D1B2A !important;
            border-color: #00C896 !important;
        }
        
        /* Lock Vault button overrides */
        .lock-btn div[data-testid="stButton"] button {
            background-color: #e63946 !important;
            border-color: #e63946 !important;
            color: white !important;
        }
        
        .lock-btn div[data-testid="stButton"] button:hover {
            background-color: #ff4d6d !important;
            border-color: #ff4d6d !important;
            color: white !important;
        }
        </style>
        """
        st.markdown(style_css, unsafe_allow_html=True)


# ----------------------------------------------------
# 🧾 One-Time Registration Screen
# ----------------------------------------------------
def render_registration_screen():
    # Inject blog decoy styles to get base styling
    inject_custom_styles(is_dark_theme=False)
    
    st.markdown("""
    <style>
    .reg-card {
        background-color: #ffffff;
        border-radius: 16px;
        padding: 40px;
        max-width: 500px;
        margin: 60px auto;
        box-shadow: 0 10px 30px rgba(0,0,0,0.05);
        border: 1px solid #EAE6DF;
        text-align: center;
    }
    .reg-title {
        font-family: 'Playfair Display', serif;
        font-size: 30px;
        font-weight: 700;
        color: #2C2C2C;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
    }
    .reg-subtitle {
        font-size: 14px;
        color: #666666;
        margin-bottom: 30px;
        line-height: 1.5;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="reg-card">
        <div class="reg-title">🔐 SecretVault Setup</div>
        <div class="reg-subtitle">
            Create a master secret phrase to initialize your local encrypted password vault.<br>
            <b>Important:</b> If you lose this phrase, your stored credentials cannot be decrypted or recovered.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Inputs centered on page
    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        phrase = st.text_input("Choose Secret Phrase", type="password", help="Minimum 8 characters.")
        confirm = st.text_input("Confirm Secret Phrase", type="password")
        
        if phrase:
            score, label, color = check_password_strength(phrase)
            st.markdown(f"""
            <div style='margin-bottom: 20px; text-align: left;'>
                <div style='display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;'>
                    <span style='color: #666666;'>Phrase Strength: <b style='color: {color};'>{label}</b></span>
                </div>
                <div style='background-color:#EAE6DF; height:6px; border-radius:3px; overflow:hidden;'>
                    <div style='background-color:{color}; width:{score}%; height:100%; transition: width 0.3s ease;'></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
        if st.button("Initialize Vault & Enter", use_container_width=True):
            if len(phrase) < 8:
                st.error("The secret phrase must be at least 8 characters long.")
            elif phrase != confirm:
                st.error("The secret phrases do not match.")
            else:
                init_vault(phrase)
                st.success("Vault initialized successfully! Redirecting to Wanderlust Diaries travel blog...")
                import time
                time.sleep(1.5)
                st.rerun()


# ----------------------------------------------------
# 🌍 Decoy Travel Blog
# ----------------------------------------------------
def render_travel_blog():
    inject_custom_styles(is_dark_theme=False)
    
    # 1. Header / Navbar
    st.markdown("""
    <div class="sticky-nav">
        <div class="nav-content">
            <div class="nav-logo">
                <span>🧭</span> Wanderlust Diaries
            </div>
            <div class="nav-links">
                <a href="#">Home</a>
                <a href="#">Destinations</a>
                <a href="#">Travel Tips</a>
                <a href="#">Gallery</a>
                <a href="#">About</a>
                <a href="#">Contact</a>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # 2. Hero Section
    st.markdown("""
    <div class="hero-banner">
        <h1>Explore The World, One Story At A Time</h1>
        <p>Handpicked destinations, honest reviews, and travel inspiration since 2018</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Search input (acts as secret vault input)
    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        search_query = st.text_input(
            "Search destinations...",
            placeholder="Search destinations...",
            label_visibility="collapsed",
            key="search_input"
        )
        st.markdown('<div class="search-subtext">Try: <i>Bali, Santorini, Maldives...</i></div>', unsafe_allow_html=True)
        
    # Check if correct phrase is typed in search bar
    if search_query:
        query_clean = search_query.strip()
        if verify_phrase(query_clean):
            # Unlock vault
            st.session_state.vault_unlocked = True
            st.session_state.secret_phrase = query_clean
            st.session_state.vault_data = decrypt_vault(query_clean)
            import time
            st.session_state.last_activity = time.time()
            st.rerun()
            
    # Handle normal search results
    if search_query and not verify_phrase(search_query.strip()):
        query_lower = search_query.lower().strip()
        st.markdown("<h3 style='margin-bottom:15px;'>Search Results</h3>", unsafe_allow_html=True)
        if "bali" in query_lower:
            st.info("🌴 **Bali, Indonesia** - Found 1 article: [Ultimate Guide to Ubud Temples & Beaches (2024)](#)")
        elif "santorini" in query_lower:
            st.info("🇬🇷 **Santorini, Greece** - Found 1 article: [How to Beat the Crowds in Oia for Sunset](#)")
        elif "maldives" in query_lower:
            st.info("🇲🇻 **Maldives** - Found 1 article: [Luxury Overwater Villas on a Budget Guide](#)")
        elif "kyoto" in query_lower:
            st.info("🇯🇵 **Kyoto, Japan** - Found 1 article: [Walkthrough of Fushimi Inari & Arashiyama Bamboo Grove](#)")
        elif "amalfi" in query_lower:
            st.info("🇮🇹 **Amalfi Coast, Italy** - Found 1 article: [Road Trip Planner: Driving the Amalfi Cliffside](#)")
        elif "banff" in query_lower:
            st.info("🇨🇦 **Banff, Canada** - Found 1 article: [Top 5 Hikes around Lake Louise and Moraine Lake](#)")
        elif "rajasthan" in query_lower:
            st.info("🇮🇳 **Rajasthan, India** - Found 1 article: [Palace Hopping in Jaipur, Udaipur & Jaisalmer](#)")
        else:
            st.warning(f"No travel logs found for '{search_query}'. Try searching: 'Bali', 'Santorini', or 'Maldives'.")
            
    st.write(" ")
    st.write(" ")
    
    # 3. Featured Destinations Section
    st.markdown("<h2 style='text-align: center; margin-bottom: 30px;'>Featured Destinations</h2>", unsafe_allow_html=True)
    
    destinations = [
        {
            "name": "Santorini, Greece",
            "flag": "🇬🇷",
            "img": "https://images.unsplash.com/photo-1570077188670-e3a8d69ac5ff?auto=format&fit=crop&q=80&w=400",
            "desc": "A stunning volcanic island in the Aegean Sea, famous for whitewashed buildings and sunset views."
        },
        {
            "name": "Kyoto, Japan",
            "flag": "🇯🇵",
            "img": "https://images.unsplash.com/photo-1493976040374-85c8e12f0c0e?auto=format&fit=crop&q=80&w=400",
            "desc": "Discover ancient temples, traditional wooden houses, and beautiful cherry blossom gardens."
        },
        {
            "name": "Amalfi Coast, Italy",
            "flag": "🇮🇹",
            "img": "https://images.unsplash.com/photo-1533900298318-6b8da08a523e?auto=format&fit=crop&q=80&w=400",
            "desc": "A picturesque stretch of mountainous coastline featuring colorful cliffside fishing villages."
        },
        {
            "name": "Banff, Canada",
            "flag": "🇨🇦",
            "img": "https://images.unsplash.com/photo-1506744038136-46273834b3fb?auto=format&fit=crop&q=80&w=400",
            "desc": "Breathtaking turquoise lakes, soaring peaks, and abundant forest wildlife in the Rockies."
        },
        {
            "name": "Maldives",
            "flag": "🇲🇻",
            "img": "https://images.unsplash.com/photo-1514282401047-d79a71a590e8?auto=format&fit=crop&q=80&w=400",
            "desc": "An archipelago of paradise islands with overwater bungalows and vibrant coral reefs."
        },
        {
            "name": "Rajasthan, India",
            "flag": "🇮🇳",
            "img": "https://images.unsplash.com/photo-1477584322904-48790ee16a6b?auto=format&fit=crop&q=80&w=400",
            "desc": "Explore grand royal palaces, historic desert forts, and rich heritage in the Land of Kings."
        }
    ]
    
    col1, col2, col3 = st.columns(3)
    for idx, dest in enumerate(destinations):
        target_col = col1 if idx % 3 == 0 else (col2 if idx % 3 == 1 else col3)
        with target_col:
            st.markdown(f"""
            <div class="destination-card">
                <img src="{dest['img']}" alt="{dest['name']}">
                <div class="card-content">
                    <h3>{dest['name']} {dest['flag']}</h3>
                    <p>{dest['desc']}</p>
                    <a href="#" class="read-more-btn">Read More →</a>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
    st.write(" ")
    st.write(" ")
    
    # 4. Travel Tips Section
    st.markdown("<h2 style='text-align: center; margin-bottom: 30px;'>Traveler Essentials</h2>", unsafe_allow_html=True)
    tip_col1, tip_col2, tip_col3 = st.columns(3)
    with tip_col1:
        st.markdown("""
        <div class="tip-card">
            <div class="tip-icon">✈️</div>
            <h4>How to find cheap flights</h4>
            <p>Learn the secret strategies to score the best airline deals and travel the world on a budget.</p>
        </div>
        """, unsafe_allow_html=True)
    with tip_col2:
        st.markdown("""
        <div class="tip-card">
            <div class="tip-icon">🎒</div>
            <h4>Ultimate packing checklist</h4>
            <p>A comprehensive packing list to ensure you never leave essential gear behind again.</p>
        </div>
        """, unsafe_allow_html=True)
    with tip_col3:
        st.markdown("""
        <div class="tip-card">
            <div class="tip-icon">🗺️</div>
            <h4>Solo travel safety guide</h4>
            <p>Crucial tips and advice for staying safe, confident, and alert when exploring on your own.</p>
        </div>
        """, unsafe_allow_html=True)
        
    st.write(" ")
    st.write(" ")
    
    # 5. Latest Blog Posts Section
    st.markdown("<h2 style='text-align: center; margin-bottom: 30px;'>Latest From the Blog</h2>", unsafe_allow_html=True)
    post_col1, post_col2, post_col3 = st.columns(3)
    
    posts = [
        {
            "title": "10 Hidden Gems in Southeast Asia",
            "meta": "June 1, 2026 • By Sarah Jenkins",
            "img": "https://images.unsplash.com/photo-1552733407-5d5c46c3bb3b?auto=format&fit=crop&q=80&w=300",
            "excerpt": "Skip the crowded beaches and tourist traps. These ten secret spots in Vietnam, Thailand, and Laos will blow your mind."
        },
        {
            "title": "A Week in Tuscany on a Budget",
            "meta": "May 25, 2026 • By Marco Rossi",
            "img": "https://images.unsplash.com/photo-1523906834658-6e24ef2386f9?auto=format&fit=crop&q=80&w=300",
            "excerpt": "Tuscany doesn't have to break the bank. Here is our complete itinerary for exploring hills and vineyards on €50 a day."
        },
        {
            "title": "Why Patagonia Should Be on Your Bucket List",
            "meta": "May 12, 2026 • By Elena Rostova",
            "img": "https://images.unsplash.com/photo-1517760444937-f6397edcbbcd?auto=format&fit=crop&q=80&w=300",
            "excerpt": "From massive glaciers to towering granite peaks, the wild landscapes of Patagonia offer an adventure of a lifetime."
        }
    ]
    
    with post_col1:
        st.markdown(f"""
        <div class="blog-card">
            <img src="{posts[0]['img']}">
            <div class="blog-card-content">
                <div>
                    <div class="blog-card-meta">{posts[0]['meta']}</div>
                    <h4>{posts[0]['title']}</h4>
                    <p class="blog-card-excerpt">{posts[0]['excerpt']}</p>
                </div>
                <a href="#" class="blog-read-more">Read Excerpt →</a>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with post_col2:
        st.markdown(f"""
        <div class="blog-card">
            <img src="{posts[1]['img']}">
            <div class="blog-card-content">
                <div>
                    <div class="blog-card-meta">{posts[1]['meta']}</div>
                    <h4>{posts[1]['title']}</h4>
                    <p class="blog-card-excerpt">{posts[1]['excerpt']}</p>
                </div>
                <a href="#" class="blog-read-more">Read Excerpt →</a>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with post_col3:
        st.markdown(f"""
        <div class="blog-card">
            <img src="{posts[2]['img']}">
            <div class="blog-card-content">
                <div>
                    <div class="blog-card-meta">{posts[2]['meta']}</div>
                    <h4>{posts[2]['title']}</h4>
                    <p class="blog-card-excerpt">{posts[2]['excerpt']}</p>
                </div>
                <a href="#" class="blog-read-more">Read Excerpt →</a>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    st.write(" ")
    st.write(" ")
    
    # 6. Newsletter Signup (Second secret entry point)
    st.markdown("""
    <div class="newsletter-banner">
        <h3>Get Travel Inspiration In Your Inbox</h3>
        <p>Sign up for our weekly newsletter and receive handpicked itineraries, travel hacks, and exclusive guides.</p>
    </div>
    """, unsafe_allow_html=True)
    
    news_col1, news_col2, news_col3 = st.columns([1, 2, 1])
    with news_col2:
        newsletter_query = st.text_input(
            "Enter your email address",
            placeholder="yourname@example.com",
            label_visibility="collapsed",
            key="newsletter_input"
        )
        
        subscribe_clicked = st.button("Subscribe Now", key="newsletter_submit", use_container_width=True)
        
        if subscribe_clicked or (newsletter_query and st.session_state.newsletter_input):
            email_clean = newsletter_query.strip()
            if verify_phrase(email_clean):
                # Unlock vault
                st.session_state.vault_unlocked = True
                st.session_state.secret_phrase = email_clean
                st.session_state.vault_data = decrypt_vault(email_clean)
                import time
                st.session_state.last_activity = time.time()
                st.rerun()
            elif email_clean:
                # Real decoy response
                st.toast("Thanks for subscribing! Check your inbox for travel inspiration.", icon="📩")
                st.success("Subscribed successfully! Thank you.")
                
    # 7. Footer
    st.markdown("""
    <div class="footer-section">
        <div class="footer-links">
            <a href="#">About</a>
            <a href="#">Privacy Policy</a>
            <a href="#">Contact</a>
            <a href="#">Instagram</a>
            <a href="#">Pinterest</a>
        </div>
        <p class="footer-copyright">© 2024 Wanderlust Diaries. All rights reserved.</p>
        <p class="footer-tagline">Made with ❤️ for travelers everywhere</p>
    </div>
    """, unsafe_allow_html=True)


# ----------------------------------------------------
# 🔓 Vault Interior Dashboard
# ----------------------------------------------------
def render_vault_interior():
    # Inject Vault dark styles
    inject_custom_styles(is_dark_theme=True)
    
    # Check if a temporary menu option redirect was requested
    if "temp_menu_option" in st.session_state:
        st.session_state.menu_option = st.session_state.temp_menu_option
        del st.session_state.temp_menu_option
        
    # Initialize menu_option if not present
    if "menu_option" not in st.session_state:
        st.session_state.menu_option = "All Passwords"
        
    # Calculate Auto-Lock Timeout in milliseconds
    timeout_ms = 0
    selected_timeout = st.session_state.get("auto_lock_timeout", "5 Minutes")
    if selected_timeout == "3 Seconds":
        timeout_ms = 3000
    elif selected_timeout == "1 Minute":
        timeout_ms = 60000
    elif selected_timeout == "5 Minutes":
        timeout_ms = 300000
    elif selected_timeout == "10 Minutes":
        timeout_ms = 600000
        
    # 1. Server-side backup check
    if timeout_ms > 0:
        import time
        now = time.time()
        if "last_activity" in st.session_state:
            elapsed = now - st.session_state.last_activity
            if elapsed > (timeout_ms / 1000.0):
                lock_vault()
        st.session_state.last_activity = now
        
    # 2. Client-side JS check via streamlit components (bypasses Content Security Policies & CORS restrictions)
    if timeout_ms > 0:
        st.components.v1.html(f"""
        <script>
        (function() {{
            let timeout;
            
            function triggerLock() {{
                try {{
                    const parentDoc = window.parent.document;
                    const buttons = parentDoc.querySelectorAll('button');
                    for (const btn of buttons) {{
                        if (btn.textContent && btn.textContent.indexOf('Lock Vault') !== -1) {{
                            btn.click();
                            break;
                        }}
                    }}
                }} catch (e) {{
                    console.error("Auto-lock trigger failed:", e);
                }}
            }}
            
            function resetTimer() {{
                clearTimeout(timeout);
                timeout = setTimeout(triggerLock, {timeout_ms});
            }}
            
            // Register event listeners on parent document (for main app interactions)
            try {{
                const pDoc = window.parent.document;
                pDoc.addEventListener('mousemove', resetTimer, true);
                pDoc.addEventListener('keydown', resetTimer, true);
                pDoc.addEventListener('mousedown', resetTimer, true);
                pDoc.addEventListener('click', resetTimer, true);
                pDoc.addEventListener('touchstart', resetTimer, true);
            }} catch (e) {{
                console.warn("Parent event listeners blocked:", e);
            }}
            
            // Register event listeners on local iframe document (fallback)
            document.addEventListener('mousemove', resetTimer, true);
            document.addEventListener('keydown', resetTimer, true);
            document.addEventListener('mousedown', resetTimer, true);
            document.addEventListener('click', resetTimer, true);
            document.addEventListener('touchstart', resetTimer, true);
            
            // Initialize timer
            resetTimer();
        }})();
        </script>
        """, height=2)
        
    # Top navigation bar inside the main view
    col_nav1, col_nav2, col_nav3, col_nav4 = st.columns([1, 1, 1, 1])
    with col_nav1:
        if st.button("🔑 All Passwords", use_container_width=True, type="primary" if st.session_state.menu_option == "All Passwords" else "secondary"):
            st.session_state.temp_menu_option = "All Passwords"
            st.rerun()
    with col_nav2:
        if st.button("➕ Add Entry", use_container_width=True, type="primary" if st.session_state.menu_option == "Add Entry" else "secondary"):
            st.session_state.temp_menu_option = "Add Entry"
            st.rerun()
    with col_nav3:
        if st.button("📥 Export Vault", use_container_width=True, type="primary" if st.session_state.menu_option == "Export Vault" else "secondary"):
            st.session_state.temp_menu_option = "Export Vault"
            st.rerun()
    with col_nav4:
        if st.button("🔒 Lock Vault", use_container_width=True, type="secondary"):
            lock_vault()
            
    # Auto-Lock settings selectbox inside the main dashboard view (highly visible)
    st.write(" ")
    col_nav_s1, col_nav_s2 = st.columns([3, 1])
    with col_nav_s2:
        timeout_options_list = ["3 Seconds", "1 Minute", "5 Minutes", "10 Minutes", "Never"]
        curr_timeout = st.session_state.get("auto_lock_timeout", "5 Minutes")
        if curr_timeout not in timeout_options_list:
            curr_timeout = "5 Minutes"
        selected_timeout = st.selectbox(
            "⏱ Auto-Lock Inactivity",
            options=timeout_options_list,
            index=timeout_options_list.index(curr_timeout),
            key="auto_lock_select_main"
        )
        if selected_timeout != curr_timeout:
            st.session_state.auto_lock_timeout = selected_timeout
            import time
            st.session_state.last_activity = time.time()
            st.rerun()
            
    # Sidebar
    with st.sidebar:
        st.markdown("## 🔑 SecretVault")
        st.markdown("Secure, local, and AES-256 encrypted password manager.")
        st.write("---")
        
        options_list = ["All Passwords", "Add Entry", "Export Vault"]
        curr_val = st.session_state.get("menu_option", "All Passwords")
        if curr_val not in options_list:
            curr_val = "All Passwords"
        curr_idx = options_list.index(curr_val)
        
        menu_option = st.radio(
            "Vault Operations",
            options=options_list,
            index=curr_idx,
            key="menu_option"
        )
        
        st.write("---")
        st.markdown('<div class="lock-btn">', unsafe_allow_html=True)
        if st.button("🔒 Lock Vault", use_container_width=True, key="sidebar_lock_btn"):
            lock_vault()
        st.markdown('</div>', unsafe_allow_html=True)
        
    # Main Vault content based on menu option
    if menu_option == "All Passwords":
        st.title("🔒 Decrypted Credentials")
        
        # Search & Filter row
        col_s, col_f = st.columns([2, 1])
        with col_s:
            search_q = st.text_input("Search Site/App Name", placeholder="Type site name to search...")
        with col_f:
            cat_filter = st.selectbox("Filter by Category", ["All", "Social", "Banking", "Work", "Shopping", "Other"])
            
        entries = st.session_state.vault_data.get("entries", [])
        
        # Apply filters
        filtered = entries
        if search_q:
            filtered = [e for e in filtered if search_q.lower() in e['site'].lower()]
        if cat_filter != "All":
            filtered = [e for e in filtered if e['category'] == cat_filter]
            
        st.write("---")
        
        if not filtered:
            if not entries:
                st.info("No credentials saved in the vault yet.")
                if st.button("➕ Add your first password entry", use_container_width=True):
                    st.session_state.temp_menu_option = "Add Entry"
                    st.rerun()
            else:
                st.info("No credentials found matching the filters.")
        else:
            # We show entries list
            for entry in filtered:
                entry_id = entry['id']
                
                # Check if we are currently editing this entry
                if st.session_state.editing_entry == entry_id:
                    # Render Inline Edit Form
                    st.markdown(f"### Edit Entry: *{entry['site']}*")
                    
                    edit_site = st.text_input("Site/App Name", value=entry['site'], key=f"e_site_{entry_id}")
                    edit_url = st.text_input("URL (optional)", value=entry['url'], key=f"e_url_{entry_id}")
                    edit_user = st.text_input("Username/Email", value=entry['username'], key=f"e_user_{entry_id}")
                    
                    if "temp_edit_pwd" in st.session_state:
                        st.session_state[f"e_pwd_{entry_id}"] = st.session_state.temp_edit_pwd
                        del st.session_state.temp_edit_pwd
                        
                    col_edit_pwd, col_edit_gen = st.columns([3, 1])
                    with col_edit_pwd:
                        edit_pwd = st.text_input("Password", value=entry['password'], type="password", key=f"e_pwd_{entry_id}")
                    with col_edit_gen:
                        st.write(" ")
                        st.write(" ")
                        if st.button("⚡ Gen New", key=f"e_gen_{entry_id}", use_container_width=True):
                            import secrets
                            import string
                            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                            generated = "".join(secrets.choice(alphabet) for _ in range(16))
                            st.session_state.temp_edit_pwd = generated
                            st.toast("New secure password generated!", icon="⚡")
                            st.rerun()
                    
                    if edit_pwd:
                        score, label, color = check_password_strength(edit_pwd)
                        st.markdown(f"""
                        <div style='margin-bottom: 15px;'>
                            <div style='display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;'>
                                <span>Password Strength: <b style='color:{color};'>{label}</b></span>
                            </div>
                            <div style='background-color:#415A77; height:6px; border-radius:3px; overflow:hidden;'>
                                <div style='background-color:{color}; width:{score}%; height:100%; transition: width 0.3s ease;'></div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                    categories_list = ["Social", "Banking", "Work", "Shopping", "Other"]
                    edit_cat = st.selectbox("Category", categories_list, index=categories_list.index(entry['category']) if entry['category'] in categories_list else 4, key=f"e_cat_{entry_id}")
                    edit_notes = st.text_area("Notes", value=entry['notes'], key=f"e_notes_{entry_id}")
                    
                    col_save, col_cancel = st.columns(2)
                    with col_save:
                        if st.button("Save Changes", key=f"save_btn_{entry_id}", use_container_width=True):
                            if not edit_site or not edit_user or not edit_pwd:
                                st.error("Site name, Username/Email, and Password are required.")
                            else:
                                # Update entry in list
                                entry['site'] = edit_site
                                entry['url'] = edit_url
                                entry['username'] = edit_user
                                entry['password'] = edit_pwd
                                entry['category'] = edit_cat
                                entry['notes'] = edit_notes
                                
                                save_vault(st.session_state.secret_phrase, st.session_state.vault_data)
                                st.session_state.editing_entry = None
                                st.success("Credential updated!")
                                st.rerun()
                                
                    with col_cancel:
                        if st.button("Cancel", key=f"cancel_btn_{entry_id}", use_container_width=True):
                            st.session_state.editing_entry = None
                            st.rerun()
                    st.write("---")
                    
                # Check if we are deleting this entry
                elif st.session_state.deleting_entry == entry_id:
                    st.warning(f"Are you sure you want to permanently delete the entry for **{entry['site']}**?")
                    col_y, col_n = st.columns(2)
                    with col_y:
                        if st.button("Yes, Delete", key=f"conf_del_{entry_id}", use_container_width=True):
                            st.session_state.vault_data['entries'] = [e for e in st.session_state.vault_data['entries'] if e['id'] != entry_id]
                            save_vault(st.session_state.secret_phrase, st.session_state.vault_data)
                            st.session_state.deleting_entry = None
                            st.success("Entry deleted successfully!")
                            st.rerun()
                    with col_n:
                        if st.button("Cancel", key=f"cancel_del_{entry_id}", use_container_width=True):
                            st.session_state.deleting_entry = None
                            st.rerun()
                    st.write("---")
                    
                else:
                    # Normal card layout
                    is_shown = entry_id in st.session_state.shown_passwords
                    pwd_display = entry['password'] if is_shown else "••••••••"
                    
                    # HTML Card wrapper
                    st.markdown(f"""
                    <div class="vault-card">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:20px; font-weight:bold; color:#00C896;">{entry['site']}</span>
                            <span class="badge">{entry['category']}</span>
                        </div>
                        <div style="margin-top:12px; font-size:14px; line-height:1.6;">
                            <div><b>Username/Email:</b> {entry['username']}</div>
                            <div><b>Password:</b> <code style="background-color:#2A3B5C; padding:2px 6px; border-radius:4px; color:#ffffff;">{pwd_display}</code></div>
                            {f"<div><b>URL:</b> <a href='{entry['url']}' target='_blank'>{entry['url']}</a></div>" if entry['url'] else ""}
                            {f"<div><b>Notes:</b> {entry['notes']}</div>" if entry['notes'] else ""}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Action row below card
                    col_show, col_copy, col_edit, col_del = st.columns([1, 1, 1, 1])
                    with col_show:
                        btn_label = "🙈 Hide" if is_shown else "👁 Show"
                        if st.button(btn_label, key=f"show_{entry_id}", use_container_width=True):
                            if is_shown:
                                st.session_state.shown_passwords.remove(entry_id)
                            else:
                                st.session_state.shown_passwords.add(entry_id)
                            st.rerun()
                            
                    with col_copy:
                        if st.button("📋 Copy", key=f"copy_{entry_id}", use_container_width=True):
                            st.session_state.copied_password = entry['password']
                            st.session_state.copied_site = entry['site']
                            st.toast("Password selected! Copy from the box below.", icon="📋")
                            st.rerun()
                            
                    with col_edit:
                        if st.button("✏️ Edit", key=f"edit_{entry_id}", use_container_width=True):
                            st.session_state.editing_entry = entry_id
                            st.rerun()
                            
                    with col_del:
                        if st.button("🗑 Delete", key=f"del_{entry_id}", use_container_width=True):
                            st.session_state.deleting_entry = entry_id
                            st.rerun()
                    
                    # If password selected for copy, show copy box inside card context
                    if st.session_state.copied_password and st.session_state.copied_site == entry['site']:
                        st.code(st.session_state.copied_password, language=None)
                        
                    st.write(" ")
                    st.write(" ")

    elif menu_option == "Add Entry":
        st.title("➕ Add New Credential")
        
        new_site = st.text_input("Site/App Name", placeholder="e.g. Google, Chase Bank")
        new_url = st.text_input("URL (optional)", placeholder="e.g. https://accounts.google.com")
        new_user = st.text_input("Username/Email", placeholder="e.g. john.doe@gmail.com")
        
        if "temp_add_pwd" in st.session_state:
            st.session_state.new_pwd_input = st.session_state.temp_add_pwd
            del st.session_state.temp_add_pwd
            
        col_pwd, col_gen = st.columns([3, 1])
        with col_pwd:
            new_pwd = st.text_input("Password", type="password", key="new_pwd_input")
        with col_gen:
            st.write(" ")
            st.write(" ")
            if st.button("⚡ Generate", use_container_width=True):
                # Generate a secure password and inject it into input state
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                generated = "".join(secrets.choice(alphabet) for _ in range(16))
                st.session_state.temp_add_pwd = generated
                st.toast("Generated secure password!", icon="⚡")
                st.rerun()
                
        # Password strength display
        if new_pwd:
            score, label, color = check_password_strength(new_pwd)
            st.markdown(f"""
            <div style='margin-bottom: 20px;'>
                <div style='display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;'>
                    <span>Password Strength: <b style='color:{color};'>{label}</b></span>
                </div>
                <div style='background-color:#415A77; height:6px; border-radius:3px; overflow:hidden;'>
                    <div style='background-color:{color}; width:{score}%; height:100%; transition: width 0.3s ease;'></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
        new_cat = st.selectbox("Category", ["Social", "Banking", "Work", "Shopping", "Other"])
        new_notes = st.text_area("Notes", placeholder="Any additional notes or security questions...")
        
        if st.button("Save Credential", use_container_width=True):
            if not new_site or not new_user or not new_pwd:
                st.error("Site/App Name, Username/Email, and Password are required fields.")
            else:
                import uuid
                new_id = str(uuid.uuid4())
                
                entry = {
                    "id": new_id,
                    "site": new_site,
                    "url": new_url,
                    "username": new_user,
                    "password": new_pwd,
                    "category": new_cat,
                    "notes": new_notes
                }
                
                st.session_state.vault_data["entries"].append(entry)
                save_vault(st.session_state.secret_phrase, st.session_state.vault_data)
                st.success(f"Credential for **{new_site}** saved successfully!")
                
                # Switch to passwords list and rerun
                st.toast("Entry saved successfully!", icon="✅")
                st.session_state.temp_menu_option = "All Passwords"
                st.rerun()

    elif menu_option == "Export Vault":
        st.title("📥 Export Credentials")
        st.markdown("""
        Export your decrypted credentials list to a clean Excel spreadsheet (.xlsx).
        
        > [!WARNING]
        > The exported Excel file will contain your passwords in plain text. Please ensure you store the downloaded file securely!
        """, unsafe_allow_html=True)
        
        entries = st.session_state.vault_data.get("entries", [])
        
        if not entries:
            st.info("No credentials saved in the vault to export.")
        else:
            df = pd.DataFrame(entries)
            if "id" in df.columns:
                df = df.drop(columns=["id"])
                
            column_mapping = {
                "site": "Site/App Name",
                "url": "URL",
                "username": "Username/Email",
                "password": "Password",
                "category": "Category",
                "notes": "Notes"
            }
            df = df.rename(columns=column_mapping)
            desired_cols = [c for c in column_mapping.values() if c in df.columns]
            df = df[desired_cols]
            
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name="Passwords")
            excel_data = output.getvalue()
            
            st.write("Preview of export list (passwords masked for security):")
            preview_df = df.copy()
            preview_df["Password"] = "••••••••"
            st.dataframe(preview_df, use_container_width=True)
            
            st.download_button(
                label="Download Excel File (.xlsx)",
                data=excel_data,
                file_name="wanderlust_passwords.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )


# ----------------------------------------------------
# 🎛 Main Application Control Flow
# ----------------------------------------------------
if not os.path.exists(VAULT_FILE):
    # Vault file does not exist, trigger setup
    render_registration_screen()
else:
    # Vault exists. Check session state lock/unlock
    if st.session_state.vault_unlocked:
        render_vault_interior()
    else:
        render_travel_blog()
