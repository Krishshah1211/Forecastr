import os
import re
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, time as dtime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from datetime import timezone, timedelta
    class ZoneInfo:
        def __init__(self, key):
            self.tz = timezone(timedelta(hours=5, minutes=30))
        def utcoffset(self, dt):
            return timedelta(hours=5, minutes=30)
        def tzname(self, dt):
            return "IST"
        def dst(self, dt):
            return timedelta(0)

import requests
import streamlit as st
import yfinance as yf
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from bs4 import BeautifulSoup

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# ====================================================
# 1. DATABASE & PERMANENT USER PERSISTENCE VAULT
# ====================================================
DB_URL = None
try:
    if "DATABASE_URL" in st.secrets:
        DB_URL = st.secrets["DATABASE_URL"]
except Exception:
    pass

IS_POSTGRES = DB_URL is not None and DB_URL.startswith("postgres")

if IS_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor

BACKUP_VAULT_FILE = "users_registry.json"

def get_db_connection():
    if IS_POSTGRES:
        return psycopg2.connect(DB_URL, sslmode="require")
    else:
        return sqlite3.connect("users_vault.db", check_same_thread=False)

def hash_secret(secret_str: str, salt: str = None) -> tuple:
    if not salt:
        salt = os.urandom(16).hex()
    hashed = hashlib.sha256((secret_str + salt).encode('utf-8')).hexdigest()
    return hashed, salt

def save_to_backup_vault(username, salt, pwd_hash, mpin_hash, user_data):
    vault = {}
    if os.path.exists(BACKUP_VAULT_FILE):
        try:
            with open(BACKUP_VAULT_FILE, "r") as f:
                vault = json.load(f)
        except Exception:
            vault = {}
    vault[username.lower()] = {
        "salt": salt,
        "password_hash": pwd_hash,
        "mpin_hash": mpin_hash,
        "user_data": user_data
    }
    try:
        with open(BACKUP_VAULT_FILE, "w") as f:
            json.dump(vault, f)
    except Exception:
        pass

def restore_from_backup_vault(conn):
    if not os.path.exists(BACKUP_VAULT_FILE):
        return
    try:
        with open(BACKUP_VAULT_FILE, "r") as f:
            vault = json.load(f)
        c = conn.cursor()
        for u, d in vault.items():
            query = "SELECT id FROM users WHERE username = %s" if IS_POSTGRES else "SELECT id FROM users WHERE username = ?"
            c.execute(query, (u,))
            if not c.fetchone():
                ins = (
                    "INSERT INTO users (username, salt, password_hash, mpin_hash, user_data) VALUES (%s, %s, %s, %s, %s)"
                    if IS_POSTGRES else
                    "INSERT INTO users (username, salt, password_hash, mpin_hash, user_data) VALUES (?, ?, ?, ?, ?)"
                )
                c.execute(ins, (u, d["salt"], d["password_hash"], d["mpin_hash"], json.dumps(d.get("user_data", {}))))
        conn.commit()
    except Exception:
        pass

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    if IS_POSTGRES:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                salt VARCHAR(100) NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                mpin_hash VARCHAR(256),
                session_token VARCHAR(256),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_data TEXT
            );
            CREATE TABLE IF NOT EXISTS stock_universe (
                symbol VARCHAR(50) PRIMARY KEY,
                company_name TEXT,
                exchange VARCHAR(10) DEFAULT 'NSE'
            );
        """)
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mpin_hash VARCHAR(256);")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS session_token VARCHAR(256);")
        conn.commit()
    else:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                mpin_hash TEXT,
                session_token TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_data TEXT
            );
            CREATE TABLE IF NOT EXISTS stock_universe (
                symbol TEXT PRIMARY KEY,
                company_name TEXT,
                exchange TEXT DEFAULT 'NSE'
            );
        """)
        try:
            c.execute("ALTER TABLE users ADD COLUMN mpin_hash TEXT;")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE users ADD COLUMN session_token TEXT;")
        except Exception:
            pass
        conn.commit()

    DEV_USER = "admin"
    DEV_PASS = "Admin@1234"
    DEV_MPIN = "1234"
    
    query = "SELECT id FROM users WHERE username = %s" if IS_POSTGRES else "SELECT id FROM users WHERE username = ?"
    c.execute(query, (DEV_USER,))
    if not c.fetchone():
        salt = os.urandom(16).hex()
        pwd_hash = hashlib.sha256((DEV_PASS + salt).encode('utf-8')).hexdigest()
        mpin_h = hashlib.sha256((DEV_MPIN + salt).encode('utf-8')).hexdigest()
        dev_data = json.dumps({"role": "developer", "watchlist": ["RELIANCE", "VADILALIND", "HDFCBANK"], "searches": []})
        insert_query = (
            "INSERT INTO users (username, salt, password_hash, mpin_hash, user_data) VALUES (%s, %s, %s, %s, %s)" 
            if IS_POSTGRES else 
            "INSERT INTO users (username, salt, password_hash, mpin_hash, user_data) VALUES (?, ?, ?, ?, ?)"
        )
        c.execute(insert_query, (DEV_USER, salt, pwd_hash, mpin_h, dev_data))
        conn.commit()
        save_to_backup_vault(DEV_USER, salt, pwd_hash, mpin_h, json.loads(dev_data))

    restore_from_backup_vault(conn)
    conn.close()

init_db()

def create_user_session(username: str) -> str:
    token = secrets.token_hex(32)
    conn = get_db_connection()
    c = conn.cursor()
    q = "UPDATE users SET session_token = %s, last_login = CURRENT_TIMESTAMP WHERE username = %s" if IS_POSTGRES else "UPDATE users SET session_token = ?, last_login = CURRENT_TIMESTAMP WHERE username = ?"
    c.execute(q, (token, username.strip().lower()))
    conn.commit()
    conn.close()
    return token

def verify_session_token(token: str) -> tuple:
    if not token or len(token) < 20:
        return False, None, None
    conn = get_db_connection()
    c = conn.cursor()
    q = "SELECT username, user_data FROM users WHERE session_token = %s" if IS_POSTGRES else "SELECT username, user_data FROM users WHERE session_token = ?"
    c.execute(q, (token,))
    row = c.fetchone()
    conn.close()
    if row:
        u_name, raw_data = row[0], row[1]
        return True, u_name, json.loads(raw_data) if raw_data else {}
    return False, None, None

def clear_user_session(username: str):
    conn = get_db_connection()
    c = conn.cursor()
    q = (
        "UPDATE users SET session_token = NULL WHERE username = %s" 
        if IS_POSTGRES else 
        "UPDATE users SET session_token = NULL WHERE username = ?"
    )
    c.execute(q, (username.strip().lower(),))
    conn.commit()
    conn.close()

def register_user(username: str, password: str, mpin: str = "1234") -> tuple:
    init_db()
    u_clean = username.strip().lower()
    if " " in u_clean or re.search(r'\s', u_clean):
        return False, "Username cannot contain spaces."
    if " " in password or re.search(r'\s', password):
        return False, "Password cannot contain spaces."
    if not re.match(r'^\d{4}$', str(mpin).strip()):
        return False, "MPIN must be exactly 4 digits."
    
    if len(u_clean) < 3:
        return False, "Username must be at least 3 characters."
    if len(password.strip()) < 6:
        return False, "Password must be at least 6 characters."
    
    conn = get_db_connection()
    c = conn.cursor()
    pwd_hash, salt = hash_secret(password)
    mpin_hash, _ = hash_secret(str(mpin).strip(), salt)
    default_data = json.dumps({"role": "trader", "watchlist": ["RELIANCE", "VADILALIND", "HDFCBANK"], "searches": []})
    try:
        query = (
            "INSERT INTO users (username, salt, password_hash, mpin_hash, user_data) VALUES (%s, %s, %s, %s, %s)" 
            if IS_POSTGRES else 
            "INSERT INTO users (username, salt, password_hash, mpin_hash, user_data) VALUES (?, ?, ?, ?, ?)"
        )
        c.execute(query, (u_clean, salt, pwd_hash, mpin_hash, default_data))
        conn.commit()
        conn.close()
        save_to_backup_vault(u_clean, salt, pwd_hash, mpin_hash, json.loads(default_data))
        return True, "Account registered! You can now log in with MPIN or Password."
    except Exception:
        conn.close()
        return False, "Username already exists or database connection failed."

def verify_user_mpin(username: str, mpin: str) -> tuple:
    init_db()
    u_clean = username.strip().lower()
    if not re.match(r'^\d{4}$', str(mpin).strip()):
        return False, None, "MPIN must be exactly 4 digits."

    conn = get_db_connection()
    c = conn.cursor()
    query = "SELECT id, salt, mpin_hash, user_data FROM users WHERE username = %s" if IS_POSTGRES else "SELECT id, salt, mpin_hash, user_data FROM users WHERE username = ?"
    c.execute(query, (u_clean,))
    row = c.fetchone()
    
    if not row and os.path.exists(BACKUP_VAULT_FILE):
        restore_from_backup_vault(conn)
        c.execute(query, (u_clean,))
        row = c.fetchone()

    if not row:
        conn.close()
        return False, None, "Username not found. Please register or check spelling."
    
    user_id, salt, stored_mpin_h, raw_data = row[0], row[1], row[2], row[3]
    if not stored_mpin_h:
        conn.close()
        return False, None, "MPIN not configured. Log in with password and set MPIN."
    
    calc_h, _ = hash_secret(str(mpin).strip(), salt)
    if calc_h == stored_mpin_h:
        update_q = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s" if IS_POSTGRES else "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?"
        c.execute(update_q, (user_id,))
        conn.commit()
        conn.close()
        return True, json.loads(raw_data) if raw_data else {}, "Login successful."
    else:
        conn.close()
        return False, None, "Incorrect 4-Digit MPIN."

def verify_user_password(username: str, password: str) -> tuple:
    init_db()
    u_clean = username.strip().lower()
    if " " in u_clean or re.search(r'\s', u_clean):
        return False, None, "Username cannot contain spaces."
    if " " in password or re.search(r'\s', password):
        return False, None, "Password cannot contain spaces."

    conn = get_db_connection()
    c = conn.cursor()
    query = "SELECT id, salt, password_hash, user_data FROM users WHERE username = %s" if IS_POSTGRES else "SELECT id, salt, password_hash, user_data FROM users WHERE username = ?"
    c.execute(query, (u_clean,))
    row = c.fetchone()
    
    if not row and os.path.exists(BACKUP_VAULT_FILE):
        restore_from_backup_vault(conn)
        c.execute(query, (u_clean,))
        row = c.fetchone()

    if not row:
        conn.close()
        return False, None, "Username not found. Please register."
    
    user_id, salt, stored_hash, raw_data = row[0], row[1], row[2], row[3]
    calc_hash, _ = hash_secret(password, salt)
    if calc_hash == stored_hash:
        update_q = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s" if IS_POSTGRES else "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?"
        c.execute(update_q, (user_id,))
        conn.commit()
        conn.close()
        return True, json.loads(raw_data) if raw_data else {}, "Login successful."
    else:
        conn.close()
        return False, None, "Incorrect password."

def update_user_mpin(username: str, new_mpin: str) -> tuple:
    init_db()
    u_clean = username.strip().lower()
    if not re.match(r'^\d{4}$', str(new_mpin).strip()):
        return False, "MPIN must be exactly 4 digits."
    conn = get_db_connection()
    c = conn.cursor()
    query = "SELECT salt, password_hash, user_data FROM users WHERE username = %s" if IS_POSTGRES else "SELECT salt, password_hash, user_data FROM users WHERE username = ?"
    c.execute(query, (u_clean,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "User not found."
    
    salt, pwd_hash, raw_data = row[0], row[1], row[2]
    new_h, _ = hash_secret(str(new_mpin).strip(), salt)
    up_q = "UPDATE users SET mpin_hash = %s WHERE username = %s" if IS_POSTGRES else "UPDATE users SET mpin_hash = ? WHERE username = ?"
    c.execute(up_q, (new_h, u_clean))
    conn.commit()
    conn.close()
    save_to_backup_vault(u_clean, salt, pwd_hash, new_h, json.loads(raw_data) if raw_data else {})
    return True, "4-Digit MPIN updated successfully!"

def update_user_password(username: str, old_pass: str, new_pass: str) -> tuple:
    init_db()
    u_clean = username.strip().lower()
    if " " in new_pass or re.search(r'\s', new_pass):
        return False, "New password cannot contain spaces."
    if len(new_pass.strip()) < 6:
        return False, "New password must be at least 6 characters."

    conn = get_db_connection()
    c = conn.cursor()
    query = "SELECT salt, password_hash, mpin_hash, user_data FROM users WHERE username = %s" if IS_POSTGRES else "SELECT salt, password_hash, mpin_hash, user_data FROM users WHERE username = ?"
    c.execute(query, (u_clean,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "User not found."
    
    salt, stored_hash, mpin_h, raw_data = row[0], row[1], row[2], row[3]
    calc_hash, _ = hash_secret(old_pass, salt)
    if calc_hash != stored_hash:
        conn.close()
        return False, "Old password verification failed."
    
    new_hash, new_salt = hash_secret(new_pass)
    up_q = "UPDATE users SET salt = %s, password_hash = %s WHERE username = %s" if IS_POSTGRES else "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?"
    c.execute(up_q, (new_salt, new_hash, u_clean))
    conn.commit()
    conn.close()
    save_to_backup_vault(u_clean, new_salt, new_hash, mpin_h, json.loads(raw_data) if raw_data else {})
    return True, "Password updated successfully!"

def save_user_data(username: str, data_dict: dict):
    init_db()
    u_clean = username.strip().lower()
    conn = get_db_connection()
    c = conn.cursor()
    up_q = "UPDATE users SET user_data = %s WHERE username = %s" if IS_POSTGRES else "UPDATE users SET user_data = ? WHERE username = ?"
    c.execute(up_q, (json.dumps(data_dict), u_clean))
    conn.commit()
    
    query = "SELECT salt, password_hash, mpin_hash FROM users WHERE username = %s" if IS_POSTGRES else "SELECT salt, password_hash, mpin_hash FROM users WHERE username = ?"
    c.execute(query, (u_clean,))
    row = c.fetchone()
    conn.close()
    if row:
        save_to_backup_vault(u_clean, row[0], row[1], row[2], data_dict)

# ====================================================
# 2. MARKET CALENDAR & COUNTDOWN ENGINE
# ====================================================
NSE_HOLIDAYS_2026 = {
    "2026-01-26": "Republic Day",
    "2026-03-03": "Holi",
    "2026-03-26": "Shri Ram Navami",
    "2026-03-31": "Shri Mahavir Jayanti",
    "2026-04-03": "Good Friday",
    "2026-04-14": "Dr. Ambedkar Jayanti",
    "2026-05-01": "Maharashtra Day",
    "2026-05-28": "Bakri Id (Eid ul-Adha)",
    "2026-06-26": "Muharram",
    "2026-09-14": "Ganesh Chaturthi",
    "2026-10-02": "Mahatma Gandhi Jayanti",
    "2026-10-20": "Dussehra",
    "2026-11-10": "Diwali-Balipratipada",
    "2026-11-24": "Guru Nanak Jayanti",
    "2026-12-25": "Christmas"
}

def get_market_calendar_status():
    ist = ZoneInfo('Asia/Kolkata')
    now_ist = datetime.now(ist)
    date_str = now_ist.strftime("%Y-%m-%d")
    weekday = now_ist.weekday()
    curr_time = now_ist.time()

    t_pre_open = dtime(9, 0)
    t_open = dtime(9, 15)
    t_closing_soon = dtime(15, 0)
    t_close = dtime(15, 30)
    t_post_close = dtime(16, 0)

    if weekday in (5, 6):
        day_name = "Saturday" if weekday == 5 else "Sunday"
        return {
            "status": "CLOSED",
            "badge": f"🔴 MARKET CLOSED ({day_name})",
            "message": "Opens Monday at 09:15 AM IST",
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }

    if date_str in NSE_HOLIDAYS_2026:
        h_name = NSE_HOLIDAYS_2026[date_str]
        return {
            "status": "CLOSED",
            "badge": f"🔴 MARKET CLOSED ({h_name})",
            "message": "Exchange Holiday • Normal Trading Resumes Next Business Day",
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }

    if curr_time < t_pre_open:
        diff_sec = int((datetime.combine(now_ist.date(), t_open, ist) - now_ist).total_seconds())
        mins, secs = divmod(diff_sec, 60)
        return {
            "status": "PRE_SESSION",
            "badge": f"⚪ PRE-MARKET (Opens in {mins:02d}m {secs:02d}s)",
            "message": "Normal trading starts at 09:15 AM IST",
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }
    elif t_pre_open <= curr_time < t_open:
        return {
            "status": "PRE_OPEN",
            "badge": "🟡 PRE-OPEN DISCOVERY (09:00 - 09:15)",
            "message": "Order Matching in progress • Market opens at 09:15 AM",
            "is_open": False,
            "closing_soon": False,
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }
    elif t_open <= curr_time < t_closing_soon:
        return {
            "status": "OPEN",
            "badge": "🟢 MARKET OPEN (Normal Trading)",
            "message": "Continuous Order Execution Active",
            "is_open": True,
            "closing_soon": False,
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }
    elif t_closing_soon <= curr_time < t_close:
        diff_sec = int((datetime.combine(now_ist.date(), t_close, ist) - now_ist).total_seconds())
        mins, secs = divmod(diff_sec, 60)
        return {
            "status": "CLOSING_SOON",
            "badge": f"⚠️ MARKET CLOSING IN {mins:02d}m {secs:02d}s",
            "message": "Square off intraday positions before 03:30 PM",
            "is_open": True,
            "closing_soon": True,
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }
    elif t_close <= curr_time < t_post_close:
        return {
            "status": "POST_CLOSE",
            "badge": "🟡 POST-CLOSING SESSION (03:30 - 04:00)",
            "message": "Closing price determination & AMO window",
            "is_open": False,
            "closing_soon": False,
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }
    else:
        return {
            "status": "CLOSED",
            "badge": "🔴 MARKET CLOSED",
            "message": "Regular trading closed for the day • Opens 09:15 AM next business day",
            "is_open": False,
            "closing_soon": False,
            "time_str": now_ist.strftime("%I:%M:%S %p IST")
        }

# ====================================================
# 3. PAGE CONFIG & RESPONSIVE THEME
# ====================================================
st.set_page_config(
    page_title="Forecastr | Institutional Market Terminal",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@500;600;700&display=swap');
    
    :root {
        --bg-main: #0B0E14;
        --bg-card: #121620;
        --border-subtle: rgba(255, 255, 255, 0.08);
        --groww-green: #00D09C;
        --kite-red: #DF514C;
        --text-primary: #F1F5F9;
        --text-secondary: #94A3B8;
    }

    .stApp {
        background-color: var(--bg-main) !important;
        color: var(--text-primary) !important;
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    h1, h2, h3, h4, p, label, .stMarkdown {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
    }

    code, .stCode, .mono { 
        font-family: 'JetBrains Mono', monospace !important; 
    }

    [data-testid="stIcon"],
    [data-testid="stExpanderToggleIcon"],
    span[class*="material-symbols"],
    span[class*="icon"],
    button[aria-label*="password"],
    button[aria-label*="Password"] {
        font-family: inherit !important;
    }

    header[data-testid="stHeader"],
    [data-testid="stHeaderActionElements"],
    div[data-testid="StyledLinkIconContainer"],
    a.anchor-link,
    h1 a, h2 a, h3 a, h4 a, h5 a, h6 a {
        display: none !important;
        visibility: hidden !important;
    }

    div[data-testid="stVerticalBlock"] > div:empty { display: none !important; }
    div[data-testid="stMarkdownContainer"]:empty { display: none !important; }
    div[data-testid="element-container"]:empty { display: none !important; }

    .block-container {
        padding: 0.8rem 1rem 2rem 1rem !important;
        max-width: 100% !important;
    }

    .market-status-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: #121620;
        border: 1px solid var(--border-subtle);
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        margin-bottom: 8px;
    }

    div[data-testid="stMetric"] {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 10px 14px;
    }
    div[data-testid="stMetricLabel"] {
        color: var(--text-secondary) !important;
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
    }
    div[data-testid="stMetricValue"] {
        color: #FFFFFF !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.15rem !important;
        font-weight: 700 !important;
    }

    div.stButton > button {
        background: var(--bg-card);
        color: var(--text-primary);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        font-weight: 600;
        font-size: 13px;
        min-height: 42px;
    }
    div.stButton > button[kind="primary"] {
        background: #00D09C !important;
        color: #071510 !important;
        border: none !important;
        font-weight: 700 !important;
    }

    div.stButton > button p {
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.25 !important;
        text-align: center !important;
        font-size: 11px !important;
    }
    div.stButton > button p strong {
        display: block !important;
        font-size: 13px !important;
        color: #FFFFFF !important;
    }

    @keyframes glowGreenTick {
        0% { border-color: #00D09C !important; background-color: rgba(0, 208, 156, 0.2) !important; }
        100% { border-color: var(--border-subtle) !important; background-color: var(--bg-card) !important; }
    }
    @keyframes glowRedTick {
        0% { border-color: #DF514C !important; background-color: rgba(223, 81, 76, 0.2) !important; }
        100% { border-color: var(--border-subtle) !important; background-color: var(--bg-card) !important; }
    }

    div.glow-up > div.stButton > button {
        animation: glowGreenTick 1.2s ease-out !important;
    }
    div.glow-down > div.stButton > button {
        animation: glowRedTick 1.2s ease-out !important;
    }

    .pulse-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 20px 0;
        margin: 10px 0;
        background: #121620;
        border-radius: 12px;
        border: 1px solid rgba(0, 208, 156, 0.2);
    }
    .stock-loader-svg { width: 100%; max-width: 260px; height: 65px; }
    .chart-glow-path {
        fill: none; stroke: #00D09C; stroke-width: 3.5; stroke-linecap: round; stroke-linejoin: round;
        stroke-dasharray: 600; stroke-dashoffset: 600;
        animation: chartPulse 1.8s ease-in-out infinite;
    }
    .chart-glow-path-bg { fill: none; stroke: rgba(255, 255, 255, 0.05); stroke-width: 2; }
    @keyframes chartPulse {
        0% { stroke-dashoffset: 600; opacity: 0.2; }
        50% { stroke-dashoffset: 0; opacity: 1; }
        100% { stroke-dashoffset: -600; opacity: 0.2; }
    }
    .loading-ticker-text {
        color: #94a3b8; font-size: 11px; font-weight: 600; letter-spacing: 0.5px;
        margin-top: 8px; text-transform: uppercase;
    }
</style>

<script>
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        return false;
    }, { capture: true });

    document.addEventListener('keydown', function(e) {
        if (e.keyCode === 123) {
            e.preventDefault(); e.stopPropagation(); return false;
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.keyCode === 73 || e.key === 'I' || e.key === 'i')) {
            e.preventDefault(); e.stopPropagation(); return false;
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.keyCode === 74 || e.key === 'J' || e.key === 'j')) {
            e.preventDefault(); e.stopPropagation(); return false;
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.keyCode === 67 || e.key === 'C' || e.key === 'c')) {
            e.preventDefault(); e.stopPropagation(); return false;
        }
        if ((e.ctrlKey || e.metaKey) && (e.keyCode === 85 || e.key === 'U' || e.key === 'u')) {
            e.preventDefault(); e.stopPropagation(); return false;
        }
    }, { capture: true });
</script>
""", unsafe_allow_html=True)

def render_brand_logo(size=30):
    svg_badge = (
        f'<svg width="{size}" height="{size}" viewBox="0 0 38 38" fill="none" style="vertical-align: middle;">'
        f'<rect width="38" height="38" rx="10" fill="#0E1424" stroke="rgba(255,255,255,0.08)" stroke-width="1.5"/>'
        f'<line x1="11" y1="9" x2="11" y2="29" stroke="#00D09C" stroke-width="1.5" stroke-linecap="round"/>'
        f'<rect x="9" y="14" width="4" height="10" rx="1" fill="#00D09C"/>'
        f'<line x1="19" y1="12" x2="19" y2="28" stroke="#ef4444" stroke-width="1.5" stroke-linecap="round"/>'
        f'<rect x="17" y="17" width="4" height="7" rx="1" fill="#ef4444"/>'
        f'<line x1="27" y1="6" x2="27" y2="31" stroke="#00D09C" stroke-width="1.5" stroke-linecap="round"/>'
        f'<rect x="25" y="10" width="4" height="15" rx="1" fill="#00D09C"/>'
        f'</svg>'
    )
    return (
        f'<div style="display: inline-flex; align-items: center; gap: 8px;">'
        f'{svg_badge}'
        f'<span style="font-size: {size-4}px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.6px;">'
        f'Forecastr<span style="color: #00D09C;">.</span>'
        f'</span>'
        f'</div>'
    )

# ====================================================
# AUTO-LOGIN & SESSION VERIFICATION
# ====================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = ""
if "user_profile" not in st.session_state:
    st.session_state.user_profile = {}
if "current_tab" not in st.session_state:
    st.session_state.current_tab = "universal"
if "universal_query" not in st.session_state:
    st.session_state.universal_query = "RELIANCE"
if "intraday_query" not in st.session_state:
    st.session_state.intraday_query = "RELIANCE"
if "ipo_filter" not in st.session_state:
    st.session_state.ipo_filter = ""
if "ipo_category_filter" not in st.session_state:
    st.session_state.ipo_category_filter = "All"
if "auto_refresh_enabled" not in st.session_state:
    st.session_state.auto_refresh_enabled = True
if "auto_refresh_sec" not in st.session_state:
    st.session_state.auto_refresh_sec = 30
if "prev_benchmark_prices" not in st.session_state:
    st.session_state.prev_benchmark_prices = {}

if st.query_params.get("logout") == "true":
    del st.query_params["logout"]
    if "auth_token" in st.query_params:
        del st.query_params["auth_token"]
    st.session_state.authenticated = False
    st.session_state.current_user = ""
    st.session_state.user_profile = {}

if not st.session_state.authenticated:
    url_token = st.query_params.get("auth_token", None)
    if url_token:
        valid_sess, sess_user, sess_profile = verify_session_token(url_token)
        if valid_sess:
            st.session_state.authenticated = True
            st.session_state.current_user = sess_user
            st.session_state.user_profile = sess_profile

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}

def show_stock_graph_loader(stock_name: str = "ORDER BOOK"):
    loader_html = f"""
    <div class="pulse-container">
        <svg class="stock-loader-svg" viewBox="0 0 300 100">
            <path class="chart-glow-path-bg" d="M 0,60 L 40,60 L 60,35 L 85,75 L 115,20 L 145,65 L 175,45 L 205,80 L 235,15 L 265,50 L 300,50" />
            <path class="chart-glow-path" d="M 0,60 L 40,60 L 60,35 L 85,75 L 115,20 L 145,65 L 175,45 L 205,80 L 235,15 L 265,50 L 300,50" />
        </svg>
        <div class="loading-ticker-text">Scanning Exchange Order Books • {stock_name}</div>
    </div>
    """
    return st.empty().markdown(loader_html, unsafe_allow_html=True)

# ====================================================
# STATUTORY DISCLAIMER DIALOG & CAUTION BAR
# ====================================================
@st.dialog("⚖️ Statutory Disclaimer & Risk Disclosure")
def open_legal_dialog():
    st.markdown("""
    #### 1. Non-Advisory & Non-SEBI Registration
    This software (**Forecastr**) is exclusively an educational and quantitative calculation tool. **It is NOT registered as an Investment Adviser or Research Analyst under SEBI Regulations.** 

    #### 2. Deterministic Mathematical Sandbox
    All price projections, target prices, volatility stops, and Camarilla coordinates are automated calculations based on historical trade ranges. They do **NOT** evaluate human psychology, breaking news, macroeconomic shifts, or black-swan occurrences.

    #### 3. Complete Release of Liability
    Trading in equities and derivatives involves severe financial risk. Users accept **100% individual responsibility** for their capital. The creators and developers accept **ZERO liability** for any financial gains or losses.
    """)
    if st.button("I Understand", type="primary", use_container_width=True):
        st.rerun()

def render_caution_bar():
    st.markdown("---")
    c1, c2 = st.columns([5, 1.2])
    with c1:
        st.markdown(
            "<p style='color: #64748b; font-size: 11px; margin-top: 6px; line-height: 1.4;'>"
            "⚠️ <b>Caution:</b> Projections and Camarilla levels are mathematical algorithmic calculations only. Equity investments are subject to market risks. Not financial advice."
            "</p>",
            unsafe_allow_html=True
        )
    with c2:
        if st.button("Read More", key="btn_read_more_legal", use_container_width=True):
            open_legal_dialog()

# ====================================================
# 4. CLEAN & RESPONSIVE AUTHENTICATION SCREEN
# ====================================================
if not st.session_state.authenticated:
    st.write("")
    st.markdown(
        f"<div style='text-align:center; margin-bottom:16px;'>"
        f"{render_brand_logo(size=36)}"
        f"<p style='color:#64748b; font-size:12px; margin-top:4px;'>Quantitative Equities & Market Terminal</p>"
        f"</div>",
        unsafe_allow_html=True
    )

    _, center_col, _ = st.columns([1, 1.8, 1])
    with center_col:
        tab_mpin, tab_pwd, tab_register = st.tabs(["⚡ Fast MPIN", "🔐 Password", "✨ New Account"])
        
        with tab_mpin:
            with st.form("clean_mpin_form"):
                m_user = st.text_input("Username", placeholder="e.g. admin", key="mpin_u")
                m_pin = st.text_input("4-Digit MPIN", type="password", max_chars=4, placeholder="••••", key="mpin_p")
                st.write("")
                submit_mpin = st.form_submit_button("Instant Unlock →", type="primary", use_container_width=True)
                if submit_mpin:
                    ok, u_data, msg = verify_user_mpin(m_user, m_pin)
                    if ok:
                        token = create_user_session(m_user)
                        st.query_params["auth_token"] = token
                        st.session_state.authenticated = True
                        st.session_state.current_user = m_user.strip().lower()
                        st.session_state.user_profile = u_data
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")

        with tab_pwd:
            with st.form("clean_login_form"):
                l_user = st.text_input("Username", placeholder="Enter username", key="pwd_u")
                l_pass = st.text_input("Password", type="password", placeholder="Enter password", key="pwd_p")
                st.write("")
                submit_login = st.form_submit_button("Sign In with Password →", type="primary", use_container_width=True)
                if submit_login:
                    ok, u_data, msg = verify_user_password(l_user, l_pass)
                    if ok:
                        token = create_user_session(l_user)
                        st.query_params["auth_token"] = token
                        st.session_state.authenticated = True
                        st.session_state.current_user = l_user.strip().lower()
                        st.session_state.user_profile = u_data
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")

        with tab_register:
            with st.form("clean_register_form"):
                r_user = st.text_input("Username", placeholder="Choose username")
                r_pass = st.text_input("Password", type="password", placeholder="Choose master password")
                r_conf = st.text_input("Confirm Password", type="password", placeholder="Confirm master password")
                r_mpin = st.text_input("Set 4-Digit MPIN", type="password", max_chars=4, placeholder="e.g. 5678")
                st.write("")
                submit_reg = st.form_submit_button("Create Account & Setup MPIN", type="primary", use_container_width=True)
                if submit_reg:
                    if r_pass != r_conf:
                        st.error("❌ Passwords do not match.")
                    else:
                        ok, msg = register_user(r_user, r_pass, r_mpin)
                        if ok:
                            st.success(f"✅ {msg}")
                        else:
                            st.error(f"❌ {msg}")

    render_caution_bar()
    st.stop()

# ====================================================
# 5. PROFILE DIALOG (FIXED CLEAN UI)
# ====================================================
@st.dialog("👤 Account Profile & Settings")
def open_profile_dropdown():
    user = st.session_state.current_user
    
    st.markdown(
        f"<div style='background:#121620; padding:12px; border-radius:10px; border:1px solid rgba(255,255,255,0.08); margin-bottom:12px;'>"
        f"<span style='color:#94a3b8; font-size:11px; text-transform:uppercase;'>Active Account</span>"
        f"<h3 style='margin:4px 0 0 0; color:#00D09C;'>{user.upper()}</h3>"
        f"</div>",
        unsafe_allow_html=True
    )

    with st.expander("Update 4-Digit Fast MPIN", expanded=True):
        new_pin = st.text_input("New 4-Digit MPIN", type="password", max_chars=4, placeholder="e.g. 1234", key="diag_mpin_input")
        if st.button("Save New MPIN", key="btn_save_mpin_diag", use_container_width=True):
            ok, msg = update_user_mpin(user, new_pin)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

    with st.expander("Change Master Password", expanded=False):
        old_p = st.text_input("Current Password", type="password", key="diag_old_pass")
        new_p = st.text_input("New Password", type="password", key="diag_new_pass")
        if st.button("Update Password", key="btn_save_pwd_diag", use_container_width=True):
            ok, msg = update_user_password(user, old_p, new_pass=new_p)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

    st.markdown("---")
    if st.button("Logout from Terminal", type="primary", use_container_width=True):
        if user:
            clear_user_session(user)
        if "auth_token" in st.query_params:
            del st.query_params["auth_token"]
        st.query_params["logout"] = "true"
        st.session_state.authenticated = False
        st.session_state.current_user = ""
        st.session_state.user_profile = {}
        st.rerun()

# ====================================================
# TAB 1: UNIVERSAL STOCK ANALYZER (SINGLE UNIFIED SEARCH)
# ====================================================
if st.session_state.current_tab == "universal":
    c_input, c_btn = st.columns([5, 1])
    with c_input:
        unified_query = st.selectbox(
            "Search Any Indian Stock (Type symbol or company name):",
            options=all_suggestions,
            index=None,
            placeholder="Type any stock, SME or symbol (e.g. Vadilal, Reliance, Hyundai, Suzlon)...",
            label_visibility="collapsed",
            key="universal_unified_search_bar"
        )
    with c_btn:
        submitted = st.button("🚀 Analyze", type="primary", use_container_width=True)

    if submitted and unified_query:
        st.session_state.universal_query = unified_query
        clean_code = unified_query.split("—")[0].strip().upper() if "—" in unified_query else unified_query.strip().upper()
        if "searches" not in st.session_state.user_profile:
            st.session_state.user_profile["searches"] = []
        if clean_code not in st.session_state.user_profile["searches"]:
            st.session_state.user_profile["searches"].append(clean_code)
            save_user_data(st.session_state.current_user, st.session_state.user_profile)

    # Benchmark Watchlist Chips
    bench_keys = ["RELIANCE", "VADILALIND", "HDFCBANK", "TATAMOTORS", "HYUNDAI", "INFY"]
    bench_data = fetch_benchmark_snapshots(bench_keys)

    q1, q2, q3, q4, q5, q6 = st.columns(6)
    quick_stocks = [
        ("RELIANCE", "Reliance Ind.", q1),
        ("VADILALIND", "Vadilal Ind.", q2),
        ("HDFCBANK", "HDFC Bank", q3),
        ("TATAMOTORS", "Tata Motors", q4),
        ("HYUNDAI", "Hyundai Motor", q5),
        ("INFY", "Infosys", q6)
    ]

    for sym, name, col in quick_stocks:
        s_data = bench_data.get(sym, {"price": 0.0, "pct": 0.0})
        curr_p = s_data["price"]
        pct = s_data["pct"]
        prev_p = st.session_state.prev_benchmark_prices.get(sym, curr_p)

        if curr_p > prev_p:
            glow_class = "glow-up"
        elif curr_p < prev_p:
            glow_class = "glow-down"
        else:
            glow_class = "glow-up" if pct >= 0 else "glow-down"

        st.session_state.prev_benchmark_prices[sym] = curr_p

        sign = "+" if pct >= 0 else ""
        badge_symbol = "🟢" if pct >= 0 else "🔴"
        button_label = f"**{sym}**\n\n{badge_symbol} {sign}{pct:.2f}%"

        with col:
            st.markdown(f"<div class='{glow_class}'>", unsafe_allow_html=True)
            if st.button(button_label, key=f"quick_btn_{sym}", use_container_width=True):
                st.session_state.universal_query = sym
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    if st.session_state.universal_query:
        meta = resolve_symbol_from_selection(st.session_state.universal_query)
        
        loader_slot = show_stock_graph_loader(meta['name'])
        live_price, df_daily, _, live_vol, bid_ask = fetch_bulletproof_market_data(meta["symbol"], meta.get("bse", ""))
        fundamentals = fetch_screener_metrics(meta["symbol"])
        headlines, sent_score, sent_label = fetch_live_stock_news_and_sentiment(meta["symbol"], meta["name"])
        loader_slot.empty()

        quant_res = calculate_swing_quant_math(df_daily, live_price, fundamentals, sent_score, live_vol, bid_ask)

        col_stitle, col_walrt = st.columns([4, 1.8])
        with col_stitle:
            st.markdown(f"## 📌 {meta['name']} <span style='font-size: 15px; color: #64748b;'>(NSE/BSE: {meta['symbol']})</span>", unsafe_allow_html=True)
        with col_walrt:
            if st.button("🔔 Alert Trade", use_container_width=True):
                st.toast(f"Trade projection updated for {meta['name']} (₹{live_price})", icon="⚡")

        m1, m2, m3, m4 = st.columns(4)
        pct_move = round(((quant_res['target'] - live_price) / live_price) * 100, 2)
        m1.metric("Live Market Price", f"₹{live_price}")
        delta_label = f"{pct_move:+}% Calculated Upside" if quant_res["signal_type"] == "BULLISH" else f"{pct_move:+}% Downside Target"
        delta_color = "normal" if quant_res["signal_type"] == "BULLISH" else "inverse"
        m2.metric("Target Estimate (Math)", f"₹{quant_res['target']}", delta=delta_label, delta_color=delta_color)
        m3.metric("Protective Stop Level", f"₹{quant_res['stop']}")
        m4.metric("Mathematical Stance", quant_res['stance'], delta=f"{quant_res['confidence']}% Conviction", delta_color=delta_color)

        st.markdown("---")

        st.markdown("#### ⚡ Real-Time Volume & Order Flow Dynamics")
        v1, v2, v3 = st.columns(3)
        v1.metric("Live Traded Volume", f"{live_vol:,} shares", delta=f"{quant_res['vol_surge_mult']}x vs 20-Day Avg")
        v2.metric("Buy vs Sell Pressure Ratio", f"{bid_ask}:1", delta="Buyer Dominance" if bid_ask >= 1.0 else "Seller Liquidation", delta_color="normal" if bid_ask >= 1.0 else "inverse")
        v3.metric("14-Day ATR Noise Boundary", f"₹{round(quant_res['atr'], 2)}", delta="Normal Movement Range")

        st.markdown("---")

        st.markdown(f"#### 📰 Live News Sentiment & Catalysts • <span style='color:#38bdf8;'>{sent_label}</span>", unsafe_allow_html=True)
        col_n1, col_n2 = st.columns([3, 1])
        with col_n1:
            for h in headlines:
                st.markdown(f"• {h}")
        with col_n2:
            st.metric("News Sentiment Score", f"{sent_score:+}/100", delta="Live News Flow", delta_color="normal" if sent_score >= 0 else "inverse")

        st.markdown("---")

        if not df_daily.empty:
            st.markdown("#### 📊 Dynamic Real-Time Price Action & EMA Boundaries")
            fig = go.Figure()
            bars = df_daily.tail(120)
            fig.add_trace(go.Candlestick(
                x=bars.index, open=bars['Open'], high=bars['High'],
                low=bars['Low'], close=bars['Close'],
                name="OHLC", increasing_line_color='#00D09C', decreasing_line_color='#ef4444'
            ))
            fig.add_hline(y=quant_res['target'], line_dash="dash", line_color="#00D09C" if quant_res["signal_type"] == "BULLISH" else "#ef4444", annotation_text="Target")
            fig.add_hline(y=quant_res['stop'], line_dash="dash", line_color="#ef4444" if quant_res["signal_type"] == "BULLISH" else "#00D09C", annotation_text="Stop")
            fig.update_layout(height=420, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", xaxis_rangeslider_visible=False)
            st.plotly_chart(fig, use_container_width=True)

        c_fund, c_rat = st.columns(2)
        with c_fund:
            with st.container(border=True):
                st.markdown("#### 🏢 Audited Fundamentals & Indicators")
                st.write(f"• **14-Day RSI:** `{quant_res['rsi']}` ({'Overbought' if quant_res['rsi'] > 70 else ('Oversold' if quant_res['rsi'] < 30 else 'Neutral')})")
                st.write(f"• **20-Day EMA:** `₹{quant_res['ema_20']}`")
                st.write(f"• **50-Day EMA:** `₹{quant_res['ema_50']}`")
                st.write(f"• **Stock P/E:** {fundamentals.get('pe', 'N/A')}")
                st.write(f"• **ROCE:** {fundamentals.get('roce', 'N/A')}%")

        with c_rat:
            with st.container(border=True):
                st.markdown("#### 📐 Algorithmic Synthesis & Market Stance")
                st.write(quant_res['thesis'])
                st.write(f"• **Market Trend Status:** `{'BULLISH MOMENTUM' if quant_res['signal_type'] == 'BULLISH' else 'BEARISH DISTRIBUTION'}`")
                st.write(f"• **Volume Surge Factor:** `{quant_res['vol_surge_mult']}x relative to 20-day mean`")

    render_caution_bar()

# ====================================================
# TAB 2: DEDICATED INTRADAY DESK (SINGLE UNIFIED SEARCH)
# ====================================================
elif st.session_state.current_tab == "intraday":
    col_iinput, col_ibtn = st.columns([5, 1])
    with col_iinput:
        selected_intra = st.selectbox(
            "Search Intraday Stock:",
            options=all_suggestions,
            index=None,
            placeholder="Type symbol or company name (e.g. Vadilal, Reliance, Tata Motors)...",
            label_visibility="collapsed",
            key="intraday_unified_search_bar"
        )
    with col_ibtn:
        scan_submitted = st.button("⚡ Scan", type="primary", use_container_width=True)

    if scan_submitted and selected_intra:
        st.session_state.intraday_query = selected_intra

    if st.session_state.intraday_query:
        meta = resolve_symbol_from_selection(st.session_state.intraday_query)
        
        loader_slot = show_stock_graph_loader(meta['name'])
        live_price, df_daily, df_5m, live_vol, bid_ask = fetch_bulletproof_market_data(meta["symbol"], meta.get("bse", ""))
        headlines, sent_score, _ = fetch_live_stock_news_and_sentiment(meta["symbol"], meta["name"])
        loader_slot.empty()

        imath = calculate_live_intraday_forecast(df_5m, df_daily, live_price, bid_ask, sent_score)

        st.markdown(f"## ⚡ {meta['name']} <span style='font-size: 15px; color: #64748b;'>(NSE: {meta['symbol']})</span>", unsafe_allow_html=True)

        with st.container(border=True):
            st.markdown(f"### 🎯 Continuous Intraday Day Forecast • <span style='color: #00D09C;'>{imath['action']}</span>", unsafe_allow_html=True)
            st.write(f"**Algorithmic Outlook for Today:** {imath['forecast_today']}")
            st.caption("Continuously recalculated using Live 5-minute ticks, order book flow, and breaking sentiment.")

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Live Market Price", f"₹{live_price}")
        k2.metric("Intraday Signal", imath["action"], delta=f"{imath['confidence']}% Confidence", delta_color="normal" if "BUY" in imath["action"] else "inverse")
        k3.metric("Entry Level", f"₹{imath['entry']}", delta=f"Stop: ₹{imath['stop']}", delta_color="inverse")
        k4.metric("Take Profit Target", f"₹{imath['target']}", delta="R:R 1:2.4")

        st.markdown("---")

        c_play, c_lev = st.columns(2)
        with c_play:
            with st.container(border=True):
                st.markdown("#### 🎯 Execution Playbook & Triggers")
                st.write(f"• **Trigger:** {imath['rule']}")
                st.write(f"• **Order Book Pressure:** `{bid_ask}:1 ratio`")
                st.write(f"• **H4 Breakout Threshold:** `₹{imath['h4']}`")
                st.write(f"• **L4 Breakdown Threshold:** `₹{imath['l4']}`")

        with c_lev:
            with st.container(border=True):
                st.markdown("#### 📐 Key Mathematical Levels")
                st.write(f"• **Session VWAP:** `₹{imath['vwap']}`")
                st.write(f"• **Take Profit Target:** `₹{imath['target']}`")
                st.write(f"• **Protective Stop:** `₹{imath['stop']}`")

        if not df_5m.empty:
            st.markdown("#### 📊 5-Minute Moving Chart")
            fig = go.Figure()
            bars = df_5m.tail(60)
            fig.add_trace(go.Candlestick(
                x=bars.index, open=bars['Open'], high=bars['High'],
                low=bars['Low'], close=bars['Close'],
                name="5m", increasing_line_color='#00D09C', decreasing_line_color='#ef4444'
            ))
            fig.add_hline(y=imath['h4'], line_dash="dash", line_color="#00D09C", annotation_text="H4 Breakout")
            fig.add_hline(y=imath['vwap'], line_dash="dot", line_color="#38bdf8", annotation_text="VWAP")
            fig.add_hline(y=imath['l4'], line_dash="dash", line_color="#ef4444", annotation_text="L4 Breakdown")
            fig.update_layout(height=400, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", xaxis_rangeslider_visible=False)
            st.plotly_chart(fig, use_container_width=True)

    render_caution_bar()

# ====================================================
# TAB 3: DEDICATED IPO & GMP RADAR
# ====================================================
elif st.session_state.current_tab == "ipo":
    col_itop1, col_itop2 = st.columns([4, 1.5])
    with col_itop1:
        st.markdown("### 🚀 Live Mainboard & SME IPO Radar")
    with col_itop2:
        if st.button("🔄 Force Sync Live Data", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    df_ipo = fetch_live_ipos_tri_source()

    total_mainboard = len(df_ipo[df_ipo["Category"] == "Mainboard"])
    total_sme = len(df_ipo[df_ipo["Category"] == "SME"])
    active_bidding = len(df_ipo[df_ipo["Current Status"].str.contains("Open|Bidding", case=False, na=False)])

    i1, i2, i3 = st.columns(3)
    i1.metric("Mainboard Issues", f"{total_mainboard} Listed", delta="Regular Exchange")
    i2.metric("SME Issues", f"{total_sme} Listed", delta="Emerging Growth")
    i3.metric("Bidding Active", f"{active_bidding} Live IPOs", delta="Real-Time")

    st.markdown("---")

    col_iposearch, col_cat = st.columns([3.5, 2.5])
    with col_iposearch:
        st.session_state.ipo_filter = st.text_input(
            "Filter IPO by Name:",
            value=st.session_state.ipo_filter,
            placeholder="Type name to filter (e.g. Shah, Orient, German, SRIT)...",
            label_visibility="collapsed"
        )
    with col_cat:
        category_choice = st.radio(
            "Category Filter:",
            ["All", "Mainboard", "SME"],
            horizontal=True,
            label_visibility="collapsed"
        )

    filtered_df = df_ipo.copy()
    if category_choice != "All":
        filtered_df = filtered_df[filtered_df["Category"] == category_choice]
    if st.session_state.ipo_filter:
        filtered_df = df_ipo[df_ipo.apply(lambda row: st.session_state.ipo_filter.lower() in str(row).lower(), axis=1)]

    st.dataframe(filtered_df, use_container_width=True, hide_index=True)
    render_caution_bar()
