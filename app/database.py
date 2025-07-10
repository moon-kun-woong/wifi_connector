import sqlite3
from typing import Generator
import os
from dotenv import load_dotenv

load_dotenv()

DB_FILE = os.getenv('DB_FILE', 'app.db')

INIT_DB_SQL = """
CREATE TABLE IF NOT EXISTS wifi_auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT NOT NULL,
    is_authenticated INTEGER DEFAULT 0,
    mac_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wifi_auth_id INTEGER NOT NULL,
    auth_code TEXT NOT NULL,
    is_used INTEGER DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (wifi_auth_id) REFERENCES wifi_auth(id)
);

CREATE INDEX IF NOT EXISTS idx_wifi_auth_phone ON wifi_auth (phone_number);
CREATE INDEX IF NOT EXISTS idx_wifi_auth_mac ON wifi_auth (mac_address);
CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON auth_codes (auth_code);
"""

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_connection()
    conn.executescript(INIT_DB_SQL)
    conn.close()

def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = get_connection()
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
init_db()
