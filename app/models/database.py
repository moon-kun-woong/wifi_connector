import sqlite3
from typing import Generator
import os
from dotenv import load_dotenv

load_dotenv()

DB_FILE = os.getenv('DB_FILE', 'app.db')

INIT_DB_SQL = """
-- 사용자 인증 정보 테이블
CREATE TABLE IF NOT EXISTS wifi_auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT NOT NULL,
    is_authenticated INTEGER DEFAULT 0,
    mac_address TEXT,
    ip_address TEXT,
    user_agent TEXT,
    device_name TEXT,
    auth_expires_at TIMESTAMP,  -- 인증 만료 시간 (1일)
    last_activity_at TIMESTAMP, -- 마지막 활동 시간
    is_blocked INTEGER DEFAULT 0, -- 차단 여부
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_completed_at TIMESTAMP
);

-- 인증 코드 테이블
CREATE TABLE IF NOT EXISTS auth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wifi_auth_id INTEGER NOT NULL,
    auth_code TEXT NOT NULL,
    is_used INTEGER DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (wifi_auth_id) REFERENCES wifi_auth(id)
);

-- 네트워크 세션 관리 테이블
CREATE TABLE IF NOT EXISTS network_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wifi_auth_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    bytes_uploaded INTEGER DEFAULT 0,
    bytes_downloaded INTEGER DEFAULT 0,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    FOREIGN KEY (wifi_auth_id) REFERENCES wifi_auth(id)
);

-- 차단된 번호/MAC 주소 관리 테이블
CREATE TABLE IF NOT EXISTS blocked_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT,
    mac_address TEXT,
    ip_address TEXT,
    block_reason TEXT,
    blocked_by TEXT DEFAULT 'system',
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- 허용된 번호/MAC 주소 화이트리스트 테이블
CREATE TABLE IF NOT EXISTS whitelisted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT,
    mac_address TEXT,
    device_name TEXT,
    added_by TEXT DEFAULT 'admin',
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- 관리자 계정 테이블
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    is_active INTEGER DEFAULT 1,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 시스템 로그 테이블
CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_level TEXT NOT NULL, -- INFO, WARNING, ERROR
    category TEXT NOT NULL,  -- AUTH, NETWORK, ADMIN, SMS
    message TEXT NOT NULL,
    phone_number TEXT,
    mac_address TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_wifi_auth_phone ON wifi_auth (phone_number);
CREATE INDEX IF NOT EXISTS idx_wifi_auth_mac ON wifi_auth (mac_address);
CREATE INDEX IF NOT EXISTS idx_wifi_auth_expires ON wifi_auth (auth_expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON auth_codes (auth_code);
CREATE INDEX IF NOT EXISTS idx_network_sessions_token ON network_sessions (session_token);
CREATE INDEX IF NOT EXISTS idx_network_sessions_active ON network_sessions (is_active);
CREATE INDEX IF NOT EXISTS idx_blocked_devices_phone ON blocked_devices (phone_number);
CREATE INDEX IF NOT EXISTS idx_blocked_devices_mac ON blocked_devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_whitelisted_devices_phone ON whitelisted_devices (phone_number);
CREATE INDEX IF NOT EXISTS idx_whitelisted_devices_mac ON whitelisted_devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_system_logs_category ON system_logs (category);
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs (created_at);
"""

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_connection()
    conn.executescript(INIT_DB_SQL)
    
    # 기본 관리자 계정 생성
    from ..admin.admin_service import ensure_default_admin
    ensure_default_admin(conn)
    
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
