import logging
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from ..models import schemas

logger = logging.getLogger(__name__)

def row_to_dict(row) -> Dict[str, Any]:
    """SQLite Row 객체를 딕셔너리로 변환"""
    if not row:
        return {}
    return {key: str(value) if key == 'created_at' else value for key, value in dict(row).items()}

# ===== 네트워크 세션 관리 =====

def create_network_session(db: sqlite3.Connection, wifi_auth_id: int, ip_address: str, mac_address: str) -> str:
    """
    새로운 네트워크 세션을 생성합니다.
    
    Args:
        db: 데이터베이스 연결
        wifi_auth_id: WiFi 인증 ID
        ip_address: 클라이언트 IP 주소
        mac_address: 클라이언트 MAC 주소
        
    Returns:
        str: 생성된 세션 토큰
    """
    # 기존 활성 세션이 있다면 종료
    end_active_sessions(db, wifi_auth_id)
    
    # 새로운 세션 토큰 생성
    session_token = secrets.token_urlsafe(32)
    
    # 세션 생성
    query = """
        INSERT INTO network_sessions 
        (wifi_auth_id, session_token, ip_address, mac_address, is_active, started_at)
        VALUES (?, ?, ?, ?, 1, ?)
    """
    db.execute(query, (wifi_auth_id, session_token, ip_address, mac_address, datetime.now()))
    db.commit()
    
    logger.info(f"새로운 네트워크 세션 생성: {session_token[:8]}... (IP: {ip_address}, MAC: {mac_address})")
    return session_token

def get_active_session(db: sqlite3.Connection, session_token: str) -> Optional[Dict[str, Any]]:
    """
    활성 세션 정보를 조회합니다.
    
    Args:
        db: 데이터베이스 연결
        session_token: 세션 토큰
        
    Returns:
        Optional[Dict]: 세션 정보 또는 None
    """
    query = """
        SELECT ns.*, wa.phone_number, wa.auth_expires_at
        FROM network_sessions ns
        JOIN wifi_auth wa ON ns.wifi_auth_id = wa.id
        WHERE ns.session_token = ? AND ns.is_active = 1
    """
    result = db.execute(query, (session_token,))
    row = result.fetchone()
    return row_to_dict(row) if row else None

def end_active_sessions(db: sqlite3.Connection, wifi_auth_id: int) -> int:
    """
    특정 사용자의 모든 활성 세션을 종료합니다.
    
    Args:
        db: 데이터베이스 연결
        wifi_auth_id: WiFi 인증 ID
        
    Returns:
        int: 종료된 세션 수
    """
    query = """
        UPDATE network_sessions 
        SET is_active = 0, ended_at = ?
        WHERE wifi_auth_id = ? AND is_active = 1
    """
    result = db.execute(query, (datetime.now(), wifi_auth_id))
    db.commit()
    
    ended_count = result.rowcount
    if ended_count > 0:
        logger.info(f"활성 세션 {ended_count}개 종료 (wifi_auth_id: {wifi_auth_id})")
    
    return ended_count

def update_session_activity(db: sqlite3.Connection, session_token: str, bytes_uploaded: int = 0, bytes_downloaded: int = 0) -> bool:
    """
    세션의 활동 정보를 업데이트합니다.
    
    Args:
        db: 데이터베이스 연결
        session_token: 세션 토큰
        bytes_uploaded: 업로드된 바이트 수
        bytes_downloaded: 다운로드된 바이트 수
        
    Returns:
        bool: 업데이트 성공 여부
    """
    query = """
        UPDATE network_sessions 
        SET bytes_uploaded = bytes_uploaded + ?, 
            bytes_downloaded = bytes_downloaded + ?
        WHERE session_token = ? AND is_active = 1
    """
    result = db.execute(query, (bytes_uploaded, bytes_downloaded, session_token))
    db.commit()
    
    return result.rowcount > 0

# ===== 차단/허용 관리 =====

def is_device_blocked(db: sqlite3.Connection, phone_number: str = None, mac_address: str = None, ip_address: str = None) -> bool:
    """
    디바이스가 차단되었는지 확인합니다.
    
    Args:
        db: 데이터베이스 연결
        phone_number: 전화번호
        mac_address: MAC 주소
        ip_address: IP 주소
        
    Returns:
        bool: 차단 여부
    """
    conditions = []
    params = []
    
    if phone_number:
        conditions.append("phone_number = ?")
        params.append(phone_number)
    if mac_address:
        conditions.append("mac_address = ?")
        params.append(mac_address)
    if ip_address:
        conditions.append("ip_address = ?")
        params.append(ip_address)
    
    if not conditions:
        return False
    
    query = f"""
        SELECT COUNT(*) as count
        FROM blocked_devices
        WHERE is_active = 1 
        AND (expires_at IS NULL OR expires_at > ?)
        AND ({' OR '.join(conditions)})
    """
    params.insert(0, datetime.now())
    
    result = db.execute(query, params)
    row = result.fetchone()
    
    return row['count'] > 0 if row else False

def is_device_whitelisted(db: sqlite3.Connection, phone_number: str = None, mac_address: str = None) -> bool:
    """
    디바이스가 화이트리스트에 있는지 확인합니다.
    
    Args:
        db: 데이터베이스 연결
        phone_number: 전화번호
        mac_address: MAC 주소
        
    Returns:
        bool: 화이트리스트 여부
    """
    conditions = []
    params = []
    
    if phone_number:
        conditions.append("phone_number = ?")
        params.append(phone_number)
    if mac_address:
        conditions.append("mac_address = ?")
        params.append(mac_address)
    
    if not conditions:
        return False
    
    query = f"""
        SELECT COUNT(*) as count
        FROM whitelisted_devices
        WHERE is_active = 1 
        AND (expires_at IS NULL OR expires_at > ?)
        AND ({' OR '.join(conditions)})
    """
    params.insert(0, datetime.now())
    
    result = db.execute(query, params)
    row = result.fetchone()
    
    return row['count'] > 0 if row else False

def block_device(db: sqlite3.Connection, phone_number: str = None, mac_address: str = None, 
                ip_address: str = None, reason: str = "관리자 차단", blocked_by: str = "admin", 
                expires_hours: int = None) -> bool:
    """
    디바이스를 차단합니다.
    
    Args:
        db: 데이터베이스 연결
        phone_number: 전화번호
        mac_address: MAC 주소
        ip_address: IP 주소
        reason: 차단 사유
        blocked_by: 차단한 사용자
        expires_hours: 차단 만료 시간 (시간 단위, None이면 영구)
        
    Returns:
        bool: 차단 성공 여부
    """
    if not any([phone_number, mac_address, ip_address]):
        return False
    
    expires_at = None
    if expires_hours:
        expires_at = datetime.now() + timedelta(hours=expires_hours)
    
    query = """
        INSERT INTO blocked_devices 
        (phone_number, mac_address, ip_address, block_reason, blocked_by, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    db.execute(query, (phone_number, mac_address, ip_address, reason, blocked_by, expires_at))
    db.commit()
    
    # 해당 디바이스의 활성 세션 종료
    if phone_number:
        # 전화번호로 wifi_auth_id 찾기
        auth_query = "SELECT id FROM wifi_auth WHERE phone_number = ?"
        auth_result = db.execute(auth_query, (phone_number,))
        auth_row = auth_result.fetchone()
        if auth_row:
            end_active_sessions(db, auth_row['id'])
    
    logger.info(f"디바이스 차단: 전화번호={phone_number}, MAC={mac_address}, IP={ip_address}, 사유={reason}")
    return True

def whitelist_device(db: sqlite3.Connection, phone_number: str = None, mac_address: str = None, 
                    device_name: str = None, added_by: str = "admin", expires_hours: int = None) -> bool:
    """
    디바이스를 화이트리스트에 추가합니다.
    
    Args:
        db: 데이터베이스 연결
        phone_number: 전화번호
        mac_address: MAC 주소
        device_name: 디바이스 이름
        added_by: 추가한 사용자
        expires_hours: 만료 시간 (시간 단위, None이면 영구)
        
    Returns:
        bool: 추가 성공 여부
    """
    if not any([phone_number, mac_address]):
        return False
    
    expires_at = None
    if expires_hours:
        expires_at = datetime.now() + timedelta(hours=expires_hours)
    
    query = """
        INSERT INTO whitelisted_devices 
        (phone_number, mac_address, device_name, added_by, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """
    db.execute(query, (phone_number, mac_address, device_name, added_by, expires_at))
    db.commit()
    
    logger.info(f"디바이스 화이트리스트 추가: 전화번호={phone_number}, MAC={mac_address}, 이름={device_name}")
    return True

# ===== 시스템 로그 관리 =====

def log_system_event(db: sqlite3.Connection, level: str, category: str, message: str, 
                    phone_number: str = None, mac_address: str = None, 
                    ip_address: str = None, user_agent: str = None) -> None:
    """
    시스템 이벤트를 로그에 기록합니다.
    
    Args:
        db: 데이터베이스 연결
        level: 로그 레벨 (INFO, WARNING, ERROR)
        category: 카테고리 (AUTH, NETWORK, ADMIN, SMS)
        message: 로그 메시지
        phone_number: 관련 전화번호
        mac_address: 관련 MAC 주소
        ip_address: 관련 IP 주소
        user_agent: 사용자 에이전트
    """
    query = """
        INSERT INTO system_logs 
        (log_level, category, message, phone_number, mac_address, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    db.execute(query, (level, category, message, phone_number, mac_address, ip_address, user_agent))
    db.commit()

def get_system_logs(db: sqlite3.Connection, category: str = None, level: str = None, 
                   limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    시스템 로그를 조회합니다.
    
    Args:
        db: 데이터베이스 연결
        category: 필터할 카테고리
        level: 필터할 로그 레벨
        limit: 조회할 최대 개수
        offset: 조회 시작 위치
        
    Returns:
        List[Dict]: 로그 목록
    """
    conditions = []
    params = []
    
    if category:
        conditions.append("category = ?")
        params.append(category)
    if level:
        conditions.append("log_level = ?")
        params.append(level)
    
    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)
    
    query = f"""
        SELECT * FROM system_logs 
        {where_clause}
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])
    
    result = db.execute(query, params)
    rows = result.fetchall()
    
    return [row_to_dict(row) for row in rows]

# ===== 통계 및 모니터링 =====

def get_auth_statistics(db: sqlite3.Connection, days: int = 7) -> Dict[str, Any]:
    """
    인증 통계를 조회합니다.
    
    Args:
        db: 데이터베이스 연결
        days: 조회할 일수
        
    Returns:
        Dict: 통계 정보
    """
    since_date = datetime.now() - timedelta(days=days)
    
    # 총 인증 시도 수
    total_attempts_query = """
        SELECT COUNT(*) as count FROM wifi_auth 
        WHERE created_at >= ?
    """
    total_attempts = db.execute(total_attempts_query, (since_date,)).fetchone()['count']
    
    # 성공한 인증 수
    successful_auths_query = """
        SELECT COUNT(*) as count FROM wifi_auth 
        WHERE is_authenticated = 1 AND created_at >= ?
    """
    successful_auths = db.execute(successful_auths_query, (since_date,)).fetchone()['count']
    
    # 현재 활성 세션 수
    active_sessions_query = """
        SELECT COUNT(*) as count FROM network_sessions 
        WHERE is_active = 1
    """
    active_sessions = db.execute(active_sessions_query).fetchone()['count']
    
    # 차단된 디바이스 수
    blocked_devices_query = """
        SELECT COUNT(*) as count FROM blocked_devices 
        WHERE is_active = 1
    """
    blocked_devices = db.execute(blocked_devices_query).fetchone()['count']
    
    return {
        'period_days': days,
        'total_auth_attempts': total_attempts,
        'successful_auths': successful_auths,
        'success_rate': round((successful_auths / total_attempts * 100) if total_attempts > 0 else 0, 2),
        'active_sessions': active_sessions,
        'blocked_devices': blocked_devices
    }

def get_active_users(db: sqlite3.Connection) -> List[Dict[str, Any]]:
    """
    현재 활성 사용자 목록을 조회합니다.
    
    Args:
        db: 데이터베이스 연결
        
    Returns:
        List[Dict]: 활성 사용자 목록
    """
    query = """
        SELECT wa.phone_number, wa.mac_address, wa.ip_address, wa.device_name,
               wa.auth_completed_at, wa.auth_expires_at, wa.last_activity_at,
               ns.session_token, ns.bytes_uploaded, ns.bytes_downloaded, ns.started_at
        FROM wifi_auth wa
        JOIN network_sessions ns ON wa.id = ns.wifi_auth_id
        WHERE wa.is_authenticated = 1 
        AND wa.auth_expires_at > ?
        AND ns.is_active = 1
        ORDER BY wa.last_activity_at DESC
    """
    
    result = db.execute(query, (datetime.now(),))
    rows = result.fetchall()
    
    return [row_to_dict(row) for row in rows]
