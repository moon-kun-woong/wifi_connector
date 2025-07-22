import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from ..models import schemas

logger = logging.getLogger(__name__)

def row_to_dict(row) -> Dict[str, Any]:
    """SQLite Row 객체를 딕셔너리로 변환"""
    if not row:
        return {}
    return {key: str(value) if key == 'created_at' else value for key, value in dict(row).items()}

# ===== 비밀번호 해싱 =====

def hash_password(password: str) -> str:
    """
    비밀번호를 해싱합니다.
    
    Args:
        password: 원본 비밀번호
        
    Returns:
        str: 해싱된 비밀번호
    """
    # 솔트 생성
    salt = secrets.token_hex(16)
    # 비밀번호와 솔트를 결합하여 해싱
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    # 솔트와 해시를 결합하여 저장
    return salt + password_hash.hex()

def verify_password(password: str, password_hash: str) -> bool:
    """
    비밀번호를 검증합니다.
    
    Args:
        password: 입력된 비밀번호
        password_hash: 저장된 해시
        
    Returns:
        bool: 비밀번호 일치 여부
    """
    try:
        # 솔트 추출 (처음 32자)
        salt = password_hash[:32]
        # 저장된 해시 추출
        stored_hash = password_hash[32:]
        # 입력된 비밀번호를 같은 솔트로 해싱
        password_hash_check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        # 해시 비교
        return password_hash_check.hex() == stored_hash
    except Exception as e:
        logger.error(f"비밀번호 검증 중 오류: {e}")
        return False

# ===== 관리자 계정 관리 =====

def create_admin_user(db: sqlite3.Connection, username: str, password: str, email: str = None) -> bool:
    """
    관리자 계정을 생성합니다.
    
    Args:
        db: 데이터베이스 연결
        username: 사용자명
        password: 비밀번호
        email: 이메일 (선택사항)
        
    Returns:
        bool: 생성 성공 여부
    """
    # 중복 사용자명 확인
    check_query = "SELECT COUNT(*) as count FROM admin_users WHERE username = ?"
    result = db.execute(check_query, (username,))
    if result.fetchone()['count'] > 0:
        logger.warning(f"관리자 계정 생성 실패: 중복된 사용자명 '{username}'")
        return False
    
    # 비밀번호 해싱
    password_hash = hash_password(password)
    
    # 관리자 계정 생성
    insert_query = """
        INSERT INTO admin_users (username, password_hash, email, is_active)
        VALUES (?, ?, ?, 1)
    """
    db.execute(insert_query, (username, password_hash, email))
    db.commit()
    
    logger.info(f"관리자 계정 생성 완료: {username}")
    return True

def authenticate_admin(db: sqlite3.Connection, username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    관리자 인증을 수행합니다.
    
    Args:
        db: 데이터베이스 연결
        username: 사용자명
        password: 비밀번호
        
    Returns:
        Optional[Dict]: 인증된 관리자 정보 또는 None
    """
    # 관리자 계정 조회
    query = """
        SELECT id, username, password_hash, email, is_active, last_login_at
        FROM admin_users 
        WHERE username = ? AND is_active = 1
    """
    result = db.execute(query, (username,))
    admin_row = result.fetchone()
    
    if not admin_row:
        logger.warning(f"관리자 인증 실패: 존재하지 않는 사용자 '{username}'")
        return None
    
    # 비밀번호 검증
    if not verify_password(password, admin_row['password_hash']):
        logger.warning(f"관리자 인증 실패: 잘못된 비밀번호 '{username}'")
        return None
    
    # 마지막 로그인 시간 업데이트
    update_query = "UPDATE admin_users SET last_login_at = ? WHERE id = ?"
    db.execute(update_query, (datetime.now(), admin_row['id']))
    db.commit()
    
    admin_info = row_to_dict(admin_row)
    # 비밀번호 해시는 제거
    del admin_info['password_hash']
    
    logger.info(f"관리자 인증 성공: {username}")
    return admin_info

def get_admin_users(db: sqlite3.Connection) -> List[Dict[str, Any]]:
    """
    모든 관리자 계정 목록을 조회합니다.
    
    Args:
        db: 데이터베이스 연결
        
    Returns:
        List[Dict]: 관리자 계정 목록
    """
    query = """
        SELECT id, username, email, is_active, last_login_at, created_at
        FROM admin_users 
        ORDER BY created_at DESC
    """
    result = db.execute(query)
    rows = result.fetchall()
    
    return [row_to_dict(row) for row in rows]

def update_admin_status(db: sqlite3.Connection, admin_id: int, is_active: bool) -> bool:
    """
    관리자 계정의 활성 상태를 변경합니다.
    
    Args:
        db: 데이터베이스 연결
        admin_id: 관리자 ID
        is_active: 활성 상태
        
    Returns:
        bool: 업데이트 성공 여부
    """
    query = "UPDATE admin_users SET is_active = ? WHERE id = ?"
    result = db.execute(query, (1 if is_active else 0, admin_id))
    db.commit()
    
    success = result.rowcount > 0
    if success:
        logger.info(f"관리자 계정 상태 변경: ID={admin_id}, 활성={is_active}")
    
    return success

# ===== 관리자 대시보드 데이터 =====

def get_dashboard_summary(db: sqlite3.Connection) -> Dict[str, Any]:
    """
    관리자 대시보드용 요약 정보를 조회합니다.
    
    Returns:
        Dict: 대시보드 요약 정보
    """
    now = datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=7)
    
    # 오늘 인증 시도 수
    today_attempts_query = """
        SELECT COUNT(*) as count FROM wifi_auth 
        WHERE created_at >= ?
    """
    today_attempts = db.execute(today_attempts_query, (today,)).fetchone()['count']
    
    # 오늘 성공한 인증 수
    today_success_query = """
        SELECT COUNT(*) as count FROM wifi_auth 
        WHERE is_authenticated = 1 AND created_at >= ?
    """
    today_success = db.execute(today_success_query, (today,)).fetchone()['count']
    
    # 현재 활성 사용자 수
    active_users_query = """
        SELECT COUNT(*) as count FROM wifi_auth wa
        JOIN network_sessions ns ON wa.id = ns.wifi_auth_id
        WHERE wa.is_authenticated = 1 
        AND wa.auth_expires_at > ?
        AND ns.is_active = 1
    """
    active_users = db.execute(active_users_query, (now,)).fetchone()['count']
    
    # 차단된 디바이스 수
    blocked_devices_query = """
        SELECT COUNT(*) as count FROM blocked_devices 
        WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)
    """
    blocked_devices = db.execute(blocked_devices_query, (now,)).fetchone()['count']
    
    # 화이트리스트 디바이스 수
    whitelisted_devices_query = """
        SELECT COUNT(*) as count FROM whitelisted_devices 
        WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)
    """
    whitelisted_devices = db.execute(whitelisted_devices_query, (now,)).fetchone()['count']
    
    # 주간 인증 트렌드
    weekly_trend_query = """
        SELECT DATE(created_at) as date, COUNT(*) as attempts,
               SUM(CASE WHEN is_authenticated = 1 THEN 1 ELSE 0 END) as success
        FROM wifi_auth 
        WHERE created_at >= ?
        GROUP BY DATE(created_at)
        ORDER BY date
    """
    weekly_trend_result = db.execute(weekly_trend_query, (week_ago,))
    weekly_trend = [row_to_dict(row) for row in weekly_trend_result.fetchall()]
    
    # 최근 시스템 로그 (에러만)
    recent_errors_query = """
        SELECT * FROM system_logs 
        WHERE log_level = 'ERROR'
        ORDER BY created_at DESC 
        LIMIT 5
    """
    recent_errors_result = db.execute(recent_errors_query)
    recent_errors = [row_to_dict(row) for row in recent_errors_result.fetchall()]
    
    return {
        'today_attempts': today_attempts,
        'today_success': today_success,
        'today_success_rate': round((today_success / today_attempts * 100) if today_attempts > 0 else 0, 2),
        'active_users': active_users,
        'blocked_devices': blocked_devices,
        'whitelisted_devices': whitelisted_devices,
        'weekly_trend': weekly_trend,
        'recent_errors': recent_errors
    }

def get_user_management_data(db: sqlite3.Connection, page: int = 1, per_page: int = 20, 
                           search: str = None) -> Dict[str, Any]:
    """
    사용자 관리 페이지용 데이터를 조회합니다.
    
    Args:
        db: 데이터베이스 연결
        page: 페이지 번호
        per_page: 페이지당 항목 수
        search: 검색어 (전화번호 또는 MAC 주소)
        
    Returns:
        Dict: 사용자 관리 데이터
    """
    offset = (page - 1) * per_page
    
    # 검색 조건 구성
    where_conditions = []
    params = []
    
    if search:
        where_conditions.append("(wa.phone_number LIKE ? OR wa.mac_address LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    
    where_clause = ""
    if where_conditions:
        where_clause = "WHERE " + " AND ".join(where_conditions)
    
    # 총 사용자 수 조회
    count_query = f"""
        SELECT COUNT(*) as total
        FROM wifi_auth wa
        {where_clause}
    """
    total_count = db.execute(count_query, params).fetchone()['total']
    
    # 사용자 목록 조회
    users_query = f"""
        SELECT wa.*, 
               CASE WHEN ns.is_active = 1 THEN 1 ELSE 0 END as is_online,
               ns.bytes_uploaded, ns.bytes_downloaded, ns.started_at as session_started
        FROM wifi_auth wa
        LEFT JOIN network_sessions ns ON wa.id = ns.wifi_auth_id AND ns.is_active = 1
        {where_clause}
        ORDER BY wa.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    
    users_result = db.execute(users_query, params)
    users = [row_to_dict(row) for row in users_result.fetchall()]
    
    return {
        'users': users,
        'total_count': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_count + per_page - 1) // per_page
    }

# ===== 초기 관리자 계정 생성 =====

def ensure_default_admin(db: sqlite3.Connection) -> None:
    """
    기본 관리자 계정이 없으면 생성합니다.
    """
    # 관리자 계정이 있는지 확인
    check_query = "SELECT COUNT(*) as count FROM admin_users WHERE is_active = 1"
    result = db.execute(check_query)
    admin_count = result.fetchone()['count']
    
    if admin_count == 0:
        # 기본 관리자 계정 생성
        default_username = "admin"
        default_password = "admin123!"  # 실제 운영시에는 반드시 변경해야 함
        
        if create_admin_user(db, default_username, default_password, "admin@hospital.local"):
            logger.warning("기본 관리자 계정이 생성되었습니다.")
            logger.warning(f"사용자명: {default_username}, 비밀번호: {default_password}")
            logger.warning("보안을 위해 반드시 비밀번호를 변경하세요!")
        else:
            logger.error("기본 관리자 계정 생성에 실패했습니다.")
