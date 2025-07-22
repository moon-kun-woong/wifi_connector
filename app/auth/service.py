import random
import sqlite3
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

from fastapi import HTTPException, status

from ..models import schemas
from ..network.network_service import (
    create_network_session, is_device_blocked, is_device_whitelisted,
    log_system_event, end_active_sessions
)


def row_to_dict(row) -> Dict[str, Any]:
    if not row:
        return {}
    
    return {key: str(value) if key == 'created_at' else value for key, value in dict(row).items()}

# ===== WiFi 인증 관련 함수들 =====

def generate_auth_code() -> str:
    """6자리 인증코드 생성"""
    return ''.join(random.choices(string.digits, k=6))


def create_wifi_auth_request(db: sqlite3.Connection, phone_number: str, mac_address: Optional[str] = None, 
                           ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict[str, Any]:
    """전화번호로 WiFi 인증 요청 생성 (개선된 버전)"""
    
    # 차단된 디바이스인지 확인
    if is_device_blocked(db, phone_number=phone_number, mac_address=mac_address, ip_address=ip_address):
        log_system_event(db, 'WARNING', 'AUTH', f'차단된 디바이스의 인증 시도', 
                        phone_number=phone_number, mac_address=mac_address, ip_address=ip_address)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                          detail="차단된 디바이스입니다. 관리자에게 문의하세요.")
    
    # 화이트리스트 디바이스인지 확인 (자동 인증)
    if is_device_whitelisted(db, phone_number=phone_number, mac_address=mac_address):
        log_system_event(db, 'INFO', 'AUTH', f'화이트리스트 디바이스 자동 인증', 
                        phone_number=phone_number, mac_address=mac_address, ip_address=ip_address)
        return auto_authenticate_device(db, phone_number, mac_address, ip_address, user_agent)
    
    # MAC 주소 기반 자동 재인증 확인 (1일 이내 인증 기록이 있는 경우)
    if mac_address:
        auto_auth_result = check_mac_auto_reauth(db, mac_address, phone_number)
        if auto_auth_result:
            log_system_event(db, 'INFO', 'AUTH', f'MAC 주소 기반 자동 재인증', 
                            phone_number=phone_number, mac_address=mac_address, ip_address=ip_address)
            return auto_auth_result
    
    # 기존 인증 기록 확인 (동일 전화번호)
    query = "SELECT * FROM wifi_auth WHERE phone_number = ? ORDER BY created_at DESC LIMIT 1"
    result = db.execute(query, (phone_number,))
    existing_auth = result.fetchone()
    
    # 새 인증 요청 생성
    if existing_auth and row_to_dict(existing_auth).get('is_authenticated') == 0:
        # 인증되지 않은 기존 요청이 있으면 재사용하고 추가 정보 업데이트
        wifi_auth_id = existing_auth['id']
        update_query = """UPDATE wifi_auth 
                         SET mac_address = ?, ip_address = ?, user_agent = ?, created_at = ?
                         WHERE id = ?"""
        db.execute(update_query, (mac_address, ip_address, user_agent, datetime.now(), wifi_auth_id))
    else:
        # 새로운 인증 요청 생성
        insert_query = """INSERT INTO wifi_auth 
                         (phone_number, mac_address, ip_address, user_agent, is_authenticated) 
                         VALUES (?, ?, ?, ?, 0)"""
        insert_result = db.execute(insert_query, (phone_number, mac_address, ip_address, user_agent))
        wifi_auth_id = insert_result.lastrowid
    
    # 이전 인증코드가 있다면 만료 처리
    db.execute("UPDATE auth_codes SET is_used = 1 WHERE wifi_auth_id = ?", (wifi_auth_id,))
    
    # 새로운 인증코드 생성
    auth_code = generate_auth_code()
    expires_at = datetime.now() + timedelta(minutes=3)  # 3분 유효기간
    
    # 인증코드 저장
    insert_code_query = """INSERT INTO auth_codes 
                         (wifi_auth_id, auth_code, is_used, expires_at) 
                         VALUES (?, ?, 0, ?)"""
    db.execute(insert_code_query, (wifi_auth_id, auth_code, expires_at))
    db.commit()
    
    # 시스템 로그 기록
    log_system_event(db, 'INFO', 'AUTH', f'인증 코드 발송', 
                    phone_number=phone_number, mac_address=mac_address, 
                    ip_address=ip_address, user_agent=user_agent)
    
    return {
        "id": wifi_auth_id,
        "phone_number": phone_number,
        "auth_code": auth_code,
        "expires_at": expires_at.isoformat()
    }

def check_mac_auto_reauth(db: sqlite3.Connection, mac_address: str, phone_number: str) -> Optional[Dict[str, Any]]:
    """
    MAC 주소 기반 자동 재인증 확인 (1일 이내 인증 기록이 있는 경우)
    """
    # 1일 이내에 같은 MAC 주소로 인증된 기록이 있는지 확인
    one_day_ago = datetime.now() - timedelta(days=1)
    
    query = """
        SELECT * FROM wifi_auth 
        WHERE mac_address = ? 
        AND is_authenticated = 1 
        AND auth_expires_at > ?
        AND auth_completed_at >= ?
        ORDER BY auth_completed_at DESC 
        LIMIT 1
    """
    
    result = db.execute(query, (mac_address, datetime.now(), one_day_ago))
    existing_auth = result.fetchone()
    
    if existing_auth:
        # 기존 인증이 유효하면 자동 재인증
        auth_dict = row_to_dict(existing_auth)
        
        # 전화번호가 다른 경우 새로운 인증 필요
        if auth_dict.get('phone_number') != phone_number:
            return None
        
        # 마지막 활동 시간 업데이트
        update_query = "UPDATE wifi_auth SET last_activity_at = ? WHERE id = ?"
        db.execute(update_query, (datetime.now(), existing_auth['id']))
        db.commit()
        
        return {
            "id": existing_auth['id'],
            "phone_number": phone_number,
            "auto_authenticated": True,
            "expires_at": auth_dict.get('auth_expires_at'),
            "message": "MAC 주소 기반 자동 재인증 완료"
        }
    
    return None

def auto_authenticate_device(db: sqlite3.Connection, phone_number: str, mac_address: str, 
                           ip_address: str, user_agent: str) -> Dict[str, Any]:
    """
    화이트리스트 디바이스 자동 인증
    """
    # 기존 활성 세션 종료
    existing_query = "SELECT id FROM wifi_auth WHERE phone_number = ? AND is_authenticated = 1"
    existing_result = db.execute(existing_query, (phone_number,))
    existing_row = existing_result.fetchone()
    
    if existing_row:
        end_active_sessions(db, existing_row['id'])
    
    # 새로운 인증 생성
    auth_expires_at = datetime.now() + timedelta(days=1)  # 1일 유효
    
    insert_query = """
        INSERT INTO wifi_auth 
        (phone_number, mac_address, ip_address, user_agent, is_authenticated, 
         auth_completed_at, auth_expires_at, last_activity_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
    """
    
    now = datetime.now()
    insert_result = db.execute(insert_query, (
        phone_number, mac_address, ip_address, user_agent, 
        now, auth_expires_at, now
    ))
    wifi_auth_id = insert_result.lastrowid
    
    # 네트워크 세션 생성
    session_token = create_network_session(db, wifi_auth_id, ip_address, mac_address)
    
    db.commit()
    
    return {
        "id": wifi_auth_id,
        "phone_number": phone_number,
        "auto_authenticated": True,
        "session_token": session_token,
        "expires_at": auth_expires_at.isoformat(),
        "message": "화이트리스트 디바이스 자동 인증 완료"
    }


def verify_auth_code(db: sqlite3.Connection, phone_number: str, auth_code: str, 
                    mac_address: Optional[str] = None, ip_address: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """인증코드 검증 (개선된 버전)"""
    # 해당 전화번호의 최신 인증 요청 조회
    query = "SELECT * FROM wifi_auth WHERE phone_number = ? ORDER BY created_at DESC LIMIT 1"
    result = db.execute(query, (phone_number,))
    wifi_auth = result.fetchone()
    
    if not wifi_auth:
        log_system_event(db, 'ERROR', 'AUTH', f'인증 요청을 찾을 수 없음', phone_number=phone_number)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="인증 요청을 찾을 수 없습니다. 다시 시도해주세요."
        )
    
    wifi_auth_id = wifi_auth['id']
    
    # 해당 인증 요청의 가장 최근 인증코드 조회
    code_query = """SELECT * FROM auth_codes 
                  WHERE wifi_auth_id = ? AND is_used = 0 AND expires_at > ? 
                  ORDER BY created_at DESC LIMIT 1"""
    code_result = db.execute(code_query, (wifi_auth_id, datetime.now()))
    auth_code_record = code_result.fetchone()
    
    if not auth_code_record:
        log_system_event(db, 'WARNING', 'AUTH', f'만료된 인증코드 사용 시도', 
                        phone_number=phone_number, mac_address=mac_address)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="만료되었거나 유효하지 않은 인증코드입니다. 새로운 인증을 요청해주세요."
        )
    
    is_valid = auth_code_record['auth_code'] == auth_code
    
    if is_valid:
        # 인증코드 사용 처리
        db.execute("UPDATE auth_codes SET is_used = 1 WHERE id = ?", (auth_code_record['id'],))
        
        # 기존 활성 세션 종료
        end_active_sessions(db, wifi_auth_id)
        
        # WiFi 인증 완료 처리 (1일 유효기간 설정)
        now = datetime.now()
        auth_expires_at = now + timedelta(days=1)  # 1일 인증 유지
        
        update_query = """UPDATE wifi_auth 
                        SET is_authenticated = 1, mac_address = ?, ip_address = ?,
                            auth_completed_at = ?, auth_expires_at = ?, last_activity_at = ?
                        WHERE id = ?"""
        db.execute(update_query, (mac_address, ip_address, now, auth_expires_at, now, wifi_auth_id))
        
        # 네트워크 세션 생성
        session_token = None
        if mac_address and ip_address:
            session_token = create_network_session(db, wifi_auth_id, ip_address, mac_address)
        
        db.commit()
        
        # 성공 로그 기록
        log_system_event(db, 'INFO', 'AUTH', f'인증 성공', 
                        phone_number=phone_number, mac_address=mac_address, ip_address=ip_address)
        
        auth_result = row_to_dict(wifi_auth)
        auth_result.update({
            'session_token': session_token,
            'auth_expires_at': auth_expires_at.isoformat(),
            'message': '인증이 성공적으로 완료되었습니다. 1일간 인터넷을 사용할 수 있습니다.'
        })
        
        return True, auth_result
    else:
        # 실패 로그 기록
        log_system_event(db, 'WARNING', 'AUTH', f'잘못된 인증코드 입력', 
                        phone_number=phone_number, mac_address=mac_address, ip_address=ip_address)
    
    return False, row_to_dict(wifi_auth)


def check_wifi_auth_status(db: sqlite3.Connection, phone_number: str = None, mac_address: str = None, 
                          session_token: str = None) -> Dict[str, Any]:
    """WiFi 인증 상태 확인 (개선된 버전)"""
    
    # 세션 토큰으로 확인하는 경우
    if session_token:
        from .network_service import get_active_session
        session_info = get_active_session(db, session_token)
        if session_info:
            # 인증 만료 시간 확인
            auth_expires_at = datetime.fromisoformat(session_info['auth_expires_at']) if session_info.get('auth_expires_at') else None
            is_expired = auth_expires_at and auth_expires_at < datetime.now()
            
            if is_expired:
                # 만료된 세션 비활성화
                from .network_service import end_active_sessions
                end_active_sessions(db, session_info['wifi_auth_id'])
                return {
                    "is_authenticated": False,
                    "is_expired": True,
                    "message": "인증이 만료되었습니다. 다시 인증해주세요."
                }
            
            return {
                "is_authenticated": True,
                "phone_number": session_info['phone_number'],
                "session_token": session_token,
                "auth_expires_at": session_info['auth_expires_at'],
                "bytes_uploaded": session_info.get('bytes_uploaded', 0),
                "bytes_downloaded": session_info.get('bytes_downloaded', 0),
                "message": "인증된 상태입니다."
            }
    
    # 전화번호 또는 MAC 주소로 확인
    conditions = []
    params = []
    
    if phone_number:
        conditions.append("phone_number = ?")
        params.append(phone_number)
    if mac_address:
        conditions.append("mac_address = ?")
        params.append(mac_address)
    
    if not conditions:
        return {
            "is_authenticated": False,
            "message": "전화번호, MAC 주소 또는 세션 토큰이 필요합니다."
        }
    
    where_clause = " OR ".join(conditions)
    query = f"SELECT * FROM wifi_auth WHERE ({where_clause}) AND is_authenticated = 1 ORDER BY auth_completed_at DESC LIMIT 1"
    
    result = db.execute(query, params)
    wifi_auth = result.fetchone()
    
    if not wifi_auth:
        return {
            "is_authenticated": False,
            "message": "인증 기록이 없습니다. 인증을 진행해주세요."
        }
    
    wifi_auth_dict = row_to_dict(wifi_auth)
    
    # 인증 만료 시간 확인
    auth_expires_at = wifi_auth_dict.get('auth_expires_at')
    if auth_expires_at:
        expires_datetime = datetime.fromisoformat(auth_expires_at) if isinstance(auth_expires_at, str) else auth_expires_at
        if expires_datetime < datetime.now():
            # 만료된 인증 비활성화
            update_query = "UPDATE wifi_auth SET is_authenticated = 0 WHERE id = ?"
            db.execute(update_query, (wifi_auth['id'],))
            
            # 활성 세션 종료
            from .network_service import end_active_sessions
            end_active_sessions(db, wifi_auth['id'])
            db.commit()
            
            return {
                "is_authenticated": False,
                "is_expired": True,
                "phone_number": wifi_auth_dict.get('phone_number'),
                "auth_completed_at": wifi_auth_dict.get('auth_completed_at'),
                "auth_expires_at": auth_expires_at,
                "message": "인증이 만료되었습니다. 다시 인증해주세요."
            }
    
    # 활성 세션 정보 조회
    session_query = """SELECT session_token, bytes_uploaded, bytes_downloaded 
                      FROM network_sessions 
                      WHERE wifi_auth_id = ? AND is_active = 1 
                      ORDER BY started_at DESC LIMIT 1"""
    session_result = db.execute(session_query, (wifi_auth['id'],))
    session_row = session_result.fetchone()
    
    session_info = {}
    if session_row:
        session_info = {
            'session_token': session_row['session_token'],
            'bytes_uploaded': session_row['bytes_uploaded'],
            'bytes_downloaded': session_row['bytes_downloaded']
        }
    
    return {
        "is_authenticated": True,
        "phone_number": wifi_auth_dict.get('phone_number'),
        "mac_address": wifi_auth_dict.get('mac_address'),
        "ip_address": wifi_auth_dict.get('ip_address'),
        "created_at": wifi_auth_dict.get('created_at'),
        "auth_completed_at": wifi_auth_dict.get('auth_completed_at'),
        "auth_expires_at": wifi_auth_dict.get('auth_expires_at'),
        "last_activity_at": wifi_auth_dict.get('last_activity_at'),
        **session_info,
        "message": "인증된 상태입니다."
    }
