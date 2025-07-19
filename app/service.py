import sqlite3
from fastapi import HTTPException, status
from typing import List, Dict, Any, Optional, Tuple
from . import schemas
import random
import string
from datetime import datetime, timedelta


def row_to_dict(row) -> Dict[str, Any]:
    if not row:
        return {}
    
    return {key: str(value) if key == 'created_at' else value for key, value in dict(row).items()}

# ===== WiFi 인증 관련 함수들 =====

def generate_auth_code() -> str:
    """6자리 인증코드 생성"""
    return ''.join(random.choices(string.digits, k=6))


def create_wifi_auth_request(db: sqlite3.Connection, phone_number: str, mac_address: Optional[str] = None) -> Dict[str, Any]:
    """전화번호로 WiFi 인증 요청 생성"""
    # 기존 인증 기록 확인 (동일 전화번호)
    query = "SELECT * FROM wifi_auth WHERE phone_number = ? ORDER BY created_at DESC LIMIT 1"
    result = db.execute(query, (phone_number,))
    existing_auth = result.fetchone()
    
    # 새 인증 요청 생성
    if existing_auth and row_to_dict(existing_auth).get('is_authenticated') == 0:
        # 인증되지 않은 기존 요청이 있으면 재사용
        wifi_auth_id = existing_auth['id']
    else:
        # 새로운 인증 요청 생성
        insert_query = "INSERT INTO wifi_auth (phone_number, mac_address, is_authenticated) VALUES (?, ?, 0)"
        insert_result = db.execute(insert_query, (phone_number, mac_address))
        db.commit()  # 트랜잭션 커밋 추가
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
    
    return {
        "id": wifi_auth_id,
        "phone_number": phone_number,
        "auth_code": auth_code,
        "expires_at": expires_at.isoformat()
    }


def verify_auth_code(db: sqlite3.Connection, phone_number: str, auth_code: str, mac_address: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """인증코드 검증"""
    # 해당 전화번호의 최신 인증 요청 조회
    query = "SELECT * FROM wifi_auth WHERE phone_number = ? ORDER BY created_at DESC LIMIT 1"
    result = db.execute(query, (phone_number,))
    wifi_auth = result.fetchone()
    
    if not wifi_auth:
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="만료되었거나 유효하지 않은 인증코드입니다. 새로운 인증을 요청해주세요."
        )
    
    is_valid = auth_code_record['auth_code'] == auth_code
    
    if is_valid:
        # 인증코드 사용 처리
        db.execute("UPDATE auth_codes SET is_used = 1 WHERE id = ?", (auth_code_record['id'],))
        
        # WiFi 인증 완료 처리
        update_query = """UPDATE wifi_auth 
                        SET is_authenticated = 1, mac_address = ?, auth_completed_at = ? 
                        WHERE id = ?"""
        db.execute(update_query, (mac_address, datetime.now(), wifi_auth_id))
        
        return True, row_to_dict(wifi_auth)
    
    return False, row_to_dict(wifi_auth)


def check_wifi_auth_status(db: sqlite3.Connection, phone_number: str, mac_address: Optional[str] = None) -> Dict[str, Any]:
    """WiFi 인증 상태 확인"""
    query = "SELECT * FROM wifi_auth WHERE phone_number = ? ORDER BY created_at DESC LIMIT 1"
    result = db.execute(query, (phone_number,))
    wifi_auth = result.fetchone()
    
    if not wifi_auth:
        return {
            "is_authenticated": False,
            "message": "인증 기록이 없습니다. 인증을 진행해주세요."
        }
    
    wifi_auth_dict = row_to_dict(wifi_auth)
    
    return {
        "is_authenticated": wifi_auth_dict.get('is_authenticated') == 1,
        "phone_number": wifi_auth_dict.get('phone_number'),
        "created_at": wifi_auth_dict.get('created_at'),
        "auth_completed_at": wifi_auth_dict.get('auth_completed_at')
    }
