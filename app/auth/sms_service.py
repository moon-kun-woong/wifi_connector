import logging
import os
from typing import Optional

from dotenv import load_dotenv
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

load_dotenv()

TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER', '')

# 테스트/개발 모드 설정
DEBUG_MODE = os.getenv('DEBUG', 'True').lower() in ('true', 't', '1', 'yes', 'y')

# Twilio 클라이언트 초기화
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        logging.info("Twilio 클라이언트가 초기화되었습니다.")
    except Exception as e:
        logging.error(f"Twilio 클라이언트 초기화 실패: {e}")
        twilio_client = None

logger = logging.getLogger(__name__)

def format_phone_number(phone_number: str) -> str:
    """
    전화번호를 국제 형식(+82)으로 변환합니다.
    
    Args:
        phone_number: 전화번호 (010-xxxx-xxxx 또는 01xxxxxxxx 형식)
        
    Returns:
        str: 국제 형식 전화번호 (+82xxxxxxxxx)
    """
    # 전화번호에서 하이픈과 공백 제거
    clean_number = phone_number.replace('-', '').replace(' ', '')
    
    # 010으로 시작하는 경우 +82로 변환
    if clean_number.startswith('0'):
        return '+82' + clean_number[1:]
    elif clean_number.startswith('+82'):
        return clean_number  # 이미 국제 형식
    else:
        return '+82' + clean_number  # 기타 경우

def send_sms(phone_number: str, message: str) -> bool:
    """
    Twilio API를 사용하여 SMS 메시지를 전송합니다.
    
    Args:
        phone_number: 수신자 전화번호 (하이픈 포함 가능)
        message: 전송할 메시지 내용
        
    Returns:
        bool: 전송 성공 여부
    """
    # 개발/테스트 모드에서는 실제 SMS를 발송하지 않고 로그만 기록
    if DEBUG_MODE:
        logger.info(f"[테스트 모드] SMS 발송 시뮬레이션 - 수신자: {phone_number}, 내용: {message}")
        return True
    
    # 로그 기록
    logger.info(f"[Twilio SMS 발송 시도] 수신자: {phone_number}, 내용: {message}")
    
    # Twilio 설정 확인
    if not twilio_client:
        logger.error("[Twilio SMS 발송 실패] Twilio 클라이언트가 초기화되지 않았습니다.")
        logger.error("TWILIO_ACCOUNT_SID와 TWILIO_AUTH_TOKEN 환경 변수를 확인하세요.")
        return False
        
    if not TWILIO_PHONE_NUMBER:
        logger.error("[Twilio SMS 발송 실패] Twilio 전화번호가 설정되지 않았습니다.")
        logger.error("TWILIO_PHONE_NUMBER 환경 변수를 확인하세요.")
        return False
        
    try:
        # 전화번호를 국제 형식으로 변환
        international_number = format_phone_number(phone_number)
        logger.debug(f"국제 형식 전화번호: {international_number}")
        
        # Twilio로 SMS 발송
        message_result = twilio_client.messages.create(
            to=international_number,
            from_=TWILIO_PHONE_NUMBER,
            body=message
        )
        
        logger.info(f"[Twilio SMS 발송 성공] 메시지 SID: {message_result.sid}")
        return True
        
    except TwilioRestException as e:
        logger.error(f"[Twilio SMS 발송 실패] Twilio API 오류: {str(e)}")
        logger.error(f"오류 코드: {e.code}, 상태: {e.status}")
        return False
    except Exception as e:
        logger.error(f"[Twilio SMS 발송 실패] 예상치 못한 오류: {str(e)}")
        return False

def validate_phone_number(phone_number: str) -> bool:
    """
    전화번호 형식이 유효한지 검증합니다.
    
    Args:
        phone_number: 검증할 전화번호
        
    Returns:
        bool: 유효한 전화번호인지 여부
    """
    # 전화번호에서 하이픈과 공백 제거
    clean_number = phone_number.replace('-', '').replace(' ', '')
    
    # 한국 휴대폰 번호 형식 검증 (010으로 시작하는 11자리)
    if len(clean_number) == 11 and clean_number.startswith('010'):
        return clean_number.isdigit()
    
    # 국제 형식 검증 (+82로 시작)
    if clean_number.startswith('+82') and len(clean_number) == 13:
        return clean_number[3:].isdigit()
    
    return False
