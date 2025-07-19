"""
SMS 메시지 전송을 위한 모듈 - Twilio API 및 이메일 SMS 게이트웨이 활용
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from typing import Dict, Optional
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

# .env 파일에서 환경 변수 값을 로드
load_dotenv()

# 이메일 SMTP 설정 불러오기
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')

# 통신사 SMS 게이트웨이 정보
CARRIER_MAP = {
    'skt': '@sms.skt.com',      # SKT
    'kt': '@lms.kt.com',        # KT
    'lgu': '@lms.uplus.co.kr',  # LG U+
    'skt_mms': '@mms.skt.com',  # SKT MMS
    'kt_mms': '@mms.kt.com',    # KT MMS
    'lgu_mms': '@mms.uplus.co.kr'  # LG U+ MMS
}

# 기본 통신사 설정
DEFAULT_CARRIER = os.getenv('DEFAULT_CARRIER', 'skt')

# Twilio 설정
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER', '')

# Twilio 클라이언트 초기화
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        logging.info("Twilio 클라이언트가 초기화되었습니다.")
    except Exception as e:
        logging.error(f"Twilio 클라이언트 초기화 실패: {e}")

logger = logging.getLogger(__name__)

def detect_carrier(phone_number: str) -> str:
    """
    전화번호 앞자리를 기준으로 통신사를 추측합니다.
    정확한 통신사 구분이 필요한 경우 사용자에게 직접 확인해야 합니다.
    
    Args:
        phone_number: 전화번호 (010-xxxx-xxxx 형식)
        
    Returns:
        str: 통신사 코드 ('skt', 'kt', 'lgu' 중 하나)
    """
    # 전화번호에서 하이픈 제거
    clean_number = phone_number.replace('-', '')
    
    # 앞 3자리는 무조건 010이므로 그 다음 번호를 확인
    if len(clean_number) >= 4:
        fourth_digit = clean_number[3]
        
        # 통신사별 번호 할당 범위에 따른 추측 (100% 정확하지 않음)
        if fourth_digit in ['1', '6', '9']:
            return 'skt'
        elif fourth_digit in ['2', '4', '7', '8']:
            return 'kt'
        elif fourth_digit in ['3', '5']:
            return 'lgu'
    
    # 판단할 수 없는 경우 기본값 반환
    return DEFAULT_CARRIER

def send_sms_via_email_gateway(phone_number: str, message: str, carrier: Optional[str] = None) -> bool:
    """
    이메일-SMS 게이트웨이를 통해 SMS 메시지를 전송합니다.
    한국 통신사들은 이메일을 SMS로 변환해주는 무료 서비스를 제공합니다.
    
    Args:
        phone_number: 수신자 전화번호 (하이픈 포함 가능)
        message: 전송할 메시지 내용
        carrier: 통신사 코드 ('skt', 'kt', 'lgu'). 지정하지 않으면 자동 감지
        
    Returns:
        bool: 전송 성공 여부
    """
    # 로그 기록
    logger.info(f"[이메일-SMS 발송 시도] 수신자: {phone_number}, 내용: {message}")
    
    # SMTP 설정이 비어있는 경우 로깅만 수행
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        logger.warning("[이메일-SMS 발송 실패] SMTP 계정 정보가 설정되지 않았습니다. 환경 변수를 확인하세요.")
        logger.warning(f"SMTP_USERNAME: {'설정됨' if SMTP_USERNAME else '설정되지 않음'}, SMTP_PASSWORD: {'설정됨' if SMTP_PASSWORD else '설정되지 않음'}")
        return False
        
    try:
        # 전화번호에서 하이픈 제거
        clean_number = phone_number.replace('-', '')
        logger.debug(f"정제된 전화번호: {clean_number}")
        
        # 통신사가 지정되지 않은 경우 추측
        if not carrier:
            carrier = detect_carrier(phone_number)
            logger.debug(f"자동 감지된 통신사: {carrier}")
            
        # 통신사별 SMS 게이트웨이 주소 가져오기
        if carrier not in CARRIER_MAP:
            logger.warning(f"[이메일-SMS 발송 실패] 알 수 없는 통신사 코드: {carrier}, 기본값 사용")
            carrier = DEFAULT_CARRIER
            
        carrier_domain = CARRIER_MAP[carrier]
        logger.debug(f"사용될 SMS 게이트웨이 도메인: {carrier_domain}")
        
        # 이메일 수신자 주소 생성 (전화번호@통신사도메인)
        recipient_email = f"{clean_number}{carrier_domain}"
        logger.debug(f"수신자 이메일 주소: {recipient_email}")
        
        # 이메일 메시지 생성
        msg = MIMEText(message)
        msg['Subject'] = ''
        msg['From'] = SMTP_USERNAME
        msg['To'] = recipient_email
        
        # SMTP 서버 연결 및 이메일 전송
        logger.debug(f"SMTP 서버 연결 시도: {SMTP_SERVER}:{SMTP_PORT}")
        try:
            logger.info(f"SMTP 서버 연결 시도: {SMTP_SERVER}:{SMTP_PORT}")
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                logger.info("SMTP 서버에 연결됨, TLS 시작")
                server.starttls()  # TLS 보안 연결
                logger.info("SMTP 로그인 시도")
                logger.info(f"SMTP 사용자명: {SMTP_USERNAME[:4]}*** / 비밀번호 길이: {len(SMTP_PASSWORD)}")
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                logger.info("SMTP 로그인 성공, 메일 전송 시도")
                server.sendmail(SMTP_USERNAME, recipient_email, msg.as_string())
                logger.info(f"메일 전송 완료: {recipient_email}")
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"[이메일-SMS 발송 실패] SMTP 인증 오류: {str(e)}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"[이메일-SMS 발송 실패] SMTP 오류: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"[이메일-SMS 발송 실패] 기타 예외 발생: {str(e)}")
            return False
            
        logger.info(f"[이메일-SMS 발송 성공] 수신자: {phone_number} (통신사: {carrier})")
        return True
        
    except smtplib.SMTPException as e:
        logger.exception(f"[이메일-SMS 발송 실패] SMTP 오류: {str(e)}")
        return False
    except Exception as e:
        logger.exception(f"[이메일-SMS 발송 실패] 예상치 못한 오류: {str(e)}")
        return False

def send_sms_via_twilio(phone_number: str, message: str) -> bool:
    """
    Twilio API를 사용하여 SMS 메시지를 전송합니다.
    
    Args:
        phone_number: 수신자 전화번호 (하이픈 포함 가능)
        message: 전송할 메시지 내용
        
    Returns:
        bool: 전송 성공 여부
    """
    # 로그 기록
    logger.info(f"[Twilio SMS 발송 시도] 수신자: {phone_number}, 내용: {message}")
    
    # Twilio 설정 확인
    if not twilio_client:
        logger.warning("[Twilio SMS 발송 실패] Twilio 클라이언트가 초기화되지 않았습니다.")
        return False
        
    if not TWILIO_PHONE_NUMBER:
        logger.warning("[Twilio SMS 발송 실패] Twilio 전화번호가 설정되지 않았습니다.")
        return False
        
    try:
        # 전화번호 형식 처리 (국제 형식으로 변환: +82)
        clean_number = phone_number.replace('-', '')
        # 010으로 시작하는 경우 +82로 변환
        if clean_number.startswith('0'):
            international_number = '+82' + clean_number[1:]
        else:
            international_number = phone_number  # 이미 국제 형식인 경우
        
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
        logger.error(f"[Twilio SMS 발송 실패] Twilio 오류: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"[Twilio SMS 발송 실패] 예상치 못한 오류: {str(e)}")
        return False

def send_sms(phone_number: str, message: str, carrier: Optional[str] = None, use_twilio: bool = True) -> bool:
    """
    SMS 메시지를 전송합니다. 
    Twilio API 또는 이메일-SMS 게이트웨이를 통해 전송할 수 있습니다.
    
    Args:
        phone_number: 수신자 전화번호 (하이픈 포함 가능)
        message: 전송할 메시지 내용
        carrier: 통신사 코드 ('skt', 'kt', 'lgu'). 지정하지 않으면 자동 감지
        use_twilio: True면 Twilio API를 사용, False면 이메일-SMS 게이트웨이 사용
        
    Returns:
        bool: 전송 성공 여부
    """
    # Twilio 사용 선택 시
    if use_twilio:
        result = send_sms_via_twilio(phone_number, message)
        if not result:
            logger.warning("Twilio 발송 실패, 이메일-SMS 게이트웨이로 시도합니다.")
            return send_sms_via_email_gateway(phone_number, message, carrier)
        return result
    
    # 이메일-SMS 게이트웨이 사용
    return send_sms_via_email_gateway(phone_number, message, carrier)