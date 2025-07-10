from fastapi import FastAPI, Depends, HTTPException, status, Response, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
import sqlite3
from typing import List, Dict, Any, Optional
import logging
import os
from pathlib import Path
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 테스트/개발 모드 설정
DEBUG_MODE = os.getenv('DEBUG', 'True').lower() in ('true', 't', '1', 'yes', 'y')

from . import schemas, crud
from .database import get_db
from .sms_service import send_sms

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

if not TEMPLATES_DIR.exists():
    TEMPLATES_DIR.mkdir(parents=True)
if not STATIC_DIR.exists():
    STATIC_DIR.mkdir(parents=True)

app = FastAPI(
    title="WiFi 인증 서비스",
    description="병원 WiFi 인증을 위한 REST API",
    version="1.0.0",
    openapi_tags=[
        {
            "name": "WiFi 인증",
            "description": "WiFi 접속 인증 관련 API"
        }
    ]
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Jinja2 템플릿 설정
templates = Jinja2Templates(directory=TEMPLATES_DIR)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('info.log', 'a', 'utf-8') # "a" 는 append 모드 : 파일이 존재하면 파일 맨 끝에 로그 추가
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    
    req_body = await request.body()
    request._body = req_body
    
    # 요청 본문 로깅 추가
    if req_body:
        try:
            decoded_req = req_body.decode('utf-8')
            logger.info(f"[요청 본문] {decoded_req}")
        except UnicodeDecodeError:
            logger.info(f"[요청 본문(바이너리)] {req_body}")
    
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk
    
    if response_body:
        try:
            decoded_res = response_body.decode('utf-8')
            logger.info(f"[응답 본문] {decoded_res}")
        except UnicodeDecodeError:
            logger.info(f"[응답 본문(에러)] {response_body}")
    
    return Response(
        content=response_body,
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=response.media_type
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exception: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({
            "detail": exception.errors(),
            "message": "입력 데이터 유효성 검증에 실패했습니다."
        }),
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exception: HTTPException):
    return JSONResponse(
        status_code=exception.status_code,
        content={
            "detail": exception.detail,
            "status_code": exception.status_code
        },
    )

# ===== WiFi 인증 관련 라우트 =====

@app.get("/", response_class=HTMLResponse, tags=["WiFi 인증"])
async def main_page(request: Request):
    """기본 랜딩 페이지"""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "title": "WiFi 인증 서비스"}
    )

@app.get("/auth", response_class=HTMLResponse, tags=["WiFi 인증"])
async def auth_page(request: Request):
    """인증 페이지"""
    return templates.TemplateResponse(
        "auth.html",
        {"request": request, "title": "WiFi 인증"}
    )

@app.get("/verify", response_class=HTMLResponse, tags=["WiFi 인증"])
async def verify_page(request: Request, phone_number: str):
    """인증번호 확인 페이지"""
    return templates.TemplateResponse(
        "verify.html",
        {"request": request, "phone_number": phone_number, "title": "인증번호 확인"}
    )

@app.get("/success", response_class=HTMLResponse, tags=["WiFi 인증"])
async def success_page(request: Request):
    """인증 성공 페이지"""
    return templates.TemplateResponse(
        "success.html",
        {"request": request, "title": "인증 성공"}
    )

@app.post(
    "/api/auth/send-code", 
    response_model=schemas.SendSMSResponse, 
    tags=["WiFi 인증"], 
    summary="인증 코드 전송",
    description="전화번호로 인증 코드를 전송합니다."
)
async def send_auth_code(
    request: schemas.PhoneNumberRequest,
    db: sqlite3.Connection = Depends(get_db)
):
    # MAC 주소는 클라이언트 정보에서 추출할 수 있음(옵션)
    mac_address = request.mac_address
    
    # 인증 코드 생성 및 DB 저장
    auth_data = crud.create_wifi_auth_request(db, request.phone_number, mac_address)
    
    # SMS 메시지 구성
    auth_code = auth_data.get("auth_code")
    message = f"[WiFi 인증] 인증번호 [{auth_code}]를 입력해주세요."
    
    # DEBUG_MODE에 따라 SMS 전송 방식 결정
    if DEBUG_MODE:
        # 개발/테스트 모드: SMS 전송 생략하고 로그만 기록
        logger.info(f"[테스트 모드] 인증번호 {auth_code} 가 생성됨 (전화번호: {request.phone_number})")
        send_result = True
    else:
        # 실제 운영 모드: 실제 SMS 발송 시도
        logger.info(f"[운영 모드] SMS 발송 시도 (전화번호: {request.phone_number})")
        send_result = send_sms(request.phone_number, message)
        if not send_result:
            logger.error(f"SMS 전송 실패: {request.phone_number}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="인증번호 발송에 실패하였습니다. 다시 시도해주세요."
            )
    
    return {
        "message": "인증번호가 발송되었습니다.",
        "phone_number": request.phone_number,
        "expires_in": 180  # 3분 유효
    }

@app.post(
    "/api/auth/verify-code", 
    response_model=schemas.VerifyAuthResponse, 
    tags=["WiFi 인증"], 
    summary="인증 코드 확인",
    description="전화번호와 인증 코드를 확인합니다."
)
async def verify_auth_code(
    request: schemas.AuthCodeRequest,
    db: sqlite3.Connection = Depends(get_db)
):
    # 인증 코드 확인
    is_valid, auth_data = crud.verify_auth_code(db, request.phone_number, request.auth_code, request.mac_address)
    
    if is_valid:
        return {
            "message": "WiFi 인증이 완료되었습니다.",
            "is_authenticated": True,
            "phone_number": request.phone_number
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="유효하지 않은 인증 코드입니다."
        )

@app.get(
    "/api/auth/status", 
    tags=["WiFi 인증"], 
    summary="WiFi 인증 상태 확인",
    description="전화번호 또는 MAC 주소로 인증 상태를 확인합니다."
)
async def check_auth_status(
    phone_number: Optional[str] = None,
    mac_address: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db)
):
    if not phone_number and not mac_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="전화번호 또는 MAC 주소 중 하나는 제공해야 합니다."
        )
    
    if phone_number:
        return crud.check_wifi_auth_status(db, phone_number, mac_address)
    
    # MAC 주소로만 조회하는 경우 (추가 구현 필요)
    return {
        "is_authenticated": False,
        "message": "MAC 주소로만 조회하는 기능은 현재 구현 중입니다."
    }
