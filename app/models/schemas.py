import re
from typing import Optional, List

from pydantic import BaseModel, Field, validator


class HTTPError(BaseModel):
    detail: str
    status_code: int

class ValidationErrorDetail(BaseModel):
    loc: List[str]
    msg: str
    type: str

class ValidationErrorResponse(BaseModel):
    detail: List[ValidationErrorDetail]
    message: str

class ConflictError(BaseModel):
    detail: str
    status_code: int = 409


# WiFi 인증 관련 스키마
class PhoneNumberRequest(BaseModel):
    phone_number: str = Field(..., description="사용자 전화번호")
    mac_address: Optional[str] = Field(None, description="기기 MAC 주소")
    
    @validator('phone_number')
    def validate_phone_number(cls, v):
        # 전화번호 형식 검증 (10-11자리 숫자, 하이픈(-) 허용)
        # 먼저 하이픈을 제거한 상태에서 검사
        clean_number = v.replace('-', '')
        
        # 10-11자리 숫자인지 확인
        if not clean_number.isdigit() or not (10 <= len(clean_number) <= 11):
            raise ValueError('올바른 전화번호 형식이 아닙니다 (예: 010-1234-5678)')
            
        # 휴대폰 번호는 010으로 시작해야 함
        if not clean_number.startswith('010'):
            raise ValueError('휴대폰 번호는 010으로 시작해야 합니다')
            
        return v  # 원래 값 그대로 반환 (검증만 수행)
    
    def get_clean_phone_number(self) -> str:
        """하이픈이 제거된 전화번호 반환"""
        return self.phone_number.replace('-', '')


class AuthCodeRequest(BaseModel):
    phone_number: str = Field(..., description="사용자 전화번호")
    auth_code: str = Field(..., description="인증 코드")
    mac_address: Optional[str] = Field(None, description="기기 MAC 주소")
    
    @validator('phone_number')
    def validate_phone_number(cls, v):
        # 전화번호 형식 검증 (10-11자리 숫자, 하이픈(-) 허용)
        # 먼저 하이픈을 제거한 상태에서 검사
        clean_number = v.replace('-', '')
        
        # 10-11자리 숫자인지 확인
        if not clean_number.isdigit() or not (10 <= len(clean_number) <= 11):
            raise ValueError('올바른 전화번호 형식이 아닙니다 (예: 010-1234-5678)')
            
        # 휴대폰 번호는 010으로 시작해야 함
        if not clean_number.startswith('010'):
            raise ValueError('휴대폰 번호는 010으로 시작해야 합니다')
            
        return clean_number  # 하이픈 제거된 번호 반환
    
    @validator('auth_code')
    def validate_auth_code(cls, v):
        if not v.isdigit() or len(v) != 6:
            raise ValueError('인증 코드는 6자리 숫자여야 합니다')
        return v


class SendSMSResponse(BaseModel):
    message: str
    phone_number: str
    expires_in: int = 180  # 초 단위 만료 시간 (3분)


class VerifyAuthResponse(BaseModel):
    message: str
    is_authenticated: bool
    phone_number: str
    network_access_granted: Optional[bool] = Field(None, description="네트워크 접근 허용 여부")


# 네트워크 제어 관련 스키마
class NetworkAccessRequest(BaseModel):
    phone_number: str = Field(..., description="사용자 전화번호")
    mac_address: str = Field(..., description="기기 MAC 주소")
    ip_address: Optional[str] = Field(None, description="클라이언트 IP 주소")


class NetworkAccessResponse(BaseModel):
    message: str
    phone_number: str
    mac_address: str
    access_revoked: bool


class NetworkStatusResponse(BaseModel):
    ip_address: str
    mac_address: str
    network_access_allowed: bool
    message: str


class SessionCleanupResponse(BaseModel):
    message: str
    cleaned_sessions: int
