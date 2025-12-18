# WiFi 캡티브 포털 서비스

**병원용 완전한 캡티브 포털 시스템**

Python FastAPI 기반의 실제 네트워크 접근 제어가 가능한 WiFi 캡티브 포털입니다. SMS 인증을 통해 사용자를 인증하고, 라우터/방화벽과 연동하여 실제 인터넷 접근을 제어합니다.

## 주요 기능

### **완전한 캡티브 포털**
- **실제 네트워크 접근 제어** - iptables, pfSense, RADIUS 연동
- **DNS 리다이렉션** - 인증되지 않은 사용자를 캡티브 포털로 리다이렉트
- **MAC 주소 기반 세션 관리** - 디바이스별 접근 제어

### **SMS 인증 시스템**
- **Twilio API 연동** - 안정적인 SMS 발송
- **6자리 인증 코드** - 3분 만료 시간
- **전화번호 검증** - 한국 휴대폰 번호 형식 검증

### **세션 관리**
- **1일 자동 만료** - 인증 후 24시간 접속 유지
- **자동 재인증** - 만료된 세션 자동 정리
- **실시간 모니터링** - 활성 사용자 및 세션 추적

### **관리자 기능**
- **사용자 관리** - 특정 번호/디바이스 차단/허용
- **접근 로그** - 상세한 인증 및 접근 기록
- **통계 대시보드** - 사용 현황 및 통계 조회
- **세션 제어** - 실시간 세션 관리 및 강제 종료

## 기술 스택

### **백엔드**
- **Python 3.8+**
- **FastAPI**
- **SQLite**
- **Uvicorn**

### **네트워크 제어**
- **iptables** - Linux 방화벽 제어
- **pfSense API** - pfSense 라우터 연동
- **RADIUS** - 엔터프라이즈 인증 서버 지원

### **외부 서비스**
- **Twilio API** - SMS 발송 서비스
- **Jinja2** - HTML 템플릿 엔진

## 프로젝트 구조

```
wifi_connector/
├── app/
│   ├── auth/                    # 인증 관련 모듈
│   │   ├── service.py          # WiFi 인증 로직
│   │   └── sms_service.py      # SMS 발송 서비스
│   ├── network/                 # 네트워크 제어 모듈
│   │   ├── network_control.py  # 실제 네트워크 제어
│   │   └── network_service.py  # 세션 관리
│   ├── admin/                   # 관리자 기능
│   │   └── admin_service.py    # 관리자 인증/관리
│   ├── models/                  # 데이터베이스 모델
│   │   ├── database.py         # DB 연결/초기화
│   │   └── schemas.py          # Pydantic 스키마
│   ├── core/                    # 핵심 설정
│   ├── api/                     # API 라우터
│   ├── utils/                   # 유틸리티
│   └── main.py                  # FastAPI 메인 앱
├── static/                      # 정적 파일
├── templates/                   # HTML 템플릿
├── tests/                       # 테스트 파일
├── .env                         # 환경 변수
├── requirements.txt             # 의존성
└── README.md                    # 프로젝트 문서
```

## 설치 및 실행

### 1. **의존성 설치**

```bash
pip install -r requirements.txt
```

### 2. **환경 설정**

`.env` 파일을 생성하고 다음 내용을 설정합니다:

```env
# 데이터베이스 설정
DB_FILE=app.db

# 서버 설정
DEBUG=True
LOG_LEVEL=DEBUG

# Twilio SMS 설정
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+1234567890

# 네트워크 제어 설정
NETWORK_CONTROLLER_TYPE=iptables  # iptables, pfsense, radius
NETWORK_INTERFACE=wlan0
CAPTIVE_PORTAL_IP=192.168.1.1
CAPTIVE_PORTAL_PORT=8000

# pfSense 설정 (NETWORK_CONTROLLER_TYPE=pfsense일 때)
# PFSENSE_API_URL=https://192.168.1.1
# PFSENSE_API_KEY=your_api_key
# PFSENSE_API_SECRET=your_api_secret

# RADIUS 설정 (NETWORK_CONTROLLER_TYPE=radius일 때)
# RADIUS_SERVER=localhost
# RADIUS_PORT=1812
# RADIUS_SECRET=testing123
```

### 3. **애플리케이션 실행**

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. **접속 확인**

- **메인 페이지**: http://localhost:8000
- **API 문서**: http://localhost:8000/docs
- **인증 페이지**: http://localhost:8000/auth

## API 엔드포인트

### **웹 페이지**
- `GET /` - 메인 랜딩 페이지
- `GET /auth` - WiFi 인증 페이지 (전화번호 입력)
- `GET /verify/{phone_number}` - 인증번호 확인 페이지
- `GET /success` - 인증 성공 페이지

### **인증 API**
- `POST /api/auth/send-code` - 인증 코드 SMS 발송
- `POST /api/auth/verify-code` - 인증 코드 확인 및 네트워크 접근 허용
- `GET /api/auth/status` - WiFi 인증 상태 확인

### **네트워크 제어 API**
- `POST /api/network/revoke-access` - 사용자 네트워크 접근 취소
- `POST /api/network/cleanup-sessions` - 만료된 세션 정리
- `GET /api/network/check-access` - 네트워크 접근 상태 확인

## 네트워크 제어 설정

### **Linux (iptables) 환경**
```bash
# root 권한 필요
sudo iptables -L  # 현재 규칙 확인

# 환경 변수 설정
NETWORK_CONTROLLER_TYPE=iptables
NETWORK_INTERFACE=wlan0
CAPTIVE_PORTAL_IP=192.168.1.1
```

### **pfSense 라우터 환경**
```env
NETWORK_CONTROLLER_TYPE=pfsense
PFSENSE_API_URL=https://192.168.1.1
PFSENSE_API_KEY=your_api_key
PFSENSE_API_SECRET=your_api_secret
PFSENSE_INTERFACE=LAN
```

### **RADIUS 서버 환경**
```env
NETWORK_CONTROLLER_TYPE=radius
RADIUS_SERVER=192.168.1.10
RADIUS_PORT=1812
RADIUS_SECRET=your_radius_secret
RADIUS_NAS_IDENTIFIER=wifi-captive-portal
```

## 데이터베이스 스키마

### **주요 테이블**
- `wifi_auth` - WiFi 인증 정보
- `auth_codes` - SMS 인증 코드
- `network_sessions` - 네트워크 세션 관리
- `blocked_devices` - 차단된 디바이스
- `whitelisted_devices` - 허용된 디바이스
- `admin_users` - 관리자 계정
- `system_logs` - 시스템 로그

## 운영 환경 배포

### **병원 서버 배포 시 고려사항**

1. **네트워크 설정**
   - 라우터/방화벽과의 연동 설정
   - DHCP 서버와 캡티브 포털 연동
   - DNS 리다이렉션 설정

2. **보안 설정**
   - HTTPS 인증서 설정
   - 관리자 계정 보안 강화
   - 로그 파일 보안 관리

3. **성능 최적화**
   - 동시 사용자 30명 기준 최적화
   - 데이터베이스 백업 자동화
   - 로그 로테이션 설정

### **시스템 요구사항**
- **OS**: Linux (Ubuntu 20.04+ 권장)
- **Python**: 3.8 이상
- **메모리**: 최소 2GB RAM
- **디스크**: 최소 10GB 여유 공간
- **네트워크**: 관리자 권한 (iptables 사용 시)

## 로깅 시스템

### **로그 레벨**
- `INFO` - 일반적인 시스템 동작
- `WARNING` - 주의가 필요한 상황
- `ERROR` - 오류 발생 상황
- `DEBUG` - 디버깅 정보 (개발 모드)

### **로그 파일**
- `info.log` - 메인 로그 파일 (최대 1500줄)
- `info.log.1`, `info.log.2`, `info.log.3` - 백업 로그 파일

### **시스템 로그 카테고리**
- `AUTH` - 인증 관련 로그
- `NETWORK` - 네트워크 제어 로그
- `ADMIN` - 관리자 활동 로그
- `SMS` - SMS 발송 로그

## 문제 해결

### **일반적인 문제들**

1. **SMS 발송 실패 시**
   
   **DEBUG 모드 활성화**
   ```bash
   # .env 파일에서 DEBUG 설정 확인
   cat .env | grep DEBUG
   
   # DEBUG=True인 경우 실제 SMS 발송되지 않음 (로그에만 기록)
   # 실제 SMS 발송을 위해서는 DEBUG=False로 변경
   ```
   
   **Twilio 설정 확인**
   ```bash
   # Twilio 연동 테스트
   python -c "from app.auth.sms_service import send_sms; print(send_sms('01012345678', '123456'))"
   
   # 환경변수 확인
   echo $TWILIO_ACCOUNT_SID
   echo $TWILIO_AUTH_TOKEN  
   echo $TWILIO_PHONE_NUMBER
   ```

2. **네트워크 제어 실패 시**
   ```bash
   # iptables 권한 확인
   sudo iptables -L WIFI_CAPTIVE
   ```

3. **데이터베이스 오류 시**
   ```bash
   # 데이터베이스 재초기화
   rm app.db
   python -c "from app.models.database import init_db; init_db()"
   ```

## 기여하기

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 라이선스

This project is licensed under the MIT License - see the LICENSE file for details.

## 지원

문제가 발생하거나 질문이 있으시면 이슈를 생성해주세요.

---

**병원 WiFi 환경을 위한 완전한 캡티브 포털 솔루션** 🚀
