# WiFi 인증 서비스

Python FastAPI를 사용한 병원용 WiFi 인증 서비스입니다.
이 프로젝트는 SQLite 데이터베이스를 사용하여 사용자 인증 정보를 관리하고, SMS를 통한 인증 코드 발송 기능을 제공합니다.

## 기술 스택

- Python 3.8+
- FastAPI
- Uvicorn (ASGI 서버)
- Jinja2 (템플릿 엔진)
- SQLite (데이터베이스)
- 문자 메시지 발송 서비스 (운영 모드)

## 설치 방법

1. 의존성 설치:

```bash
pip install -r requirements.txt
```

2. 환경 설정:
   `.env` 파일을 생성하고 다음 내용을 설정합니다:

```
DEBUG=True  # 개발/테스트 모드 (True) 또는 운영 모드 (False)
SMS_API_KEY=your_sms_api_key  # SMS 서비스 API 키 (운영 모드)
```

## 실행 방법

1. 애플리케이션 실행:

```bash
uvicorn app.main:app --reload
```

2. 브라우저에서 다음 URL 접속:
   - 메인 페이지: http://localhost:8000
   - API 문서: http://localhost:8000/docs (Swagger UI)

## 프로젝트 구조

```
wifi_connector/
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI 애플리케이션 시작점
│   ├── database.py       # 데이터베이스 연결 설정
│   ├── schemas.py        # Pydantic 모델/스키마 (요청/응답 검증)
│   ├── service.py        # 서비스 로직 구현
│   └── sms_service.py    # SMS 발송 관련 기능
├── templates/            # HTML 템플릿 파일
├── static/               # 정적 파일 (CSS, JS, 이미지 등)
├── .env                  # 환경 변수 설정
├── app.db                # SQLite 데이터베이스 파일
├── info.log              # 로그 파일
├── requirements.txt      # 의존성 패키지 목록
├── runtime.txt           # 런타임 버전 정보
└── README.md             # 프로젝트 설명
```

## API 엔드포인트

### 웹 페이지

- `GET /`: 메인 랜딩 페이지
- `GET /auth`: WiFi 인증 페이지 (전화번호 입력)
- `GET /verify`: 인증번호 확인 페이지
- `GET /success`: 인증 성공 페이지

### API

- `POST /api/auth/send-code`: 인증 코드 SMS 발송
- `POST /api/auth/verify-code`: 인증 코드 확인
- `GET /api/auth/status`: WiFi 인증 상태 확인

## 로깅 시스템

이 프로젝트는 요청/응답 로깅 시스템을 포함하고 있어 문제 해결과 모니터링에 도움이 됩니다. 로그는 `info.log` 파일에 저장되며, 최대 1500줄로 제한되어 3개의 백업 파일을 유지합니다.

## 개발 및 운영 모드

- **개발/테스트 모드** (DEBUG=True): 실제 SMS를 발송하지 않고 로그에 인증 코드를 기록합니다.
- **운영 모드** (DEBUG=False): 실제 SMS API를 통해 인증 코드를 발송합니다.
