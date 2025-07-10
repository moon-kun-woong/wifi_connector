# FastAPI CRUD 애플리케이션

Python FastAPI를 사용한 간단한 CRUD애플리케이션입니다.
이 프로젝트는 SQLAlchemy ORM과 SQLite 데이터베이스를 사용합니다.

## 기술 스택

- Python 3.8.0
- FastAPI
- Uvicorn (ASGI 서버)
- SQLAlchemy 2.0 (ORM)
- SQLite (데이터베이스)

## 설치 방법

1. 의존성 설치:

```bash
pip install -r requirements.txt
```

## 실행 방법

1. 애플리케이션 실행:

```bash
uvicorn app.main:app --reload
```

2. 브라우저에서 다음 URL 접속:
   - API 문서: http://localhost:8000/docs (Swagger UI)

## 프로젝트 구조

```
TempFastAPIProject/
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI 애플리케이션 시작점
│   ├── database.py       # 데이터베이스 연결 설정
│   ├── models.py         # SQLAlchemy 모델 (데이터베이스 테이블)
│   ├── schemas.py        # Pydantic 모델/스키마 (요청/응답 검증)
│   └── crud.py           # CRUD 작업 함수
├── requirements.txt      # 의존성 패키지 목록
└── README.md             # 프로젝트 설명
```

## API 엔드포인트

- `POST /items/`: 새 아이템 생성
- `GET /items/`: 모든 아이템 조회
- `GET /items/{item_id}`: ID로 특정 아이템 조회
- `PUT /items/{item_id}`: 아이템 업데이트
- `DELETE /items/{item_id}`: 아이템 삭제
