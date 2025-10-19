from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import inventory, download, playbooks
from app.database import Base, engine

app = FastAPI(
    title="OneClickSecure API",
    description="플레이북 관리와 인벤터리 시스템",
    version="1.0.0"
)

# CORS 미들웨어 - 문법 오류 수정
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001"
    ], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# DB 테이블 자동 생성
Base.metadata.create_all(bind=engine)

# 라우터 등록
app.include_router(inventory.router)
app.include_router(download.router, prefix="/api")
app.include_router(playbooks.router)

@app.get("/")
def root():
    return {
        "message": "OneClickSecure API is running",
        "status": "healthy",
        "features": {
            "inventory": True,
            "playbooks": True,
            "download": True
        }
    }