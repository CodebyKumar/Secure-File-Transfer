# app/routes/health.py
from fastapi import APIRouter
from ..core.config import settings

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "ok", "env": settings.ENV}
