# app/main.py
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware


from .core.config import settings
from app.routes.health import router as health_router
from app.api.v1 import auth


app = FastAPI(title=settings.APP_NAME)

# Basic CORS for dev (adjust in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
async def health():
    return {"status": "ok", "env": settings.ENV}


app.include_router(health_router, prefix="/api/v1")

app.include_router(auth.router)
