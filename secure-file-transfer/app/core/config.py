# app/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_NAME: str = "secure-file-transfer"
    ENV: str = "development"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    DATABASE_URL: str  # async URL
    REDIS_URL: str | None = None

    S3_ENDPOINT: str | None = None
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_BUCKET: str | None = None

    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    @property
    def DATABASE_URL_SYNC(self) -> str:
        """
        Convert asyncpg URL to sync psycopg URL for Alembic migrations.
        Example:
        async: postgresql+asyncpg://user:pass@localhost/db
        sync:  postgresql://user:pass@localhost/db
        """
        return self.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")


settings = Settings()
