# app/core/session.py
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    # Prefer python-jose for consistency across the codebase
    from jose import jwt, JWTError
except Exception:  # pragma: no cover - fallback shouldn't be required in this project
    jwt = None  # type: ignore
    JWTError = Exception  # type: ignore

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

from app.core.config import settings


ALGORITHM = "HS256"


class _InMemoryStore:
    """Minimal in-memory fallback store that mimics Redis setex/get for tests.

    Stores token -> (value, expires_at_epoch). Expired keys are lazily purged on get.
    """

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, int]] = {}

    def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        expires_at = int(datetime.now(timezone.utc).timestamp()) + int(ttl_seconds)
        self._data[key] = (value, expires_at)

    def get(self, key: str) -> Optional[str]:
        entry = self._data.get(key)
        if not entry:
            return None
        value, expires_at = entry
        now = int(datetime.now(timezone.utc).timestamp())
        if now >= expires_at:
            # expired – remove and return None
            self._data.pop(key, None)
            return None
        return value


def _build_store():
    """Try to create a Redis client; fall back to in-memory if unavailable.

    This makes tests independent of a running Redis instance while using Redis in dev/prod.
    """

    # Prefer explicit REDIS_URL if provided; otherwise default to localhost
    redis_url = settings.REDIS_URL or "redis://localhost:6379/0"
    if redis is None:
        return _InMemoryStore()
    try:
        client = redis.from_url(redis_url, decode_responses=True)  # type: ignore[attr-defined]
        # Light-touch connectivity check; don't explode tests if Redis is down
        try:
            client.ping()
        except Exception:
            return _InMemoryStore()
        return client
    except Exception:
        return _InMemoryStore()


_store = _build_store()


# -------------------- CREATE TOKEN --------------------
def create_access_token(user_id: int) -> str:
    """Create a JWT access token with expiration using shared project secrets."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": str(user_id), "exp": int(expire.timestamp())}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
    return token


# -------------------- REVOKE TOKEN --------------------
def revoke_token(token: str) -> None:
    """Mark a token as revoked in the token store until it naturally expires."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        exp_timestamp = int(payload.get("exp", 0))
        ttl = exp_timestamp - int(datetime.now(timezone.utc).timestamp())
        if ttl > 0:
            _store.setex(token, ttl, "revoked")
    except JWTError:
        # token invalid or expired – nothing to revoke
        return


# -------------------- CHECK REVOCATION --------------------
def is_token_revoked(token: str) -> bool:
    """Check if token is revoked."""
    return _store.get(token) is not None
