# app/core/security.py

from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
import os


# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash the given password using bcrypt."""
    truncated_password = password[:72]
    return pwd_context.hash(truncated_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against the hashed version."""
    plain_password = plain_password[:72]
    return pwd_context.verify(plain_password, hashed_password)


# JWT configuration
ALGORITHM = "HS256"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token with an expiration time."""
    to_encode = data.copy()
    # Use timezone-aware UTC datetime and store numeric expiry (epoch seconds) for JWT 'exp'
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": int(expire.timestamp())})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# --- Symmetric encryption helpers (AES-GCM) ---
def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypt bytes using AES-GCM. Returns nonce + ciphertext_with_tag.

    The provided key is normalized to 32 bytes using SHA-256 so callers can pass arbitrary lengths.
    """
    norm_key = sha256(key).digest()
    nonce = os.urandom(12)
    aesgcm = AESGCM(norm_key)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Decrypt bytes produced by encrypt_bytes (nonce + ciphertext_with_tag)."""
    norm_key = sha256(key).digest()
    if len(data) < 13:  # nonce (12) + at least 1 byte of ciphertext/tag
        raise ValueError("Ciphertext too short")
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(norm_key)
    return aesgcm.decrypt(nonce, ct, None)


# (Removed legacy CFB helpers in favor of AES-GCM above)
