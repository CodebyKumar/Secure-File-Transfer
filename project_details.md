# Secure File Transfer System - Backend Development Documentation

## Project Overview

A FastAPI-based REST API for secure file sharing with end-to-end encryption, JWT authentication with 2FA, and scalable storage infrastructure.

### Tech Stack
- **Framework**: FastAPI
- **Database**: PostgreSQL
- **Cache/Session**: Redis
- **Object Storage**: MinIO
- **Encryption**: AES-256
- **Authentication**: JWT + 2FA (TOTP)
- **Package Manager**: uv

---

## 1. Project Setup

### 1.1 Prerequisites
- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- MinIO Server
- uv package manager

### 1.2 Install uv
```bash
# On macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 1.3 Initialize Project
```bash
# Create project directory
mkdir secure-file-transfer
cd secure-file-transfer

# Initialize uv project
uv init

# Create virtual environment
uv venv

# Activate virtual environment
# On Unix/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate
```

### 1.4 Install Dependencies
Create `pyproject.toml`:
```toml
[project]
name = "secure-file-transfer"
version = "0.1.0"
description = "Secure file transfer system with encryption and 2FA"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.109.0",
    "uvicorn[standard]>=0.27.0",
    "sqlalchemy>=2.0.25",
    "alembic>=1.13.1",
    "psycopg2-binary>=2.9.9",
    "redis>=5.0.1",
    "minio>=7.2.3",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
    "python-multipart>=0.0.6",
    "pydantic>=2.5.3",
    "pydantic-settings>=2.1.0",
    "cryptography>=42.0.0",
    "pyotp>=2.9.0",
    "qrcode>=7.4.2",
    "pillow>=10.2.0",
    "python-dotenv>=1.0.0",
    "email-validator>=2.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.4",
    "pytest-asyncio>=0.23.3",
    "httpx>=0.26.0",
    "black>=24.1.1",
    "ruff>=0.1.14",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

Install dependencies:
```bash
uv pip install -e ".[dev]"
```

---

## 2. Environment Configuration

Create `.env` file:
```env
# Application
APP_NAME=Secure File Transfer System
APP_VERSION=1.0.0
DEBUG=True
API_V1_PREFIX=/api/v1

# Security
SECRET_KEY=your-secret-key-here-generate-with-openssl-rand-hex-32
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
ENCRYPTION_KEY=your-encryption-key-base64-encoded-32-bytes

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/secure_file_transfer
DB_ECHO=False

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_SESSION_DB=1

# MinIO
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET_NAME=secure-files
MINIO_SECURE=False

# File Upload
MAX_FILE_SIZE=104857600  # 100MB in bytes
ALLOWED_EXTENSIONS=.pdf,.doc,.docx,.xls,.xlsx,.txt,.jpg,.png,.zip

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# 2FA
TWO_FACTOR_ISSUER=SecureFileTransfer
```

Create `.gitignore`:
```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
.venv/
venv/
env/

# Environment
.env
.env.local

# Database
*.db
*.sqlite3

# IDE
.vscode/
.idea/
*.swp
*.swo

# Testing
.pytest_cache/
.coverage
htmlcov/

# Logs
*.log

# OS
.DS_Store
Thumbs.db

# MinIO data
minio-data/
```

---

## 3. Core Configuration (`app/core/config.py`)

```python
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application
    APP_NAME: str = "Secure File Transfer System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENCRYPTION_KEY: str
    
    # Database
    DATABASE_URL: str
    DB_ECHO: bool = False
    
    # Redis
    REDIS_URL: str
    REDIS_SESSION_DB: int = 1
    
    # MinIO
    MINIO_ENDPOINT: str
    MINIO_ACCESS_KEY: str
    MINIO_SECRET_KEY: str
    MINIO_BUCKET_NAME: str = "secure-files"
    MINIO_SECURE: bool = False
    
    # File Upload
    MAX_FILE_SIZE: int = 104857600  # 100MB
    ALLOWED_EXTENSIONS: str = ".pdf,.doc,.docx,.xls,.xlsx,.txt,.jpg,.png,.zip"
    
    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:3000"
    
    # 2FA
    TWO_FACTOR_ISSUER: str = "SecureFileTransfer"
    
    @property
    def allowed_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]
    
    @property
    def allowed_extensions_list(self) -> List[str]:
        return [ext.strip() for ext in self.ALLOWED_EXTENSIONS.split(",")]


settings = Settings()
```

---

## 4. Database Models

### 4.1 User Model (`app/models/user.py`)
```python
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # 2FA
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    files = relationship("File", back_populates="owner", cascade="all, delete-orphan")
```

### 4.2 File Model (`app/models/file.py`)
```python
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, BigInteger, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.base import Base


class File(Base):
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)  # MinIO path
    file_size = Column(BigInteger, nullable=False)  # in bytes
    mime_type = Column(String, nullable=False)
    
    # Encryption
    encryption_key = Column(String, nullable=False)  # Encrypted with master key
    encryption_iv = Column(String, nullable=False)
    
    # Sharing
    is_public = Column(Boolean, default=False)
    share_token = Column(String, unique=True, nullable=True, index=True)
    share_expires_at = Column(DateTime, nullable=True)
    download_count = Column(Integer, default=0)
    max_downloads = Column(Integer, nullable=True)
    
    # Ownership
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="files")
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### 4.3 Database Base (`app/db/base.py`)
```python
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Import all models here for Alembic
from app.models.user import User
from app.models.file import File
```

### 4.4 Database Session (`app/db/session.py`)
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

---

## 5. Pydantic Schemas

### 5.1 User Schemas (`app/schemas/user.py`)
```python
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None


class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    two_factor_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    model_config = {"from_attributes": True}


class TwoFactorSetup(BaseModel):
    secret: str
    qr_code: str  # Base64 encoded QR code


class TwoFactorVerify(BaseModel):
    totp_code: str
```

### 5.2 File Schemas (`app/schemas/file.py`)
```python
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class FileUpload(BaseModel):
    is_public: bool = False
    max_downloads: Optional[int] = None
    share_expires_hours: Optional[int] = None


class FileResponse(BaseModel):
    id: int
    filename: str
    original_filename: str
    file_size: int
    mime_type: str
    is_public: bool
    share_token: Optional[str]
    share_expires_at: Optional[datetime]
    download_count: int
    max_downloads: Optional[int]
    created_at: datetime
    
    model_config = {"from_attributes": True}


class FileShare(BaseModel):
    max_downloads: Optional[int] = None
    expires_hours: int = Field(default=24, ge=1, le=720)  # Max 30 days


class FileShareResponse(BaseModel):
    share_url: str
    share_token: str
    expires_at: Optional[datetime]
```

### 5.3 Token Schemas (`app/schemas/token.py`)
```python
from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[int] = None
    email: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str
```

---

## 6. Services

### 6.1 Authentication Service (`app/services/auth_service.py`)
```python
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp
import qrcode
import io
import base64

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload
        except JWTError:
            return None
    
    @staticmethod
    def generate_totp_secret() -> str:
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(email: str, secret: str) -> str:
        """Generate QR code for 2FA setup"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=email,
            issuer_name=settings.TWO_FACTOR_ISSUER
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)


auth_service = AuthService()
```

### 6.2 Encryption Service (`app/services/encryption_service.py`)
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os


class EncryptionService:
    def __init__(self, master_key: str):
        self.master_key = base64.b64decode(master_key)
    
    def encrypt_file(self, file_data: bytes) -> tuple[bytes, str, str]:
        """
        Encrypt file data with AES-256
        Returns: (encrypted_data, base64_key, base64_iv)
        """
        # Generate random key and IV for this file
        key = os.urandom(32)  # 256 bits
        iv = os.urandom(16)   # 128 bits
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the key with master key
        encrypted_key = self._encrypt_key(key)
        
        return encrypted_data, encrypted_key, base64.b64encode(iv).decode()
    
    def decrypt_file(self, encrypted_data: bytes, encrypted_key: str, iv: str) -> bytes:
        """Decrypt file data"""
        # Decrypt the key
        key = self._decrypt_key(encrypted_key)
        iv_bytes = base64.b64decode(iv)
        
        # Decrypt data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def _encrypt_key(self, key: bytes) -> str:
        """Encrypt file key with master key"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_key = padder.update(key) + padder.finalize()
        
        encrypted = encryptor.update(padded_key) + encryptor.finalize()
        # Store IV + encrypted key
        return base64.b64encode(iv + encrypted).decode()
    
    def _decrypt_key(self, encrypted_key: str) -> bytes:
        """Decrypt file key with master key"""
        data = base64.b64decode(encrypted_key)
        iv = data[:16]
        encrypted = data[16:]
        
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_key = decryptor.update(encrypted) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        key = unpadder.update(padded_key) + unpadder.finalize()
        
        return key


# Initialize with master key from settings
from app.core.config import settings
encryption_service = EncryptionService(settings.ENCRYPTION_KEY)
```

### 6.3 Storage Service (`app/services/storage_service.py`)
```python
from minio import Minio
from minio.error import S3Error
from io import BytesIO
from app.core.config import settings
import uuid


class StorageService:
    def __init__(self):
        self.client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE
        )
        self.bucket_name = settings.MINIO_BUCKET_NAME
        self._ensure_bucket()
    
    def _ensure_bucket(self):
        """Create bucket if it doesn't exist"""
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
        except S3Error as e:
            print(f"Error creating bucket: {e}")
    
    def upload_file(self, file_data: bytes, filename: str) -> str:
        """Upload encrypted file to MinIO"""
        object_name = f"{uuid.uuid4()}/{filename}"
        
        try:
            self.client.put_object(
                self.bucket_name,
                object_name,
                BytesIO(file_data),
                length=len(file_data)
            )
            return object_name
        except S3Error as e:
            raise Exception(f"Failed to upload file: {e}")
    
    def download_file(self, object_name: str) -> bytes:
        """Download file from MinIO"""
        try:
            response = self.client.get_object(self.bucket_name, object_name)
            data = response.read()
            response.close()
            response.release_conn()
            return data
        except S3Error as e:
            raise Exception(f"Failed to download file: {e}")
    
    def delete_file(self, object_name: str):
        """Delete file from MinIO"""
        try:
            self.client.remove_object(self.bucket_name, object_name)
        except S3Error as e:
            raise Exception(f"Failed to delete file: {e}")


storage_service = StorageService()
```

---

## 7. CRUD Operations

### 7.1 User CRUD (`app/crud/crud_user.py`)
```python
from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.auth_service import auth_service
from datetime import datetime
from typing import Optional


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def create_user(db: Session, user: UserCreate) -> User:
    hashed_password = auth_service.get_password_hash(user.password)
    db_user = User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_last_login(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if user:
        user.last_login = datetime.utcnow()
        db.commit()


def enable_2fa(db: Session, user_id: int, secret: str):
    user = get_user_by_id(db, user_id)
    if user:
        user.two_factor_secret = secret
        user.two_factor_enabled = True
        db.commit()
        db.refresh(user)
    return user


def disable_2fa(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if user:
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.commit()
    return user
```

### 7.2 File CRUD (`app/crud/crud_file.py`)
```python
from sqlalchemy.orm import Session
from app.models.file import File
from datetime import datetime, timedelta
from typing import Optional, List
import secrets


def create_file(
    db: Session,
    filename: str,
    original_filename: str,
    file_path: str,
    file_size: int,
    mime_type: str,
    encryption_key: str,
    encryption_iv: str,
    owner_id: int,
    is_public: bool = False,
    max_downloads: Optional[int] = None
) -> File:
    db_file = File(
        filename=filename,
        original_filename=original_filename,
        file_path=file_path,
        file_size=file_size,
        mime_type=mime_type,
        encryption_key=encryption_key,
        encryption_iv=encryption_iv,
        owner_id=owner_id,
        is_public=is_public,
        max_downloads=max_downloads
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    return db_file


def get_file_by_id(db: Session, file_id: int, owner_id: int) -> Optional[File]:
    return db.query(File).filter(
        File.id == file_id,
        File.owner_id == owner_id
    ).first()


def get_file_by_share_token(db: Session, token: str) -> Optional[File]:
    return db.query(File).filter(File.share_token == token).first()


def get_user_files(db: Session, owner_id: int, skip: int = 0, limit: int = 100) -> List[File]:
    return db.query(File).filter(
        File.owner_id == owner_id
    ).offset(skip).limit(limit).all()


def create_share_link(
    db: Session,
    file_id: int,
    owner_id: int,
    expires_hours: int,
    max_downloads: Optional[int] = None
) -> Optional[File]:
    file = get_file_by_id(db, file_id, owner_id)
    if file:
        file.share_token = secrets.token_urlsafe(32)
        file.share_expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
        if max_downloads:
            file.max_downloads = max_downloads
        file.is_public = True
        db.commit()
        db.refresh(file)
    return file


def increment_download_count(db: Session, file_id: int):
    file = db.query(File).filter(File.id == file_id).first()
    if file:
        file.download_count += 1
        db.commit()


def delete_file(db: Session, file_id: int, owner_id: int) -> bool:
    file = get_file_by_id(db, file_id, owner_id)
    if file:
        db.delete(file)
        db.commit()
        return True
    return False
```

---

## 8. API Dependencies (`app/api/v1/deps.py`)

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.auth_service import auth_service
from app.crud import crud_user
from app.models.user import User

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    payload = auth_service.verify_token(token)
    
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = crud_user.get_user_by_id(db, int(user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user
```

---

## 9. API Endpoints

### 9.1 Auth Endpoints (`app/api/v1/endpoints/auth.py`)
```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.user import UserCreate, UserLogin, UserResponse, TwoFactorSetup, TwoFactorVerify
from app.schemas.token import Token, RefreshTokenRequest
from app.crud import crud_user
from app.services.auth_service import auth_service
from app.api.v1.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user exists
    db_user = crud_user.get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    new_user = crud_user.create_user(db, user)
    return new_user


@router.post("/login", response_model=Token)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login user with email/password and optional 2FA"""
    user = crud_user.get_user_by_email(db, user_data.email)
    
    if not user or not auth_service.verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Check 2FA if enabled
    if user.two_factor_enabled:
        if not user_data.totp_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA code required"
            )
        
        if not auth_service.verify_totp(user.two_factor_secret, user_data.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code"
            )
    
    # Update last login
    crud_user.update_last_login(db, user.id)
    
    # Generate tokens
    access_token = auth_service.create_access_token(data={"sub": str(user.id), "email": user.email})
    refresh_token = auth_service.create_refresh_token(data={"sub": str(user.id)})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh", response_model=Token)
def refresh_token(token_data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Refresh access token using refresh token"""
    payload = auth_service.verify_token(token_data.refresh_token)
    
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user_id = payload.get("sub")
    user = crud_user.get_user_by_id(db, int(user_id))
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Generate new tokens
    access_token = auth_service.create_access_token(data={"sub": str(user.id), "email": user.email})
    refresh_token = auth_service.create_refresh_token(data={"sub": str(user.id)})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/2fa/setup", response_model=TwoFactorSetup)
def setup_2fa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Setup 2FA for user"""
    if current_user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA already enabled"
        )
    
    # Generate secret
    secret = auth_service.generate_totp_secret()
    
    # Generate QR code
    qr_code = auth_service.generate_qr_code(current_user.email, secret)
    
    # Store secret temporarily (not enabled yet)
    current_user.two_factor_secret = secret
    db.commit()
    
    return {
        "secret": secret,
        "qr_code": qr_code
    }


@router.post("/2fa/verify")
def verify_2fa(
    verify_data: TwoFactorVerify,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify and enable 2FA"""
    if not current_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup not initiated"
        )
    
    if not auth_service.verify_totp(current_user.two_factor_secret, verify_data.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code"
        )
    
    # Enable 2FA
    crud_user.enable_2fa(db, current_user.id, current_user.two_factor_secret)
    
    return {"message": "2FA enabled successfully"}


@router.delete("/2fa/disable")
def disable_2fa(
    verify_data: TwoFactorVerify,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable 2FA"""
    if not current_user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not enabled"
        )
    
    if not auth_service.verify_totp(current_user.two_factor_secret, verify_data.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code"
        )
    
    crud_user.disable_2fa(db, current_user.id)
    
    return {"message": "2FA disabled successfully"}


@router.get("/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user
```

### 9.2 File Endpoints (`app/api/v1/endpoints/files.py`)
```python
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File as FastAPIFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import os

from app.db.session import get_db
from app.schemas.file import FileResponse, FileShare, FileShareResponse
from app.crud import crud_file
from app.services.encryption_service import encryption_service
from app.services.storage_service import storage_service
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.core.config import settings

router = APIRouter()


@router.post("/upload", response_model=FileResponse, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = FastAPIFile(...),
    is_public: bool = False,
    max_downloads: int = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload and encrypt a file"""
    # Validate file size
    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum allowed size of {settings.MAX_FILE_SIZE} bytes"
        )
    
    # Validate file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in settings.allowed_extensions_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file_ext} not allowed"
        )
    
    # Encrypt file
    encrypted_data, encrypted_key, iv = encryption_service.encrypt_file(content)
    
    # Upload to MinIO
    file_path = storage_service.upload_file(encrypted_data, file.filename)
    
    # Save metadata to database
    db_file = crud_file.create_file(
        db=db,
        filename=file.filename,
        original_filename=file.filename,
        file_path=file_path,
        file_size=len(content),
        mime_type=file.content_type or "application/octet-stream",
        encryption_key=encrypted_key,
        encryption_iv=iv,
        owner_id=current_user.id,
        is_public=is_public,
        max_downloads=max_downloads
    )
    
    return db_file


@router.get("/", response_model=List[FileResponse])
def list_files(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all files for current user"""
    files = crud_file.get_user_files(db, current_user.id, skip, limit)
    return files


@router.get("/{file_id}", response_model=FileResponse)
def get_file_info(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get file information"""
    file = crud_file.get_file_by_id(db, file_id, current_user.id)
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    return file


@router.get("/{file_id}/download")
async def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download and decrypt a file"""
    file = crud_file.get_file_by_id(db, file_id, current_user.id)
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Download encrypted file from MinIO
    encrypted_data = storage_service.download_file(file.file_path)
    
    # Decrypt file
    decrypted_data = encryption_service.decrypt_file(
        encrypted_data,
        file.encryption_key,
        file.encryption_iv
    )
    
    # Increment download count
    crud_file.increment_download_count(db, file.id)
    
    return StreamingResponse(
        iter([decrypted_data]),
        media_type=file.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{file.original_filename}"'
        }
    )


@router.post("/{file_id}/share", response_model=FileShareResponse)
def create_share_link(
    file_id: int,
    share_data: FileShare,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a shareable link for a file"""
    file = crud_file.create_share_link(
        db,
        file_id,
        current_user.id,
        share_data.expires_hours,
        share_data.max_downloads
    )
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    share_url = f"{settings.API_V1_PREFIX}/files/shared/{file.share_token}"
    
    return {
        "share_url": share_url,
        "share_token": file.share_token,
        "expires_at": file.share_expires_at
    }


@router.get("/shared/{token}")
async def download_shared_file(token: str, db: Session = Depends(get_db)):
    """Download a file using a share token (no authentication required)"""
    file = crud_file.get_file_by_share_token(db, token)
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired share link"
        )
    
    # Check if link expired
    if file.share_expires_at and file.share_expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Share link has expired"
        )
    
    # Check download limit
    if file.max_downloads and file.download_count >= file.max_downloads:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Download limit reached"
        )
    
    # Download and decrypt
    encrypted_data = storage_service.download_file(file.file_path)
    decrypted_data = encryption_service.decrypt_file(
        encrypted_data,
        file.encryption_key,
        file.encryption_iv
    )
    
    # Increment download count
    crud_file.increment_download_count(db, file.id)
    
    return StreamingResponse(
        iter([decrypted_data]),
        media_type=file.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{file.original_filename}"'
        }
    )


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a file"""
    file = crud_file.get_file_by_id(db, file_id, current_user.id)
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Delete from MinIO
    storage_service.delete_file(file.file_path)
    
    # Delete from database
    crud_file.delete_file(db, file_id, current_user.id)
    
    return None
```

---

## 10. Main Application (`app/main.py`)

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.endpoints import auth, files
from app.db.base import Base
from app.db.session import engine

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Secure file transfer system with AES-256 encryption and JWT+2FA authentication"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix=f"{settings.API_V1_PREFIX}/auth", tags=["Authentication"])
app.include_router(files.router, prefix=f"{settings.API_V1_PREFIX}/files", tags=["Files"])


@app.get("/")
def root():
    return {
        "message": "Secure File Transfer API",
        "version": settings.APP_VERSION,
        "docs": "/docs"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---
<!-- 
## 11. Database Migrations (Alembic)

### 11.1 Initialize Alembic
```bash
uv run alembic init alembic
```

### 11.2 Configure Alembic (`alembic.ini`)
```ini
# Update sqlalchemy.url line to:
# sqlalchemy.url = driver://user:pass@localhost/dbname
# Or remove it and use env.py configuration
```

### 11.3 Configure env.py (`alembic/env.py`)
```python
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from app.core.config import settings
from app.db.base import Base

# this is the Alembic Config object
config = context.config

# Set database URL from settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

### 11.4 Create Initial Migration
```bash
uv run alembic revision --autogenerate -m "Initial migration"
uv run alembic upgrade head
```

---

## 12. Running the Application

### 12.1 Setup Infrastructure

**PostgreSQL:**
```bash
# Using Docker
docker run --name postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=secure_file_transfer -p 5432:5432 -d postgres:15
```

**Redis:**
```bash
docker run --name redis -p 6379:6379 -d redis:7
```

**MinIO:**
```bash
docker run --name minio -p 9000:9000 -p 9001:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin -d minio/minio server /data --console-address ":9001"
```

### 12.2 Generate Encryption Key
```bash
# Generate a secure 32-byte key and base64 encode it
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
```

Add this to your `.env` as `ENCRYPTION_KEY`

### 12.3 Run Application
```bash
# Development
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## 13. API Testing

### 13.1 Register User
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

### 13.2 Login
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### 13.3 Upload File
```bash
curl -X POST "http://localhost:8000/api/v1/files/upload" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "file=@/path/to/file.pdf" \
  -F "is_public=false"
```

### 13.4 Setup 2FA
```bash
curl -X POST "http://localhost:8000/api/v1/auth/2fa/setup" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 14. Testing with Pytest

Create `tests/conftest.py`:
```python
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.db.base import Base
from app.db.session import get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)
```

Run tests:
```bash
uv run pytest tests/ -v
```

---

## 15. Deployment Checklist

- [ ] Set strong `SECRET_KEY` and `ENCRYPTION_KEY`
- [ ] Configure production database credentials
- [ ] Set `DEBUG=False`
- [ ] Configure HTTPS/TLS certificates
- [ ] Set up proper CORS origins
- [ ] Configure rate limiting
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy for database and MinIO
- [ ] Set up Redis persistence
- [ ] Configure file size limits based on requirements
- [ ] Set up regular security audits
- [ ] Implement API rate limiting
- [ ] Configure proper firewall rules
- [ ] Set up container orchestration (Docker Compose/Kubernetes)

---

## 16. Docker Deployment (Optional)

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    depends_on:
      - postgres
      - redis
      - minio
  
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: secure_file_transfer
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7
    volumes:
      - redis_data:/data
  
  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio_data:/data

volumes:
  postgres_data:
  redis_data:
  minio_data:
```

Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install uv

COPY pyproject.toml .
RUN uv pip install --system -e .

COPY app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 17. Security Best Practices

1. **Never commit `.env` file** - Use environment variables in production
2. **Rotate encryption keys periodically** - Implement key rotation strategy
3. **Use HTTPS only** - Never transmit tokens over HTTP
4. **Implement rate limiting** - Prevent brute force attacks
5. **Regular security audits** - Review code and dependencies
6. **Input validation** - Validate all user inputs
7. **SQL injection prevention** - Use SQLAlchemy ORM properly
8. **XSS prevention** - Sanitize outputs if rendering HTML
9. **CSRF protection** - Implement for state-changing operations
10. **Regular backups** - Automate database and file backups

--- -->

## 18. Support & Documentation

- **API Documentation**: http://localhost:8000/docs (Swagger UI)
- **Alternative Docs**: http://localhost:8000/redoc (ReDoc)
- **Health Check**: http://localhost:8000/health

For questions or issues, refer to:
- FastAPI docs: https://fastapi.tiangolo.com
- SQLAlchemy docs: https://docs.sqlalchemy.org
- MinIO docs: https://min.io/docs/minio/linux/index.html