from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


# User Base Schema
class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)


# User Creation Schema
class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100)


# User Login Schema
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6)


# User Response Schema
class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    two_factor_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


# User Update Schema
class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)


# Password Change Schema
class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


# 2FA Setup Response
class TwoFactorSetup(BaseModel):
    secret: str
    qr_code: str


# 2FA Verify Schema
class TwoFactorVerify(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6)