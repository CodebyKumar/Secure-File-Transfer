# app/api/v1/auth.py

from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.user import User
from app.schemas.user import UserCreate, UserResponse
from app.core.db import get_db
from app.core.security import hash_password, verify_password, create_access_token
from app.core.otp import verify_otp
from app.core.password import validate_password
from app.core.session import ALGORITHM, is_token_revoked
from jose import jwt, JWTError
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


# -------------------- SIGNUP --------------------
@router.post(
    "/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def signup(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user."""
    result = await db.execute(select(User).filter(User.email == user.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


# -------------------- LOGIN --------------------
@router.post("/login")
async def login(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and issue a JWT access token."""
    result = await db.execute(select(User).filter(User.email == user.email))
    db_user = result.scalars().first()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}


# -------------------- VERIFY 2FA --------------------
@router.post("/verify-2fa")
async def verify_two_factor(
    user_id: int, token: str, db: AsyncSession = Depends(get_db)
):
    """Verify a user's 2FA token."""
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()

    if not user or not user.otp_secret:
        raise HTTPException(status_code=400, detail="2FA not setup for this user")

    if verify_otp(user.otp_secret, token):
        return {"success": True, "message": "2FA verified!"}
    else:
        raise HTTPException(status_code=401, detail="Invalid 2FA token")


# -------------------- CHANGE PASSWORD --------------------
@router.post("/change-password")
async def change_password(
    user_id: int, new_password: str, db: AsyncSession = Depends(get_db)
):
    """Change a user's password with validation and hashing."""
    if not validate_password(new_password):
        raise HTTPException(
            status_code=400, detail="Password does not meet security policy"
        )

    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # hash the password before saving
    user.hashed_password = hash_password(new_password)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"success": True, "message": "Password changed successfully"}


# -------------------- GET CURRENT USER --------------------
async def get_current_user(authorization: str = Header(...)):
    """Decode JWT token and return current user id."""
    token = authorization.split(" ")[1]
    if is_token_revoked(token):
        raise HTTPException(status_code=401, detail="Token revoked")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        # Tokens created by session store user id in sub as string
        return int(sub) if sub is not None else None
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
