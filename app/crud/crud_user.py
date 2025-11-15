from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.auth_service import auth_service
from datetime import datetime
from typing import Optional


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def create_user(db: Session, user: UserCreate) -> User:
    hashed_password = auth_service.get_password_hash(user.password)
    db_user = User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=True,
        is_verified=False
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
        db.refresh(user)
    return user


def enable_2fa(db: Session, user_id: int, secret: str):
    user = get_user_by_id(db, user_id)
    if user:
        user.two_factor_enabled = True
        user.two_factor_secret = secret
        db.commit()
        db.refresh(user)
    return user


def disable_2fa(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if user:
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.commit()
        db.refresh(user)
    return user


def update_user(db: Session, user_id: int, user_update: dict) -> Optional[User]:
    user = get_user_by_id(db, user_id)
    if user:
        for field, value in user_update.items():
            if hasattr(user, field) and value is not None:
                setattr(user, field, value)
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
    return user


def delete_user(db: Session, user_id: int) -> bool:
    user = get_user_by_id(db, user_id)
    if user:
        db.delete(user)
        db.commit()
        return True
    return False