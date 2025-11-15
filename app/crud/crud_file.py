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
    encryption_key: bytes,
    encryption_iv: bytes,
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
        max_downloads=max_downloads,
        download_count=0
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
    expires_hours: Optional[int] = 24,
    max_downloads: Optional[int] = None
) -> Optional[File]:
    file = get_file_by_id(db, file_id, owner_id)
    if file:
        file.share_token = secrets.token_urlsafe(32)
        if expires_hours:
            file.share_expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
        if max_downloads:
            file.max_downloads = max_downloads
        db.commit()
        db.refresh(file)
    return file


def increment_download_count(db: Session, file_id: int):
    file = db.query(File).filter(File.id == file_id).first()
    if file:
        file.download_count += 1
        db.commit()
        db.refresh(file)
    return file


def delete_file(db: Session, file_id: int, owner_id: int) -> bool:
    file = get_file_by_id(db, file_id, owner_id)
    if file:
        db.delete(file)
        db.commit()
        return True
    return False


def get_public_files(db: Session, skip: int = 0, limit: int = 100) -> List[File]:
    return db.query(File).filter(
        File.is_public == True
    ).offset(skip).limit(limit).all()


def update_file(db: Session, file_id: int, owner_id: int, update_data: dict) -> Optional[File]:
    file = get_file_by_id(db, file_id, owner_id)
    if file:
        for field, value in update_data.items():
            if hasattr(file, field) and value is not None:
                setattr(file, field, value)
        file.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(file)
    return file


def get_file_stats(db: Session, owner_id: int) -> dict:
    """Get file statistics for a user"""
    total_files = db.query(File).filter(File.owner_id == owner_id).count()
    total_downloads = db.query(File).filter(File.owner_id == owner_id).with_entities(
        db.func.sum(File.download_count)
    ).scalar() or 0
    total_size = db.query(File).filter(File.owner_id == owner_id).with_entities(
        db.func.sum(File.file_size)
    ).scalar() or 0
    
    return {
        "total_files": total_files,
        "total_downloads": total_downloads,
        "total_size": total_size
    }