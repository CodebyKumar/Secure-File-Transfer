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
from app.services.storage_service import storage_service, StorageUnavailableError
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
    try:
        file_path = storage_service.upload_file(encrypted_data, file.filename)
    except StorageUnavailableError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    
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
    try:
        encrypted_data = storage_service.download_file(file.file_path)
    except StorageUnavailableError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    
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
    try:
        encrypted_data = storage_service.download_file(file.file_path)
    except StorageUnavailableError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
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
    try:
        storage_service.delete_file(file.file_path)
    except StorageUnavailableError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    
    # Delete from database
    crud_file.delete_file(db, file_id, current_user.id)
    
    return None


@router.get("/stats/overview")
def get_file_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get file statistics for current user"""
    stats = crud_file.get_file_stats(db, current_user.id)
    return stats