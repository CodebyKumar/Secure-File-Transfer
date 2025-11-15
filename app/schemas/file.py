from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# File Base Schema
class FileBase(BaseModel):
    filename: str
    is_public: bool = False


# File Response Schema
class FileResponse(FileBase):
    id: int
    original_filename: str
    file_size: int
    mime_type: str
    owner_id: int
    download_count: int
    created_at: datetime
    updated_at: Optional[datetime]
    share_token: Optional[str]
    share_expires_at: Optional[datetime]
    max_downloads: Optional[int]

    class Config:
        from_attributes = True


# File Share Schema
class FileShare(BaseModel):
    expires_hours: Optional[int] = Field(24, ge=1, le=168)  # 1 hour to 1 week
    max_downloads: Optional[int] = Field(None, ge=1, le=1000)


# File Share Response Schema
class FileShareResponse(BaseModel):
    share_url: str
    share_token: str
    expires_at: Optional[datetime]


# File Upload Response Schema
class FileUploadResponse(BaseModel):
    id: int
    filename: str
    file_size: int
    message: str = "File uploaded successfully"