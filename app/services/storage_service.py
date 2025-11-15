from minio import Minio
from minio.error import S3Error
import uuid
import os
from typing import Optional
from app.core.config import settings


# Custom exception for storage availability problems
class StorageUnavailableError(Exception):
    """Raised when the storage backend (MinIO) cannot be reached or is misconfigured"""
    pass


class StorageService:
    def __init__(self):
        self.client = None
        self.bucket_name = settings.MINIO_BUCKET_NAME
        self._initialized = False
    
    def _initialize_client(self):
        """Initialize MinIO client lazily"""
        if not self._initialized:
            try:
                self.client = Minio(
                    settings.MINIO_ENDPOINT,
                    access_key=settings.MINIO_ACCESS_KEY,
                    secret_key=settings.MINIO_SECRET_KEY,
                    secure=settings.MINIO_SECURE
                )
                self._ensure_bucket_exists()
                self._initialized = True
            except Exception as e:
                # Raise a specific error so callers can return a friendly HTTP response
                raise StorageUnavailableError(f"Failed to connect to MinIO: {e}. Please ensure MinIO is running on {settings.MINIO_ENDPOINT}")
    
    def _ensure_bucket_exists(self):
        """Create bucket if it doesn't exist"""
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
        except S3Error as e:
            # wrap MinIO errors in our storage-specific error
            raise StorageUnavailableError(f"Error creating/checking bucket '{self.bucket_name}': {e}")
    
    def upload_file(self, data: bytes, original_filename: str) -> str:
        """
        Upload file data to MinIO
        Returns: file_path (object name)
        """
        self._initialize_client()
        
        # Generate unique filename
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        
        try:
            # Upload data
            from io import BytesIO
            data_stream = BytesIO(data)
            
            self.client.put_object(
                self.bucket_name,
                unique_filename,
                data_stream,
                length=len(data),
                content_type="application/octet-stream"
            )
            
            return unique_filename
            
        except S3Error as e:
            raise StorageUnavailableError(f"Failed to upload file: {e}")
    
    def download_file(self, file_path: str) -> bytes:
        """
        Download file data from MinIO
        """
        self._initialize_client()
        
        try:
            response = self.client.get_object(self.bucket_name, file_path)
            data = response.read()
            response.close()
            response.release_conn()
            return data
            
        except S3Error as e:
            raise StorageUnavailableError(f"Failed to download file: {e}")
    
    def delete_file(self, file_path: str) -> bool:
        """
        Delete file from MinIO
        """
        self._initialize_client()
        
        try:
            self.client.remove_object(self.bucket_name, file_path)
            return True
            
        except S3Error as e:
            raise StorageUnavailableError(f"Failed to delete file: {e}")
    
    def file_exists(self, file_path: str) -> bool:
        """
        Check if file exists in MinIO
        """
        self._initialize_client()
        
        try:
            self.client.stat_object(self.bucket_name, file_path)
            return True
        except S3Error as e:
            raise StorageUnavailableError(f"Failed to stat object: {e}")
    
    def get_file_url(self, file_path: str, expires_hours: int = 24) -> Optional[str]:
        """
        Generate presigned URL for file access
        """
        self._initialize_client()
        
        try:
            from datetime import timedelta
            return self.client.presigned_get_object(
                self.bucket_name,
                file_path,
                expires=timedelta(hours=expires_hours)
            )
        except S3Error as e:
            raise StorageUnavailableError(f"Error generating presigned URL: {e}")


# Create singleton instance
storage_service = StorageService()