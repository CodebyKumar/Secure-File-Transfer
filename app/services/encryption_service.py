from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
from typing import Tuple
from app.core.config import settings


class EncryptionService:
    def __init__(self):
        if settings.ENCRYPTION_KEY:
            self.master_key = base64.b64decode(settings.ENCRYPTION_KEY.encode())
        else:
            # Generate a key for development (not recommended for production)
            self.master_key = os.urandom(32)
    
    def encrypt_file(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt file data using AES-256-CBC
        Returns: (encrypted_data, encryption_key, iv)
        """
        # Generate random key and IV for this file
        file_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)        # 128-bit IV
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(file_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to multiple of 16 bytes (AES block size)
        padded_data = self._pad_data(data)
        
        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the file key with master key
        fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        encrypted_key = fernet.encrypt(file_key)
        
        return encrypted_data, encrypted_key, iv
    
    def decrypt_file(self, encrypted_data: bytes, encrypted_key: bytes, iv: bytes) -> bytes:
        """
        Decrypt file data
        """
        # Decrypt the file key with master key
        fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        file_key = fernet.decrypt(encrypted_key)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(file_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        data = self._unpad_data(padded_data)
        
        return data
    
    def _pad_data(self, data: bytes) -> bytes:
        """Add PKCS7 padding to data"""
        block_size = 16  # AES block size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding from data"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]


# Create singleton instance
encryption_service = EncryptionService()