import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock
from app.main import app  # Your FastAPI instance
from app.models import File


@pytest.mark.asyncio
async def test_file_upload_download(monkeypatch):
    test_filename = "test.txt"
    test_content = b"Hello Secure File Transfer!"
    owner_id = 1
    file_id = 123
    object_name = "mocked_uuid.enc"

    # Mock File DB object
    mock_file = File(
        id=file_id,
        filename=test_filename,
        encrypted_path=object_name,
        owner_id=owner_id,
        is_public=False,
    )

    # Mock MinIO put_object
    mock_put_object = MagicMock(return_value=None)
    monkeypatch.setattr("app.api.v1.files.client.put_object", mock_put_object)

    # Mock DB session add, commit, refresh
    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=mock_file)
    mock_db.add = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    # Mock MinIO get_object
    mock_minio_response = MagicMock()
    # Encrypt manually for test
    from app.core.security import encrypt_bytes

    key = b"YOUR_32_BYTE_AES_KEY_HERE_12345678"
    encrypted_content = encrypt_bytes(test_content, key)
    mock_minio_response.read.return_value = encrypted_content
    monkeypatch.setattr(
        "app.api.v1.files.client.get_object", lambda bucket, name: mock_minio_response
    )

    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Test Upload
        files = {"file": (test_filename, test_content, "text/plain")}
        response = await ac.post(f"/upload/?owner_id={owner_id}", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == test_filename

        # Test Download
        response = await ac.get(f"/download/?file_id={file_id}&user_id={owner_id}")
        assert response.status_code == 200
        content = await response.aread()
        assert content == test_content
