import os
from typing import Any

try:
    from minio import Minio  # type: ignore
except Exception:  # pragma: no cover - optional dependency during tests
    Minio = None  # type: ignore


MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "secure-files")


def get_client() -> Any:
    """Return a MinIO client without performing any network IO at import time.

    Tests can monkeypatch attributes on the returned client; in production, callers
    may optionally ensure the bucket exists.
    """
    if Minio is None:
        raise RuntimeError("minio package not installed")
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,  # True if using TLS
    )


def ensure_bucket(client: Any, bucket: str) -> None:
    """Ensure a bucket exists; no-op if it already exists. Safe for production init."""
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
    except Exception:
        # Avoid failing at import/startup; callers can handle/log if desired
        pass
