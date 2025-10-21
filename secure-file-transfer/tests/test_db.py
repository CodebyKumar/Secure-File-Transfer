# tests/test_db.py
import pytest
from sqlalchemy import text
from app.core.db import engine


@pytest.mark.asyncio
async def test_db_connection():
    async with engine.begin() as conn:
        result = await conn.execute(text("SELECT 1"))
        value = result.scalar()
        assert value == 1
