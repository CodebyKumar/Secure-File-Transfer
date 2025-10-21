import pytest
from app.core.otp import generate_otp_secret, verify_otp


@pytest.mark.asyncio
async def test_otp_verification():
    secret = generate_otp_secret()
    import pyotp

    token = pyotp.TOTP(secret).now()
    assert verify_otp(secret, token)
