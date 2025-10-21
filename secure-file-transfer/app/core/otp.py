# app/core/otp.py
import pyotp


def generate_otp_secret() -> str:
    return pyotp.random_base32()


def get_totp(secret: str):
    return pyotp.TOTP(secret)


def verify_otp(secret: str, token: str) -> bool:
    totp = get_totp(secret)
    return totp.verify(token)
