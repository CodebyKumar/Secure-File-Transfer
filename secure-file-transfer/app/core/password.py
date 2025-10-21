# app/core/password.py
import re
from datetime import datetime, timedelta

PASSWORD_POLICY_REGEX = (
    r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)
ROTATION_DAYS = 90


def validate_password(password: str) -> bool:
    return bool(re.fullmatch(PASSWORD_POLICY_REGEX, password))


def password_needs_rotation(last_changed: datetime) -> bool:
    return datetime.utcnow() > last_changed + timedelta(days=ROTATION_DAYS)
