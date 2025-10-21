from datetime import datetime, timedelta
from app.core.password import validate_password, password_needs_rotation


def test_password_validation():
    assert validate_password("StrongPass1!")
    assert not validate_password("weakpass")


def test_password_rotation():
    old_date = datetime.utcnow() - timedelta(days=100)
    new_date = datetime.utcnow()
    assert password_needs_rotation(old_date) is True
    assert password_needs_rotation(new_date) is False
