from app.core.session import create_access_token, revoke_token, is_token_revoked


def test_token_revocation():
    token = create_access_token(user_id=1)
    assert not is_token_revoked(token)

    revoke_token(token)
    assert is_token_revoked(token)
