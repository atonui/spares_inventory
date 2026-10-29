from datetime import datetime, timezone

from jose import jwt
import pytest
from fastapi import HTTPException


def test_security_helpers_hash_passwords_and_create_signed_tokens():
    from backend.security import create_access_token, hash_password, verify_password

    hashed = hash_password("correct horse battery staple")

    assert hashed != "correct horse battery staple"
    assert verify_password("correct horse battery staple", hashed) is True
    assert verify_password("wrong password", hashed) is False

    token = create_access_token({"sub": "42", "role": "admin"}, "jwt-secret")
    decoded = jwt.decode(token, "jwt-secret", algorithms=["HS256"])

    assert decoded["sub"] == "42"
    assert decoded["role"] == "admin"
    assert datetime.fromtimestamp(decoded["exp"], tz=timezone.utc) > datetime.now(timezone.utc)


def test_csrf_helpers_accept_generated_tokens_and_reject_invalid_tokens():
    from backend.security import create_csrf_helpers

    csrf = create_csrf_helpers("csrf-secret")
    token = csrf.generate_csrf_token()

    assert csrf.verify_csrf_token(token) is True
    assert csrf.verify_csrf_token("not-a-valid-token") is False


def test_csrf_tokens_are_bound_to_the_session_that_requested_them():
    from backend.security import create_csrf_helpers

    csrf = create_csrf_helpers("csrf-secret")
    anonymous = csrf.generate_csrf_token()
    session_one = csrf.generate_csrf_token("session-one")

    assert csrf.verify_csrf_token(anonymous)
    assert not csrf.verify_csrf_token(anonymous, session_token="session-one")
    assert csrf.verify_csrf_token(session_one, session_token="session-one")
    assert not csrf.verify_csrf_token(session_one, session_token="session-two")
    assert not csrf.verify_csrf_token(session_one)


def test_main_csrf_wrappers_use_the_current_serializer(monkeypatch):
    import main
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer("patched-secret")
    monkeypatch.setattr(main, "csrf_serializer", serializer)

    token = main.generate_csrf_token()

    assert serializer.loads(token, max_age=3600)
    assert main.verify_csrf_token(token) is True


@pytest.mark.parametrize("token,detail", [(None, "CSRF token missing"), ("", "CSRF token missing"), ("bad", "Invalid CSRF token")])
def test_csrf_request_validation_preserves_errors(token, detail):
    from backend.security import require_csrf_token

    with pytest.raises(HTTPException) as error:
        require_csrf_token(token, lambda value: False)
    assert error.value.status_code == 403
    assert error.value.detail == detail


def test_csrf_request_validation_accepts_valid_token():
    from backend.security import create_csrf_helpers, require_csrf_token

    csrf = create_csrf_helpers("request-secret")
    assert require_csrf_token(csrf.generate_csrf_token(), csrf.verify_csrf_token) is True


def test_main_csrf_dependency_uses_current_verifier(monkeypatch):
    import asyncio
    import main

    monkeypatch.setattr(
        main, "verify_csrf_token",
        lambda token, session_token=None: token == "current-token" and session_token is None,
    )
    assert asyncio.run(main.verify_csrf("current-token")) is True
    with pytest.raises(HTTPException) as error:
        asyncio.run(main.verify_csrf("other-token"))
    assert error.value.detail == "Invalid CSRF token"


@pytest.mark.parametrize("prefix", ["2a", "2b", "2y"])
def test_password_verification_accepts_existing_passlib_hashes(prefix):
    from backend.security import verify_password

    stored = "$2b$12$1ko/TYGtQom7PVOe9Okis.Sc060PQqpiIlbAx4ovC6vZMv1nnE0na"
    stored = "$" + prefix + stored[3:]
    assert verify_password("legacy password", stored)
    assert not verify_password("different password", stored)


def test_password_verification_preserves_legacy_utf8_truncation():
    from backend.security import hash_password, verify_password

    stored = "$2b$12$pRKYffSAPWTG7xyIm.n5JO6rHIZeCzXx7MwXdDBP.wmNw.AKZok7W"
    assert verify_password("é" * 40, stored)
    assert verify_password("é" * 36 + "different suffix", stored)
    assert not verify_password("è" * 40, stored)
    assert verify_password("é" * 40, hash_password("é" * 40))


def test_password_hash_format_and_rejected_inputs():
    from backend.security import hash_password, password_needs_rehash, verify_password

    assert hash_password("test password").startswith("$spares-bcrypt-sha256$v1$")
    assert password_needs_rehash("$2b$12$legacy")
    with pytest.raises(ValueError):
        hash_password("contains\x00nul")
    with pytest.raises(ValueError):
        hash_password("x" * 4097)
    with pytest.raises(ValueError):
        verify_password("password", "invalid hash")


def test_new_password_hashes_distinguish_passwords_past_bcrypt_byte_limit():
    from backend.security import hash_password, password_needs_rehash, verify_password

    password = "x" * 72 + "first suffix"
    stored = hash_password(password)

    assert not password_needs_rehash(stored)
    assert verify_password(password, stored)
    assert not verify_password("x" * 72 + "different suffix", stored)
