from datetime import datetime, timezone

from jose import jwt


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


def test_main_csrf_wrappers_use_the_current_serializer(monkeypatch):
    import main
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer("patched-secret")
    monkeypatch.setattr(main, "csrf_serializer", serializer)

    token = main.generate_csrf_token()

    assert serializer.loads(token, max_age=3600)
    assert main.verify_csrf_token(token) is True
