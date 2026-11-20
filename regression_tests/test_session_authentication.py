from contextlib import closing
import asyncio

import pytest
from fastapi import HTTPException


def test_postgres_principal_lookup_hashes_presented_credential():
    from hashlib import sha256
    from uuid import uuid4

    from backend.services.principals import resolve_principal

    organization_id = uuid4()

    class Result:
        def fetchone(self):
            return {
                "user_id": 23,
                "expires_at": "2099-01-01T00:00:00Z",
                "absolute_expires_at": "2099-01-01T00:00:00Z",
                "archived_at": None,
                "organization_id": organization_id,
                "company_role": "engineer",
                "membership_active": True,
                "organization_active": True,
                "is_platform_admin": False,
            }

    class Connection:
        query = ""
        params = ()

        def execute(self, query, params):
            self.query = query
            self.params = params
            return Result()

    connection = Connection()
    principal = resolve_principal(connection, "native-session-secret")

    assert "session_token_hash" in connection.query
    assert "session_token =" not in connection.query
    assert connection.params == (sha256(b"native-session-secret").hexdigest(),)
    assert principal.user_id == 23


def test_main_dependency_accepts_bearer_using_existing_session_authenticator(monkeypatch):
    import main
    from starlette.requests import Request

    seen = []
    monkeypatch.setattr(
        main,
        "authenticate_session",
        lambda credential, *args, **kwargs: seen.append(credential) or 23,
    )

    request = Request({"type": "http", "headers": [(b"authorization", b"Bearer native-session-secret")]})
    assert asyncio.run(main.get_current_user(None, request)) == 23
    assert seen == ["native-session-secret"]


@pytest.mark.parametrize(
    "cookie,authorization",
    [
        (None, "Basic abc"),
        (None, "Bearer"),
        ("cookie-secret", "Bearer bearer-secret"),
    ],
)
def test_main_dependency_rejects_invalid_or_mixed_authentication(cookie, authorization):
    import main
    from starlette.requests import Request

    headers = [] if authorization is None else [(b"authorization", authorization.encode())]
    if cookie:
        headers.append((b"cookie", f"session_token={cookie}".encode()))
    request = Request({"type": "http", "headers": headers})

    with pytest.raises(HTTPException) as error:
        asyncio.run(main.get_current_user(cookie, request))

    assert error.value.status_code == 401
