"""PostgreSQL native bearer login must use hashed server-side sessions."""

from datetime import datetime, timedelta, timezone
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

pytest_plugins = ("regression_tests.postgres_fixtures",)


class NoLimiter:
    def limit(self, _rule):
        return lambda function: function


def test_openapi_documents_cookie_and_opaque_bearer_auth_without_protecting_login():
    import main

    document = main.app.openapi()
    schemes = document["components"]["securitySchemes"]

    assert schemes["BearerAuth"]["type"] == "http"
    assert schemes["BearerAuth"]["scheme"] == "bearer"
    assert "not a JWT" in schemes["BearerAuth"]["description"]
    assert schemes["SessionCookie"]["type"] == "apiKey"
    assert schemes["SessionCookie"]["in"] == "cookie"
    assert schemes["SessionCookie"]["name"] == "session_token"

    native_login = document["paths"]["/api/auth/native/login"]["post"]
    native_schema = native_login["responses"]["200"]["content"]["application/json"]["schema"]
    assert native_schema["$ref"].endswith("NativeLoginResponse")
    native_fields = document["components"]["schemas"]["NativeLoginResponse"]["properties"]
    assert {"token_type", "access_token", "refresh_token", "expires_at", "user"} <= native_fields.keys()
    assert "BearerAuth" not in repr(native_login.get("security", []))

    assert document["paths"]["/api/auth/login"]["post"].get("security") in (None, [])
    profile_security = document["paths"]["/api/profile"]["get"]["security"]
    assert {"BearerAuth", "SessionCookie"} <= set().union(*(entry.keys() for entry in profile_security))


@pytest.fixture
def native_auth_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.auth import create_auth_router
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.temporal import serialize_instant, utc_now

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)
    organization_id = connection.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Native Tenant',%s) RETURNING id",
        ("native-" + uuid4().hex,),
    ).fetchone()["id"]
    user_id = connection.execute(
        """INSERT INTO users(email,name,password_hash,territory)
           VALUES ('native@example.test','Native User','stored-hash','East') RETURNING id"""
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,'engineer')",
        (organization_id, user_id),
    )
    connection.commit()

    def get_connection():
        import os
        import psycopg

        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute("SET search_path TO %s" % ('"' + schema + '"',))
        conn.commit()
        return conn

    router = create_auth_router(
        get_connection=get_connection,
        authenticated_writer=lambda user_id, session_token: authenticated_write_transaction(
            get_connection, user_id=user_id, session_token=session_token,
        ),
        stock_writer=lambda: pytest.fail("PostgreSQL login must not use the SQLite writer"),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
        authenticated_csrf_dependency=lambda: None,
        csrf_token_factory=lambda: "csrf",
        password_hash=lambda value: "hashed:" + value,
        password_verify=lambda plain, hashed: plain == "correct-password" and hashed == "stored-hash",
        security_config=lambda: {
            "max_login_attempts": 5,
            "lockout_duration_minutes": 15,
            "session_duration_hours": 24,
            "remember_me_duration_days": 30,
        },
        reset_email=lambda *args: None,
        activity_log=lambda **kwargs: None,
        endpoint_log=lambda **kwargs: (lambda function: function),
        mutation_activity=lambda *args: None,
        limiter=NoLimiter(),
        logger=SimpleNamespace(info=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None),
        cookie_secure=lambda: True,
        native_refresh_encryption_key="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    )

    def endpoint(path):
        return next(route.endpoint for route in router.routes if route.path == path)

    yield SimpleNamespace(
        connection=connection,
        get_connection=get_connection,
        endpoint=endpoint,
        user_id=user_id,
        organization_id=organization_id,
    )
    connection.rollback()


def login_request():
    return SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "integration-test"},
    )


def test_native_login_uses_shared_account_lockout(native_auth_api):
    from backend.schemas.auth import UserLogin
    from fastapi import HTTPException

    api = native_auth_api
    api.connection.execute(
        "UPDATE users SET failed_login_attempts = 4 WHERE id = %s", (api.user_id,)
    )
    api.connection.commit()

    with pytest.raises(HTTPException) as error:
        asyncio.run(api.endpoint("/api/auth/native/login")(
            UserLogin(email="native@example.test", password="wrong"),
            login_request(),
            csrf_valid=True,
        ))
    assert error.value.status_code == 423
    user = api.connection.execute(
        "SELECT failed_login_attempts, account_locked_until FROM users WHERE id = %s",
        (api.user_id,),
    ).fetchone()
    assert user["failed_login_attempts"] == 5
    assert user["account_locked_until"] is not None

    with pytest.raises(HTTPException) as locked:
        asyncio.run(api.endpoint("/api/auth/native/login")(
            UserLogin(email="native@example.test", password="correct-password"),
            login_request(),
            csrf_valid=True,
        ))
    assert locked.value.status_code == 423


def test_native_login_issues_one_bearer_and_stores_only_its_hash(native_auth_api):
    from backend.schemas.auth import UserLogin
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.session_credentials import hash_session_credential

    api = native_auth_api
    response = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password", remember_me=True),
        login_request(),
        csrf_valid=True,
    ))
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert payload["token_type"] == "Bearer"
    assert payload["access_token"]
    assert payload["refresh_token"]
    assert payload["expires_at"].endswith("Z")
    assert payload["user"] == {
        "id": api.user_id,
        "email": "native@example.test",
        "name": "Native User",
        "role": "engineer",
        "territory": "East",
    }
    stored = api.connection.execute(
        "SELECT id, session_token_hash, expires_at, absolute_expires_at FROM sessions WHERE user_id = %s",
        (api.user_id,),
    ).fetchone()
    assert stored["session_token_hash"] == hash_session_credential(payload["access_token"])
    assert payload["access_token"] not in stored["session_token_hash"]
    assert stored["expires_at"] == payload["expires_at"]
    assert stored["absolute_expires_at"]
    remaining = datetime.fromisoformat(stored["expires_at"].replace("Z", "+00:00")) - datetime.now(timezone.utc)
    assert timedelta(minutes=14) < remaining <= timedelta(minutes=15)
    absolute_remaining = datetime.fromisoformat(stored["absolute_expires_at"].replace("Z", "+00:00")) - datetime.now(timezone.utc)
    assert timedelta(days=29) < absolute_remaining <= timedelta(days=30)

    refresh = api.connection.execute(
        "SELECT token_hash, expires_at FROM session_refresh_credentials WHERE session_id = %s",
        (stored["id"],),
    ).fetchone()
    assert refresh["token_hash"] == hash_session_credential(payload["refresh_token"])
    assert payload["refresh_token"] not in refresh["token_hash"]
    assert refresh["expires_at"] == stored["absolute_expires_at"]

    from backend.services.session_authentication import authenticate_session
    principal = authenticate_session(payload["access_token"], api.get_connection)
    assert principal == AuthenticatedPrincipal(
        api.user_id, api.organization_id, "engineer", False
    )


def test_web_login_keeps_cookie_contract_and_does_not_return_bearer(native_auth_api):
    from backend.schemas.auth import UserLogin

    api = native_auth_api
    response = asyncio.run(api.endpoint("/api/auth/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(),
        csrf_valid=True,
    ))
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert "session_token=" in response.headers["set-cookie"]
    assert "access_token" not in payload
    assert "token_type" not in payload
    assert set(payload) == {"success", "user"}


def test_native_refresh_rotates_credentials_and_same_request_retry_returns_same_result(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin
    from backend.services.session_credentials import hash_session_credential

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    original_session_hash = hash_session_credential(original["access_token"])
    request = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", b"refresh-attempt-0001")],
        "client": ("127.0.0.1", 1234),
    })

    first = asyncio.run(api.endpoint("/api/auth/native/refresh")(
        NativeRefreshRequest(refresh_token=original["refresh_token"]), request,
        "refresh-attempt-0001",
    ))
    rotated = json.loads(first.body)
    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    assert rotated["access_token"] != original["access_token"]
    assert rotated["refresh_token"] != original["refresh_token"]

    retry = asyncio.run(api.endpoint("/api/auth/native/refresh")(
        NativeRefreshRequest(refresh_token=original["refresh_token"]), request,
        "refresh-attempt-0001",
    ))
    assert retry.body == first.body

    session = api.connection.execute(
        "SELECT session_token_hash FROM sessions WHERE user_id = %s", (api.user_id,),
    ).fetchone()
    assert session["session_token_hash"] == hash_session_credential(rotated["access_token"])
    credentials = api.connection.execute(
        "SELECT token_hash, consumed_at FROM session_refresh_credentials ORDER BY id",
    ).fetchall()
    assert len(credentials) == 2
    assert credentials[0]["consumed_at"] is not None
    assert credentials[1]["token_hash"] == hash_session_credential(rotated["refresh_token"])


def test_concurrent_native_refresh_same_request_id_rotates_only_once(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    request_id = "concurrent-same-request-0001"
    barrier = Barrier(2)

    def refresh():
        request = Request({
            "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
            "headers": [(b"x-request-id", request_id.encode())],
            "client": ("127.0.0.1", 1234),
        })
        barrier.wait()
        return asyncio.run(api.endpoint("/api/auth/native/refresh")(
            NativeRefreshRequest(refresh_token=original["refresh_token"]), request, request_id,
        ))

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(refresh)
        second = pool.submit(refresh)
        responses = [first.result(), second.result()]

    assert [response.status_code for response in responses] == [200, 200]
    assert responses[0].body == responses[1].body
    credentials = api.connection.execute(
        "SELECT consumed_at FROM session_refresh_credentials ORDER BY id",
    ).fetchall()
    assert len(credentials) == 2
    assert credentials[0]["consumed_at"] is not None
    assert credentials[1]["consumed_at"] is None
    assert api.connection.execute(
        "SELECT is_active FROM sessions WHERE user_id = %s", (api.user_id,),
    ).fetchone()["is_active"] is True


def test_concurrent_native_refresh_different_request_ids_revokes_session(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    barrier = Barrier(2)

    def refresh(request_id):
        request = Request({
            "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
            "headers": [(b"x-request-id", request_id.encode())],
            "client": ("127.0.0.1", 1234),
        })
        barrier.wait()
        try:
            response = asyncio.run(api.endpoint("/api/auth/native/refresh")(
                NativeRefreshRequest(refresh_token=original["refresh_token"]), request, request_id,
            ))
            return response.status_code
        except HTTPException as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(refresh, "concurrent-attempt-0001")
        second = pool.submit(refresh, "concurrent-attempt-0002")
        statuses = sorted((first.result(), second.result()))

    assert statuses == [200, 401]
    assert api.connection.execute(
        "SELECT is_active FROM sessions WHERE user_id = %s", (api.user_id,),
    ).fetchone()["is_active"] is False


def test_native_refresh_replay_with_different_request_id_revokes_device_session(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    session_id = api.connection.execute(
        "SELECT id FROM sessions WHERE user_id = %s", (api.user_id,),
    ).fetchone()["id"]
    request = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", b"refresh-attempt-0001")],
        "client": ("127.0.0.1", 1234),
    })
    asyncio.run(api.endpoint("/api/auth/native/refresh")(
        NativeRefreshRequest(refresh_token=original["refresh_token"]), request,
        "refresh-attempt-0001",
    ))
    replay = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", b"different-attempt-0002")],
        "client": ("127.0.0.1", 1234),
    })

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.endpoint("/api/auth/native/refresh")(
            NativeRefreshRequest(refresh_token=original["refresh_token"]), replay,
            "different-attempt-0002",
        ))
    assert error.value.status_code == 401
    session = api.connection.execute(
        "SELECT is_active FROM sessions WHERE id = %s", (session_id,),
    ).fetchone()
    assert session["is_active"] is False


def test_native_refresh_rejects_expired_refresh_credential(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin
    from backend.temporal import serialize_instant, utc_now
    from fastapi import HTTPException

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    session_id = api.connection.execute(
        "SELECT id FROM sessions WHERE user_id = %s", (api.user_id,),
    ).fetchone()["id"]
    api.connection.execute(
        "UPDATE session_refresh_credentials SET expires_at = %s WHERE session_id = %s",
        (serialize_instant(utc_now() - timedelta(seconds=1)), session_id),
    )
    api.connection.commit()
    request_id = "expired-refresh-0001"
    request = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", request_id.encode())],
        "client": ("127.0.0.1", 1234),
    })

    with pytest.raises(HTTPException) as error:
        asyncio.run(api.endpoint("/api/auth/native/refresh")(
            NativeRefreshRequest(refresh_token=original["refresh_token"]), request, request_id,
        ))

    assert error.value.status_code == 401
    session = api.connection.execute(
        "SELECT is_active FROM sessions WHERE id = %s", (session_id,),
    ).fetchone()
    assert session["is_active"] is False


def test_native_refresh_revokes_session_when_membership_is_inactive(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin
    from fastapi import HTTPException

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    session_id = api.connection.execute(
        "SELECT id FROM sessions WHERE user_id = %s", (api.user_id,),
    ).fetchone()["id"]
    api.connection.execute(
        "UPDATE organization_memberships SET is_active = FALSE WHERE user_id = %s",
        (api.user_id,),
    )
    api.connection.commit()
    request_id = "inactive-membership-0001"
    request = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", request_id.encode())],
        "client": ("127.0.0.1", 1234),
    })

    with pytest.raises(HTTPException) as error:
        asyncio.run(api.endpoint("/api/auth/native/refresh")(
            NativeRefreshRequest(refresh_token=original["refresh_token"]), request, request_id,
        ))

    assert error.value.status_code == 401
    assert api.connection.execute(
        "SELECT is_active FROM sessions WHERE id = %s", (session_id,),
    ).fetchone()["is_active"] is False


def test_native_refresh_is_allowed_after_access_credential_expires(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin
    from backend.temporal import serialize_instant, utc_now

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    api.connection.execute(
        "UPDATE sessions SET expires_at = %s WHERE user_id = %s",
        (serialize_instant(utc_now() - timedelta(seconds=1)), api.user_id),
    )
    api.connection.commit()
    request_id = "after-access-expiry-0001"
    request = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", request_id.encode())],
        "client": ("127.0.0.1", 1234),
    })

    response = asyncio.run(api.endpoint("/api/auth/native/refresh")(
        NativeRefreshRequest(refresh_token=original["refresh_token"]), request, request_id,
    ))

    assert response.status_code == 200
    assert json.loads(response.body)["access_token"] != original["access_token"]


def test_native_logout_revokes_refresh_credential_without_setting_cookie(native_auth_api):
    from backend.schemas.auth import NativeRefreshRequest, UserLogin
    from fastapi import HTTPException

    api = native_auth_api
    login = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(), csrf_valid=True,
    ))
    original = json.loads(login.body)
    logout_request = Request({
        "type": "http", "method": "POST", "path": "/api/v1/auth/logout",
        "headers": [(b"authorization", f"Bearer {original['access_token']}".encode())],
        "client": ("127.0.0.1", 1234),
    })

    response = asyncio.run(api.endpoint("/api/v1/auth/logout")(
        user_id=api.user_id, request=logout_request, csrf_valid=True,
    ))

    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    request_id = "after-native-logout-0001"
    refresh_request = Request({
        "type": "http", "method": "POST", "path": "/api/auth/native/refresh",
        "headers": [(b"x-request-id", request_id.encode())],
        "client": ("127.0.0.1", 1234),
    })
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.endpoint("/api/auth/native/refresh")(
            NativeRefreshRequest(refresh_token=original["refresh_token"]), refresh_request, request_id,
        ))

    assert error.value.status_code == 401


def test_valid_bearer_request_is_authenticated_before_csrf_exemption(native_auth_api, monkeypatch):
    import main
    from fastapi import HTTPException
    from backend.schemas.auth import UserLogin

    api = native_auth_api
    response = asyncio.run(api.endpoint("/api/auth/native/login")(
        UserLogin(email="native@example.test", password="correct-password"),
        login_request(),
        csrf_valid=True,
    ))
    token = json.loads(response.body)["access_token"]
    monkeypatch.setattr(main, "get_db_connection", api.get_connection)

    valid_request = Request({
        "type": "http", "method": "POST", "path": "/api/profile",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "client": ("127.0.0.1", 1234),
    })
    principal = asyncio.run(main.get_current_user(request=valid_request))
    assert principal.user_id == api.user_id
    assert asyncio.run(main.verify_authenticated_csrf(valid_request, principal, None)) is True

    invalid_request = Request({
        "type": "http", "method": "POST", "path": "/api/profile",
        "headers": [(b"authorization", b"Bearer invalid")],
        "client": ("127.0.0.1", 1234),
    })
    with pytest.raises(HTTPException) as error:
        asyncio.run(main.get_current_user(request=invalid_request))
    assert error.value.status_code == 401
