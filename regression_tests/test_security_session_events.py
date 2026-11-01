"""Session telemetry records committed changes without bearer/refresh secrets."""

import asyncio
import json
import sqlite3
from datetime import timedelta

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from regression_tests.test_stock_safety import api
from regression_tests.test_security_reset_events import reset_unit_api, security_api
from regression_tests.test_native_bearer_auth import native_auth_api, login_request

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_session_event_writer_accepts_only_curated_lifecycle_metadata():
    from backend.services.security_events import record_security_event

    class Capture:
        def execute(self, query, params):
            self.params = params

    conn = Capture()
    for event, source in [
        ("session_issued", "native_login"),
        ("session_rotated", "native_refresh"),
    ]:
        record_security_event(
            conn,
            event=event,
            outcome="success",
            actor_user_id=1,
            details={
                "is_mobile": True,
                "source": source,
                "refresh_token": "private-refresh",
                "device_name": "private-device",
            },
        )
        assert json.loads(conn.params[-1]) == {"is_mobile": True, "source": source}
    record_security_event(
        conn,
        event="session_revoked",
        outcome="success",
        actor_user_id=1,
        details={
            "reason": "user_logout",
            "session_count": 2,
            "is_mobile": False,
            "session_token": "private-token",
        },
    )
    assert json.loads(conn.params[-1]) == {
        "reason": "user_logout",
        "session_count": 2,
        "is_mobile": False,
    }
    record_security_event(
        conn,
        event="session_revoked",
        outcome="success",
        details={"session_count": True, "reason": "private-reason"},
    )
    assert json.loads(conn.params[-1]) == {}


def test_browser_login_emits_session_issued_without_session_token(reset_unit_api):
    client, db, events = reset_unit_api
    response = client.post(
        "/api/auth/login",
        json={"email": "user1@example.com", "password": "test-password"},
    )
    assert response.status_code == 200
    issued = [e for e in events if e["event"] == "session_issued"]
    assert len(issued) == 1
    assert issued[0]["details"] == {"is_mobile": False, "source": "browser_login"}
    assert response.cookies["session_token"] not in str(events)


@pytest.mark.parametrize("operation", ["specific", "other", "all", "logout"])
def test_session_revocation_emits_after_commit(reset_unit_api, operation):
    from backend.services.session_credentials import hash_session_credential

    client, db, events = reset_unit_api
    with sqlite3.connect(db) as conn:
        sid = conn.execute(
            "INSERT INTO sessions(user_id,session_token,expires_at) VALUES(1,?,'2099-01-01T00:00:00.000000Z')",
            (hash_session_credential("private-other-token"),),
        ).lastrowid
    headers = {"Cookie": "session_token=fixture-session-1"}
    if operation == "specific":
        response = client.delete(f"/api/auth/sessions/{sid}", headers=headers)
    else:
        path = {
            "other": "/api/auth/revoke-other-sessions",
            "all": "/api/auth/sessions/revoke-all",
            "logout": "/api/auth/logout",
        }[operation]
        response = client.post(path, headers=headers)
    assert response.status_code == 200
    assert len(events) == 1
    assert events[0]["event"] == "session_revoked"
    assert events[0]["outcome"] == "success"
    assert events[0]["actor_user_id"] == 1
    assert events[0]["details"]["session_count"] == 1
    assert (
        events[0]["details"]["reason"]
        == {
            "specific": "user_revoked",
            "other": "other_sessions_revoked",
            "all": "other_sessions_revoked",
            "logout": "user_logout",
        }[operation]
    )
    assert all(
        t not in str(events) for t in ["fixture-session-1", "private-other-token"]
    )


@pytest.mark.parametrize("operation", ["other", "all"])
def test_noop_revocation_does_not_emit_success_event(reset_unit_api, operation):
    client, db, events = reset_unit_api
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO sessions(user_id,session_token,expires_at,is_active) VALUES(1,'already-inactive','2099-01-01T00:00:00.000000Z',0)"
        )
    path = (
        "/api/auth/revoke-other-sessions"
        if operation == "other"
        else "/api/auth/sessions/revoke-all"
    )
    assert (
        client.post(
            path, headers={"Cookie": "session_token=fixture-session-1"}
        ).status_code
        == 200
    )
    assert events == []


def test_revocation_commit_failure_does_not_emit_event(reset_unit_api):
    client, db, events = reset_unit_api
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """CREATE TABLE revoke_guard (user_id INTEGER REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED);
          CREATE TRIGGER reject_revoke_commit AFTER UPDATE OF is_active ON sessions BEGIN INSERT INTO revoke_guard VALUES(-1); END;"""
        )
    with pytest.raises(sqlite3.IntegrityError):
        client.post(
            "/api/auth/logout", headers={"Cookie": "session_token=fixture-session-1"}
        )
    assert events == []
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute("SELECT is_active FROM sessions WHERE user_id=1").fetchone()[0]
            == 1
        )


def native_login(api):
    from backend.schemas.auth import UserLogin

    return json.loads(
        asyncio.run(
            api.endpoint("/api/auth/native/login")(
                UserLogin(email="native@example.test", password="correct-password"),
                login_request(),
                csrf_valid=True,
            )
        ).body
    )


def test_native_issue_rotation_retry_and_replay_have_truthful_postgres_events(
    native_auth_api,
):
    from backend.schemas.auth import NativeRefreshRequest

    api = native_auth_api
    first = native_login(api)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/native/refresh",
            "headers": [],
            "client": ("127.0.0.1", 1234),
        }
    )
    payload = NativeRefreshRequest(refresh_token=first["refresh_token"])
    rotated = asyncio.run(
        api.endpoint("/api/auth/native/refresh")(payload, request, "request-one")
    )
    retry = asyncio.run(
        api.endpoint("/api/auth/native/refresh")(payload, request, "request-one")
    )
    assert retry.body == rotated.body
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            api.endpoint("/api/auth/native/refresh")(payload, request, "request-two")
        )
    assert error.value.status_code == 401
    rows = api.connection.execute(
        "SELECT event,details FROM platform_security_events WHERE event LIKE 'session_%' ORDER BY id"
    ).fetchall()
    assert rows == [
        {
            "event": "session_issued",
            "details": {"is_mobile": True, "source": "native_login"},
        },
        {
            "event": "session_rotated",
            "details": {"is_mobile": True, "source": "native_refresh"},
        },
        {
            "event": "session_revoked",
            "details": {
                "is_mobile": True,
                "reason": "refresh_reuse",
                "session_count": 1,
            },
        },
    ]
    secrets = [
        first["access_token"],
        first["refresh_token"],
        *json.loads(rotated.body).values(),
    ]
    assert all(
        str(secret) not in str(rows)
        for secret in secrets
        if isinstance(secret, str) and len(secret) > 20
    )


def test_native_replacement_emits_revoke_and_issue_only_after_commit(native_auth_api):
    api = native_auth_api
    first = native_login(api)
    native_login(api)
    rows = api.connection.execute(
        "SELECT event,details FROM platform_security_events WHERE event LIKE 'session_%' ORDER BY id"
    ).fetchall()
    assert rows == [
        {
            "event": "session_issued",
            "details": {"is_mobile": True, "source": "native_login"},
        },
        {
            "event": "session_revoked",
            "details": {
                "is_mobile": True,
                "reason": "session_replaced",
                "session_count": 1,
            },
        },
        {
            "event": "session_issued",
            "details": {"is_mobile": True, "source": "native_login"},
        },
    ]
    assert first["refresh_token"] not in str(rows)


def test_pair_completion_emits_issue_and_revocation_of_replaced_mobile(native_auth_api):
    from backend.schemas.mobile_pairing import MobilePairingComplete
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    api = native_auth_api
    native_login(api)
    api.connection.execute(
        "INSERT INTO mobile_pairing_requests(request_id,user_id,qr_token_hash,claim_token_hash,status,device_name,created_at,expires_at) VALUES('pair-request',%s,%s,%s,'approved','private-device-name',%s,%s)",
        (
            api.user_id,
            hash_session_credential("private-qr"),
            hash_session_credential("private-claim-token-long-enough"),
            serialize_instant(utc_now()),
            serialize_instant(utc_now() + timedelta(minutes=2)),
        ),
    )
    api.connection.commit()
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/mobile-pairing/complete",
            "headers": [],
            "client": ("127.0.0.1", 1234),
        }
    )
    response = asyncio.run(
        api.endpoint("/api/v1/auth/mobile-pairing/complete")(
            MobilePairingComplete(claim_token="private-claim-token-long-enough"),
            request,
        )
    )
    assert response.status_code == 200
    rows = api.connection.execute(
        "SELECT event,details FROM platform_security_events WHERE event LIKE 'session_%' ORDER BY id"
    ).fetchall()
    assert rows[-2:] == [
        {
            "event": "session_revoked",
            "details": {
                "is_mobile": True,
                "reason": "session_replaced",
                "session_count": 1,
            },
        },
        {
            "event": "session_issued",
            "details": {"is_mobile": True, "source": "mobile_pairing"},
        },
    ]
    assert all(
        secret not in str(rows)
        for secret in [
            "private-claim-token-long-enough",
            "private-device-name",
            "private-qr",
        ]
    )


@pytest.mark.parametrize(
    "operation", ["specific", "other", "all", "logout", "mobile", "rollback"]
)
def test_postgres_revocation_events_track_committed_state(security_api, operation):
    import main
    import psycopg
    from backend.services.session_credentials import hash_session_credential

    client, admin, uid = security_api
    current = admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES(%s,%s,'2099-01-01T00:00:00.000000Z') RETURNING id",
        (uid, hash_session_credential("private-current")),
    ).fetchone()["id"]
    target = admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at,is_mobile) VALUES(%s,%s,'2099-01-01T00:00:00.000000Z',TRUE) RETURNING id",
        (uid, hash_session_credential("private-mobile")),
    ).fetchone()["id"]
    if operation == "rollback":
        admin.execute(
            "CREATE FUNCTION reject_session_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit guard'; END $$"
        )
        admin.execute(
            "CREATE CONSTRAINT TRIGGER reject_session_commit AFTER UPDATE ON sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.is_active IS DISTINCT FROM NEW.is_active) EXECUTE FUNCTION reject_session_commit()"
        )
    admin.commit()
    main.app.dependency_overrides[main.verify_authenticated_csrf] = lambda: True
    headers = {"Cookie": "session_token=private-current"}
    if operation in {"specific", "mobile"}:
        path = (
            f"/api/auth/sessions/{target}"
            if operation == "specific"
            else f"/api/profile/mobile-devices/{target}"
        )
        call = lambda: client.delete(path, headers=headers)
    else:
        path = {
            "other": "/api/auth/revoke-other-sessions",
            "all": "/api/auth/sessions/revoke-all",
            "logout": "/api/auth/logout",
            "rollback": "/api/auth/logout",
        }[operation]
        call = lambda: client.post(path, headers=headers)
    if operation == "rollback":
        with pytest.raises(psycopg.errors.RaiseException):
            call()
        assert (
            admin.execute(
                "SELECT count(*) AS n FROM platform_security_events"
            ).fetchone()["n"]
            == 0
        )
        assert (
            admin.execute(
                "SELECT is_active FROM sessions WHERE id=%s", (current,)
            ).fetchone()["is_active"]
            is True
        )
    else:
        assert call().status_code == 200
        rows = admin.execute(
            "SELECT event,outcome,actor_user_id,details FROM platform_security_events"
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert (row["event"], row["outcome"], row["actor_user_id"]) == (
            "session_revoked",
            "success",
            uid,
        )
        assert (
            row["details"]["reason"]
            == {
                "specific": "user_revoked",
                "other": "other_sessions_revoked",
                "all": "other_sessions_revoked",
                "logout": "user_logout",
                "mobile": "mobile_access_revoked",
            }[operation]
        )
        assert row["details"]["session_count"] == 1
        assert all(
            token not in str(row) for token in ["private-current", "private-mobile"]
        )
        revoked_id = current if operation == "logout" else target
        assert (
            admin.execute(
                "SELECT is_active FROM sessions WHERE id=%s", (revoked_id,)
            ).fetchone()["is_active"]
            is False
        )


def test_v22_upgrade_preserves_v21_events_and_enables_new_taxonomy(
    postgres_schema, monkeypatch
):
    import psycopg
    from backend.postgres_migrations import registry
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.security_events import record_security_event

    conn, schema = postgres_schema
    migrations = registry.MIGRATIONS
    with monkeypatch.context() as patch:
        patch.setattr(registry, "MIGRATIONS", migrations[:21])
        assert apply_postgres_migrations(conn).current_version == 21
    conn.commit()
    record_security_event(conn, event="login_failed", outcome="failure")
    conn.commit()
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            record_security_event(conn, event="session_issued", outcome="success")
    assert apply_postgres_migrations(conn).current_version == 22
    conn.commit()
    record_security_event(
        conn,
        event="session_issued",
        outcome="success",
        details={"is_mobile": True, "source": "native_login"},
    )
    conn.commit()
    assert [
        row["event"]
        for row in conn.execute(
            "SELECT event FROM platform_security_events ORDER BY id"
        ).fetchall()
    ] == ["login_failed", "session_issued"]


def test_native_issue_commit_failure_never_emits_success(native_auth_api):
    import psycopg

    api = native_auth_api
    api.connection.execute(
        "CREATE FUNCTION reject_native_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit guard'; END $$"
    )
    api.connection.execute(
        "CREATE CONSTRAINT TRIGGER reject_native_commit AFTER INSERT ON sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_commit()"
    )
    api.connection.commit()
    with pytest.raises(psycopg.errors.RaiseException):
        native_login(api)
    assert (
        api.connection.execute("SELECT count(*) AS n FROM sessions").fetchone()["n"]
        == 0
    )
    assert (
        api.connection.execute(
            "SELECT count(*) AS n FROM platform_security_events"
        ).fetchone()["n"]
        == 0
    )
