"""Real PostgreSQL reset routes must persist curated events without tenant context."""

import os
from datetime import timedelta
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.rows import dict_row

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def security_api(postgres_schema, monkeypatch):
    import main
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.temporal import serialize_instant, utc_now

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    uid = admin.execute(
        "INSERT INTO users(email,name,password_hash,reset_token,reset_token_expires) VALUES ('private@example.com','Private',%s,'private-token',%s) RETURNING id",
        (
            main.hash_password("test-password"),
            serialize_instant(utc_now() + timedelta(hours=1)),
        ),
    ).fetchone()["id"]
    admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (uid,))
    admin.commit()

    def connect():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.commit()
        return conn

    monkeypatch.setattr(main, "get_db_connection", connect)
    from cryptography.fernet import Fernet

    monkeypatch.setattr(
        main.settings, "MAIL_PAYLOAD_ENCRYPTION_KEY", Fernet.generate_key().decode()
    )
    monkeypatch.setattr(main, "FRONTEND_URL", "https://example.test")
    main.app.dependency_overrides[main.verify_csrf] = lambda: True
    main.limiter.reset()
    client = TestClient(main.app)
    try:
        yield client, admin, uid
    finally:
        client.close()
        main.app.dependency_overrides.clear()
        main.limiter.reset()


@pytest.mark.parametrize("known", [True, False])
def test_reset_request_persists_global_event_without_email(security_api, known):
    client, admin, uid = security_api
    email = "private@example.com" if known else "unknown@example.com"
    response = client.post("/api/forgot-password", json={"email": email})
    assert response.status_code == 200
    assert response.json() == {
        "message": "If the email exists, a reset link has been sent"
    }
    row = admin.execute("SELECT * FROM platform_security_events").fetchone()
    assert row is not None
    assert (row["event"], row["outcome"], row["actor_user_id"], row["details"]) == (
        "password_reset_requested",
        "success",
        uid if known else None,
        {"account_match": known},
    )
    assert email not in str(row)


@pytest.mark.parametrize(
    "reason,token,password",
    [
        ("invalid_token", "absent-token", "new-password"),
        ("token_expired", "private-token", "new-password"),
        ("weak_password", "private-token", "short"),
    ],
)
def test_reset_failures_persist_curated_reason_without_email(
    security_api, reason, token, password, caplog
):
    from backend.temporal import serialize_instant, utc_now

    client, admin, uid = security_api
    if reason == "token_expired":
        admin.execute(
            "UPDATE users SET reset_token_expires=%s WHERE id=%s",
            (serialize_instant(utc_now() - timedelta(hours=1)), uid),
        )
        admin.commit()
    response = client.post(
        "/api/reset-password", json={"token": token, "new_password": password}
    )
    assert response.status_code == 400
    row = admin.execute("SELECT * FROM platform_security_events").fetchone()
    assert row is not None
    assert (row["event"], row["outcome"], row["actor_user_id"], row["details"]) == (
        "password_reset_failed",
        "failure",
        None if reason == "invalid_token" else uid,
        {"reason": reason},
    )
    assert all(
        secret not in str(row) for secret in ["private@example.com", token, password]
    )
    assert "private@example.com" not in caplog.text
    assert (
        admin.execute(
            "SELECT count(*) AS n FROM activity_logs WHERE action LIKE 'password_reset%'"
        ).fetchone()["n"]
        == 0
    )


def test_reset_completion_records_event_after_password_and_session_commit(
    security_api, caplog
):
    client, admin, uid = security_api
    response = client.post(
        "/api/reset-password",
        json={"token": "private-token", "new_password": "new-password"},
    )
    assert response.status_code == 200
    row = admin.execute("SELECT * FROM platform_security_events").fetchone()
    assert row is not None
    assert (row["event"], row["outcome"], row["actor_user_id"], row["details"]) == (
        "password_reset_completed",
        "success",
        uid,
        {},
    )
    assert (
        admin.execute("SELECT reset_token FROM users WHERE id=%s", (uid,)).fetchone()[
            "reset_token"
        ]
        is None
    )
    assert "private@example.com" not in caplog.text
    assert (
        admin.execute(
            "SELECT count(*) AS n FROM activity_logs WHERE action LIKE 'password_reset%'"
        ).fetchone()["n"]
        == 0
    )


@pytest.fixture
def reset_unit_api(api):
    """SQLite route coverage with only the external telemetry sink replaced."""
    import main
    from fastapi import FastAPI
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from backend.routes.auth import create_auth_router

    events = []
    app = FastAPI()
    noop = lambda *args, **kwargs: None
    router = create_auth_router(
        get_connection=main.get_db_connection,
        authenticated_writer=main.authenticated_write_transaction,
        stock_writer=main.stock_write_transaction,
        current_user=lambda: 1,
        csrf_dependency=lambda: True,
        authenticated_csrf_dependency=lambda: True,
        csrf_token_factory=noop,
        password_hash=main.hash_password,
        password_verify=main.verify_password,
        security_config=main.get_security_config,
        reset_email=noop,
        queue_reset_email=noop,
        activity_log=main.log_activity,
        endpoint_log=main.log_endpoint,
        mutation_activity=noop,
        limiter=Limiter(key_func=get_remote_address, enabled=False),
        logger=main.logger,
        cookie_secure=lambda: False,
        security_event=lambda **event: events.append(event),
    )
    app.include_router(router)
    with TestClient(app) as client:
        yield client, api[1], events


from regression_tests.test_stock_safety import api


@pytest.mark.parametrize(
    "reason",
    [
        "invalid_token",
        "token_expired",
        "weak_password",
        "success",
        "request",
        "unmatched_request",
    ],
)
def test_reset_routes_emit_security_event_instead_of_tenant_activity(
    reset_unit_api, reason, caplog
):
    import sqlite3
    from regression_tests.test_auth_router import set_reset_token

    client, db, events = reset_unit_api
    set_reset_token(db, token="private-token", expired=reason == "token_expired")
    if reason in {"request", "unmatched_request"}:
        response = client.post(
            "/api/forgot-password",
            json={
                "email": (
                    "user1@example.com" if reason == "request" else "absent@example.com"
                )
            },
        )
        expected = (
            "password_reset_requested",
            "success",
            1 if reason == "request" else None,
            {"account_match": reason == "request"},
        )
    else:
        response = client.post(
            "/api/reset-password",
            json={
                "token": (
                    "absent-token" if reason == "invalid_token" else "private-token"
                ),
                "new_password": (
                    "short" if reason == "weak_password" else "new-password"
                ),
            },
        )
        expected = (
            ("password_reset_completed", "success", 1, {})
            if reason == "success"
            else (
                "password_reset_failed",
                "failure",
                None if reason == "invalid_token" else 1,
                {"reason": reason},
            )
        )
    assert response.status_code == (
        200 if reason in {"success", "request", "unmatched_request"} else 400
    )
    assert len(events) == 1
    event = events[0]
    assert (
        event["event"],
        event["outcome"],
        event["actor_user_id"],
        event.get("details", {}),
    ) == expected
    assert "user1@example.com" not in caplog.text
    assert all(
        secret not in str(event)
        for secret in [
            "private-token",
            "absent-token",
            "new-password",
            "user1@example.com",
        ]
    )
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM activity_logs WHERE action LIKE 'password_reset%'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "case,expected_status,event,outcome",
    [
        ("success", 200, "login_succeeded", "success"),
        ("known_failure", 401, "login_failed", "failure"),
        ("unmatched_failure", 401, "login_failed", "failure"),
        ("locked", 423, "login_blocked", "blocked"),
    ],
)
def test_login_events_persist_in_postgres(
    security_api, case, expected_status, event, outcome
):
    from backend.temporal import serialize_instant, utc_now

    client, admin, uid = security_api
    if case == "locked":
        admin.execute(
            "UPDATE users SET account_locked_until=%s WHERE id=%s",
            (serialize_instant(utc_now() + timedelta(hours=1)), uid),
        )
        admin.commit()
    response = client.post(
        "/api/auth/login",
        json={
            "email": (
                "absent@example.test"
                if case == "unmatched_failure"
                else "private@example.com"
            ),
            "password": "test-password" if case == "success" else "wrong-password",
        },
    )
    assert response.status_code == expected_status
    row = admin.execute("SELECT * FROM platform_security_events WHERE event=%s", (event,)).fetchone()
    assert row is not None
    assert (row["event"], row["outcome"], row["actor_user_id"]) == (
        event,
        outcome,
        None if case == "unmatched_failure" else uid,
    )
    assert all(
        secret not in str(row)
        for secret in [
            "private@example.com",
            "absent@example.test",
            "test-password",
            "wrong-password",
        ]
    )
