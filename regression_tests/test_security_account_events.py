"""Account events must be private, global, and truthful about committed state."""

import sqlite3

import main
import psycopg
import pytest

from regression_tests.test_stock_safety import api
from regression_tests.test_security_reset_events import reset_unit_api, security_api

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.mark.parametrize(
    "case,expected_status,event",
    [
        ("known_failure", 401, "login_failed"),
        ("unknown_failure", 401, "login_failed"),
        ("lockout", 423, "account_locked"),
        ("blocked", 423, "login_blocked"),
        ("success", 200, "login_succeeded"),
    ],
)
def test_login_security_events_replace_tenant_activity_without_identifiers(
    reset_unit_api, case, expected_status, event, caplog
):
    client, db, events = reset_unit_api
    with sqlite3.connect(db) as conn:
        if case == "success":
            conn.execute("UPDATE users SET name='user1@example.com' WHERE id=1")
        if case == "lockout":
            conn.execute(
                "UPDATE system_settings SET setting_value='1' WHERE setting_key='max_login_attempts'"
            )
        if case == "blocked":
            conn.execute(
                "UPDATE users SET account_locked_until='2099-01-01T00:00:00.000000Z' WHERE id=1"
            )
    response = client.post(
        "/api/auth/login",
        json={
            "email": (
                "private-unknown@example.com"
                if case == "unknown_failure"
                else "user1@example.com"
            ),
            "password": (
                "test-password" if case == "success" else "private-wrong-password"
            ),
        },
    )
    assert response.status_code == expected_status
    auth_events = [e for e in events if e["event"] in {"login_succeeded", "login_failed", "login_blocked", "account_locked"}]
    assert len(auth_events) == 1
    assert auth_events[0]["event"] == event
    assert auth_events[0]["actor_user_id"] == (None if case == "unknown_failure" else 1)
    assert all(
        secret not in str(events) + caplog.text
        for secret in [
            "private-unknown@example.com",
            "user1@example.com",
            "private-wrong-password",
        ]
    )
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM activity_logs WHERE action IN ('login','login_success','login_failed','login_blocked','account_locked')"
            ).fetchone()[0]
            == 0
        )


def test_password_change_emits_only_after_committed_password_and_revocation(
    reset_unit_api,
):
    client, db, events = reset_unit_api
    response = client.post(
        "/api/profile/change-password",
        headers={"Cookie": "session_token=fixture-session-1"},
        json={
            "current_password": "test-password",
            "new_password": "private-new-password",
        },
    )
    assert response.status_code == 200
    assert [
        (e["event"], e["outcome"], e["actor_user_id"], e.get("details", {}))
        for e in events
    ] == [("password_changed", "success", 1, {})]
    assert "private-new-password" not in str(events)
    with sqlite3.connect(db) as conn:
        assert main.verify_password(
            "private-new-password",
            conn.execute("SELECT password_hash FROM users WHERE id=1").fetchone()[0],
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id=1 AND is_active=1"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "current,new",
    [("wrong-current", "private-new-password"), ("test-password", "short")],
)
def test_rejected_password_change_never_emits_success(reset_unit_api, current, new):
    client, db, events = reset_unit_api
    response = client.post(
        "/api/profile/change-password",
        headers={"Cookie": "session_token=fixture-session-1"},
        json={"current_password": current, "new_password": new},
    )
    assert response.status_code == 400
    assert events == []
    with sqlite3.connect(db) as conn:
        assert main.verify_password(
            "test-password",
            conn.execute("SELECT password_hash FROM users WHERE id=1").fetchone()[0],
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id=1 AND is_active=1"
            ).fetchone()[0]
            == 1
        )


def test_password_commit_failure_never_logs_success(reset_unit_api, caplog):
    client, db, events = reset_unit_api
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """CREATE TABLE commit_guard (user_id INTEGER REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED);
            CREATE TRIGGER reject_password_commit AFTER UPDATE OF password_hash ON users BEGIN
            INSERT INTO commit_guard VALUES (-1); END;"""
        )
    with pytest.raises(sqlite3.IntegrityError):
        client.post(
            "/api/profile/change-password",
            headers={"Cookie": "session_token=fixture-session-1"},
            json={
                "current_password": "test-password",
                "new_password": "private-new-password",
            },
        )
    assert events == []
    assert "Password changed successfully" not in caplog.text
    with sqlite3.connect(db) as conn:
        assert main.verify_password(
            "test-password",
            conn.execute("SELECT password_hash FROM users WHERE id=1").fetchone()[0],
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM sessions WHERE user_id=1 AND is_active=1"
            ).fetchone()[0]
            == 1
        )


def test_lockout_transition_persists_in_postgres(security_api, monkeypatch):
    client, admin, uid = security_api
    cfg = main.get_security_config()
    cfg["max_login_attempts"] = 1
    monkeypatch.setattr(main, "get_security_config", lambda: cfg)
    response = client.post(
        "/api/auth/login",
        json={"email": "private@example.com", "password": "wrong-password"},
    )
    assert response.status_code == 423
    row = admin.execute(
        "SELECT event,outcome,actor_user_id,details FROM platform_security_events"
    ).fetchone()
    assert row == {
        "event": "account_locked",
        "outcome": "blocked",
        "actor_user_id": uid,
        "details": {"account_match": True},
    }
    assert (
        admin.execute(
            "SELECT account_locked_until FROM users WHERE id=%s", (uid,)
        ).fetchone()["account_locked_until"]
        is not None
    )


@pytest.mark.parametrize("commit_failure", [False, True])
def test_password_change_postgres_event_tracks_commit(
    security_api, commit_failure, caplog
):
    from backend.services.session_credentials import hash_session_credential

    client, admin, uid = security_api
    admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,'2099-01-01T00:00:00.000000Z')",
        (uid, hash_session_credential("private-session-token")),
    )
    if commit_failure:
        admin.execute(
            """CREATE FUNCTION reject_password_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit guard'; END $$"""
        )
        admin.execute(
            "CREATE CONSTRAINT TRIGGER reject_password_commit AFTER UPDATE ON users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_password_commit()"
        )
    admin.commit()
    main.app.dependency_overrides[main.verify_authenticated_csrf] = lambda: True
    request = lambda: client.post(
        "/api/profile/change-password",
        headers={"Cookie": "session_token=private-session-token"},
        json={
            "current_password": "test-password",
            "new_password": "private-new-password",
        },
    )
    if commit_failure:
        with pytest.raises(psycopg.errors.RaiseException):
            request()
        assert (
            admin.execute(
                "SELECT count(*) AS n FROM platform_security_events"
            ).fetchone()["n"]
            == 0
        )
        assert "Password changed successfully" not in caplog.text
    else:
        assert request().status_code == 200
        row = admin.execute(
            "SELECT event,outcome,actor_user_id,details FROM platform_security_events"
        ).fetchone()
        assert row == {
            "event": "password_changed",
            "outcome": "success",
            "actor_user_id": uid,
            "details": {},
        }
        assert "private-new-password" not in str(row)
    user = admin.execute(
        "SELECT password_hash FROM users WHERE id=%s", (uid,)
    ).fetchone()
    assert main.verify_password(
        "test-password" if commit_failure else "private-new-password",
        user["password_hash"],
    )
    assert (
        admin.execute(
            "SELECT is_active FROM sessions WHERE user_id=%s", (uid,)
        ).fetchone()["is_active"]
        is commit_failure
    )
