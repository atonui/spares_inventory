from contextlib import closing
import asyncio
import sqlite3

import pytest
from fastapi import HTTPException

from backend.database import connect_database
from regression_tests.session_fixtures import session_database


def test_authentication_commits_activity_for_only_the_validated_session(tmp_path):
    from backend.services.session_authentication import authenticate_session

    path = session_database(tmp_path / 'sessions.db')
    with closing(connect_database(path)) as conn:
        conn.execute("UPDATE sessions SET last_activity='2000-01-01'")
        conn.commit()
    assert authenticate_session('admin-token', lambda: connect_database(path)) == 1
    with closing(connect_database(path)) as conn:
        rows = conn.execute('SELECT id,last_activity FROM sessions ORDER BY id').fetchall()
        assert rows[0]['last_activity'] != '2000-01-01'
        assert all(row['last_activity'] == '2000-01-01' for row in rows[1:])


@pytest.mark.parametrize('token,detail', [(None, 'Not authenticated'), ('absent', 'Invalid or expired session')])
def test_denied_authentication_preserves_activity(tmp_path, token, detail):
    from backend.services.session_authentication import authenticate_session

    path = session_database(tmp_path / 'sessions.db')
    with closing(connect_database(path)) as conn:
        before = [tuple(row) for row in conn.execute('SELECT * FROM sessions')]
    with pytest.raises(HTTPException) as error:
        authenticate_session(token, lambda: connect_database(path))
    assert (error.value.status_code, error.value.detail) == (401, detail)
    with closing(connect_database(path)) as conn:
        assert [tuple(row) for row in conn.execute('SELECT * FROM sessions')] == before


def test_activity_update_failure_rolls_back_and_releases_writer(tmp_path):
    from backend.services.session_authentication import authenticate_session

    path = session_database(tmp_path / 'sessions.db')
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_activity BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'activity failure'); END")
        conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match='activity failure'):
        authenticate_session('admin-token', lambda: connect_database(path))
    with closing(connect_database(path)) as conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('DROP TRIGGER reject_activity')
        conn.commit()


def test_main_dependency_uses_current_connection_factory(tmp_path, monkeypatch):
    import main

    path = session_database(tmp_path / 'sessions.db')
    monkeypatch.setattr(main, 'get_db_connection', lambda: connect_database(path))
    assert asyncio.run(main.get_current_user('engineer-token')) == 3


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
