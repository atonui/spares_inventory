"""Authentication extraction contracts, using disposable application configuration."""
import json
import pytest
from pydantic import ValidationError
import main
import os
import psycopg
from backend.security import hash_session_credential
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi.routing import APIRoute

ROOT = Path(__file__).resolve().parents[1]
AUTH_OPERATIONS = {
    ('GET', '/api/csrf-token'), ('GET', '/api/profile'), ('PUT', '/api/profile'),
    ('POST', '/api/profile/change-password'), ('POST', '/api/auth/revoke-other-sessions'),
    ('POST', '/api/forgot-password'), ('POST', '/api/reset-password'),
    ('GET', '/api/verify-reset-token/{token}'), ('POST', '/api/auth/login'),
    ('GET', '/api/auth/sessions'), ('DELETE', '/api/auth/sessions/{session_id}'),
    ('POST', '/api/auth/sessions/revoke-all'), ('POST', '/api/auth/logout'),
    ('POST', '/api/profile/email-change-requests'),
    ('GET', '/api/profile/email-change-request'),
    ('DELETE', '/api/profile/email-change-request'),
    ('POST', '/api/auth/email-change/confirm'),
    ('POST', '/api/auth/native/login'),
    ('GET', '/api/me'),
}


@pytest.fixture
def auth_api(stock_api):
    """(client, db, current) on Postgres; every user's password is 'test-password'."""
    stock_api[1].execute('UPDATE users SET password_hash=?', (main.hash_password('test-password'),))
    main.limiter.reset()
    yield stock_api
    main.limiter.reset()


def set_reset_token(db, token='auth-reset', expired=False):
    expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=-1 if expired else 1)
    with db as conn:
        conn.execute('UPDATE users SET reset_token=?,reset_token_expires=? WHERE id=1',
                     (token, expiry.isoformat(timespec='microseconds') + 'Z'))


def test_auth_routes_owned_once_by_extracted_router():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)]
    scoped = [r for r in routes if any((m, r.path) in AUTH_OPERATIONS for m in r.methods)]
    assert len(scoped) == len(AUTH_OPERATIONS)
    assert {(m, r.path) for r in scoped for m in r.methods} == AUTH_OPERATIONS
    assert all(r.endpoint.__module__ == 'backend.routes.auth' for r in scoped)
    assert next(r for r in routes if r.path == '/api/inventory/add' and 'POST' in r.methods).endpoint.__module__ == 'backend.routes.inventory_writes'


def test_auth_dependencies_keep_override_identity(auth_api):
    client, db, actor = auth_api
    route = next(r for r in main.app.routes if getattr(r, 'path', '') == '/api/profile'
                 and 'PUT' in getattr(r, 'methods', set()))
    assert {d.call for d in route.dependant.dependencies} == {main.get_current_user, main.verify_authenticated_csrf}
    actor['id'] = 3
    assert client.get('/api/profile').json()['id'] == 3
    # SaaS members cannot change their own email; their company admin does it.
    assert client.put('/api/profile', json={'email': 'changed@example.com'}).status_code == 403
    client.cookies.set('session_token', 'revoked')
    assert client.put('/api/profile', json={'email': 'denied@example.com'}, headers={'X-CSRF-Token': 'x'}).status_code == 401
    assert db.execute('SELECT email FROM users WHERE id=3').fetchone()[0] == 'engineer@example.test'


def test_forgot_password_queues_mail_in_the_token_transaction(auth_api, monkeypatch):
    client, db, _ = auth_api
    observed = []

    def enqueue(conn, *, email, token, expires_at, frontend_url, encryption_key):
        assert frontend_url == main.FRONTEND_URL
        assert encryption_key == main.settings.MAIL_PAYLOAD_ENCRYPTION_KEY
        assert expires_at is not None
        stored = conn.execute('SELECT reset_token FROM users WHERE email=%s', (email,)).fetchone()['reset_token']
        observed.append((conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE, email, token, stored))
        return 1

    monkeypatch.setattr(main, 'enqueue_password_reset_mail', enqueue)
    # The request schema rejects reserved domains such as .test.
    db.execute("UPDATE users SET email='admin@example.com' WHERE id=1")
    response = client.post('/api/forgot-password', json={'email': 'admin@example.com'})

    assert response.status_code == 200
    assert response.json() == {'message': 'If the email exists, a reset link has been sent'}
    [(in_transaction, email, token, stored_during_enqueue)] = observed
    assert in_transaction and email == 'admin@example.com' and token == stored_during_enqueue
    assert db.execute('SELECT reset_token FROM users WHERE id=1').fetchone()[0] == token


def test_forgot_password_rolls_back_token_and_redacts_logs_when_enqueue_fails(auth_api, monkeypatch, caplog):
    client, db, _ = auth_api
    db.execute("UPDATE users SET reset_token='previous-token', email='private-user@example.com' WHERE id=1")

    def fail_enqueue(_conn, *, email, token, **_kwargs):
        raise RuntimeError(f'{email} {token} private queue diagnostic')

    monkeypatch.setattr(main, 'enqueue_password_reset_mail', fail_enqueue)
    response = client.post('/api/forgot-password', json={'email': 'private-user@example.com'})

    assert response.status_code == 200
    assert response.json() == {'message': 'If the email exists, a reset link has been sent'}
    assert db.execute('SELECT reset_token FROM users WHERE id=1').fetchone()[0] == 'previous-token'
    assert caplog.records
    assert all('private-user@example.com' not in record.getMessage() for record in caplog.records)
    assert all('private queue diagnostic' not in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize('path,payload,limit,initial_status', [
    ('/api/auth/login', {'email': 'absent@example.com', 'password': 'wrong'}, 5, 401),
    ('/api/forgot-password', {'email': 'absent@example.com'}, 3, 200),
    ('/api/reset-password', {'token': 'absent', 'new_password': 'new-password'}, 5, 400),
])
def test_auth_public_rate_limits_preserved(auth_api, path, payload, limit, initial_status):
    client, _, _ = auth_api
    headers = {'X-CSRF-Token': client.get('/api/csrf-token').json()['csrf_token']}
    for _ in range(limit):
        assert client.post(path, json=payload, headers=headers).status_code == initial_status
    assert client.post(path, json=payload, headers=headers).status_code == 429


def test_auth_backend_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.auth, backend.schemas.auth; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; '
              'assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True,
                            text=True, env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('remember,seconds', [(False, 86400), (True, 2592000)])
def test_auth_login_expiry_and_cookie(auth_api, remember, seconds):
    client, db, _ = auth_api
    response = client.post('/api/auth/login', json={'email': 'admin@example.test', 'password': 'test-password', 'remember_me': remember})
    assert response.status_code == 200
    assert response.json()['user']['id'] == 1
    assert 'access_token' not in response.json()
    assert 'token_type' not in response.json()
    cookie = response.headers['set-cookie'].lower()
    assert f'max-age={seconds}' in cookie
    assert '; httponly' in cookie and '; secure' in cookie and 'samesite=lax' in cookie
    with db as conn:
        created, expires = conn.execute('SELECT created_at,expires_at FROM sessions ORDER BY id DESC LIMIT 1').fetchone()
    assert abs((datetime.fromisoformat(expires) - datetime.fromisoformat(created)).total_seconds() - seconds) < 2


def test_native_login_requires_csrf_and_returns_bearer_credentials(auth_api):
    client, _, current = auth_api
    current['anonymous'] = True
    no_csrf = client.post('/api/auth/native/login', json={'email': 'admin@example.test', 'password': 'test-password'})
    assert no_csrf.status_code == 403
    assert no_csrf.json()['detail'] == 'CSRF token missing'

    csrf = client.get('/api/csrf-token').json()['csrf_token']
    response = client.post('/api/auth/native/login', json={'email': 'admin@example.test', 'password': 'test-password'},
                           headers={'X-CSRF-Token': csrf})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['access_token'] and body['refresh_token']
    assert 'set-cookie' not in response.headers


def test_auth_login_lockout(auth_api):
    client, db, _ = auth_api
    with db as conn:
        conn.execute("""INSERT INTO system_settings(setting_key,setting_value) VALUES('max_login_attempts','2')
                        ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value""")
    assert client.post('/api/auth/login', json={'email': 'admin@example.test', 'password': 'wrong'}).status_code == 401
    assert client.post('/api/auth/login', json={'email': 'admin@example.test', 'password': 'wrong'}).status_code == 423
    response = client.post('/api/auth/login', json={'email': 'admin@example.test', 'password': 'test-password'})
    assert response.status_code == 423
    assert response.json()['detail'].startswith('Account locked.')
    with db as conn:
        assert conn.execute('SELECT failed_login_attempts FROM users WHERE id=1').fetchone()[0] == 2


@pytest.mark.parametrize('expired', [False, True])
def test_auth_reset_token_lifecycle(auth_api, expired):
    client, db, _ = auth_api
    set_reset_token(db, expired=expired)
    verification = client.get('/api/verify-reset-token/auth-reset')
    assert verification.status_code == (400 if expired else 200)
    if not expired:
        assert verification.json() == {'valid': True}
    response = client.post('/api/reset-password', json={'token': 'auth-reset', 'new_password': 'new-password'})
    assert response.status_code == (400 if expired else 200)
    with db as conn:
        password_hash, token = conn.execute('SELECT password_hash,reset_token FROM users WHERE id=1').fetchone()
        if expired:
            assert response.json()['detail'] == 'Token has expired'
            assert token == 'auth-reset'
        else:
            assert main.verify_password('new-password', password_hash)
            assert token is None
            assert conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=1 AND is_active').fetchone()[0] == 0
    if not expired:
        assert client.post('/api/reset-password', json={'token': 'auth-reset', 'new_password': 'another-password'}).status_code == 400


def test_auth_profile_sessions_and_logout(auth_api):
    client, db, _ = auth_api
    assert client.get('/api/me').json()['id'] == 1
    with db as conn:
        conn.execute("INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES(1,?,'2099-01-01T00:00:00.000000Z')",
                     (hash_session_credential('other-auth'),))
    sessions = client.get('/api/auth/sessions').json()
    assert len(sessions) == 2 and sum(s['is_current'] for s in sessions) == 1
    other = next(s['id'] for s in sessions if not s['is_current'])
    assert client.delete(f'/api/auth/sessions/{other}').json() == {'success': True, 'message': 'Session revoked'}
    assert client.delete('/api/auth/sessions/99999').status_code == 404
    response = client.post('/api/auth/logout')
    assert response.status_code == 200
    assert 'max-age=0' in response.headers['set-cookie'].lower()
    with db as conn:
        assert conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=1 AND is_active').fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM platform_audit_events WHERE action='user_logout' AND actor_user_id=1").fetchone()[0] == 1


def test_auth_profile_requires_real_csrf(auth_api):
    client, _, _ = auth_api
    client.cookies.set('session_token', 'admin-token')
    assert client.put('/api/profile', json={}).json()['detail'] == 'CSRF token missing'
    assert client.put('/api/profile', json={}, headers={'X-CSRF-Token': 'invalid'}).json()['detail'] == 'Invalid CSRF token'
    token = client.get('/api/csrf-token').json()['csrf_token']
    assert client.put('/api/profile', json={}, headers={'X-CSRF-Token': token}).status_code == 200

EXPECTED_SCHEMAS = {'ForgotPasswordRequest': {'properties': {'email': {'format': 'email',
                                                    'title': 'Email',
                                                    'type': 'string'}},
                           'required': ['email'],
                           'title': 'ForgotPasswordRequest',
                           'type': 'object'},
 'PasswordChange': {'properties': {'current_password': {'title': 'Current Password',
                                                        'type': 'string'},
                                   'new_password': {'title': 'New Password', 'type': 'string'}},
                    'required': ['current_password', 'new_password'],
                    'title': 'PasswordChange',
                    'type': 'object'},
 'ResetPasswordRequest': {'properties': {'new_password': {'title': 'New Password',
                                                          'type': 'string'},
                                         'token': {'title': 'Token', 'type': 'string'}},
                          'required': ['token', 'new_password'],
                          'title': 'ResetPasswordRequest',
                          'type': 'object'},
 'UserLogin': {'properties': {'email': {'title': 'Email', 'type': 'string'},
                              'password': {'title': 'Password', 'type': 'string'},
                              'remember_me': {'default': False,
                                              'title': 'Remember Me',
                                              'type': 'boolean'}},
               'required': ['email', 'password'],
               'title': 'UserLogin',
               'type': 'object'},
 'UserProfileUpdate': {'properties': {'email': {'anyOf': [{'format': 'email', 'type': 'string'},
                                                          {'type': 'null'}],
                                                'default': None,
                                                'title': 'Email'},
                                    'display_timezone': {'anyOf': [{'maxLength': 100, 'type': 'string'}, {'type': 'null'}],
                                                         'default': None, 'title': 'Display Timezone'}},
                       'title': 'UserProfileUpdate',
                       'type': 'object'},
 'UserResponse': {'properties': {'archived_at': {'anyOf': [{'type': 'string'}, {'type': 'null'}],
                                                 'default': None,
                                                 'title': 'Archived At'},
                                 'email': {'title': 'Email', 'type': 'string'},
                                 'id': {'title': 'Id', 'type': 'integer'},
                                 'is_platform_admin': {'default': False,
                                                       'title': 'Is Platform Admin',
                                                       'type': 'boolean'},
                                 'name': {'title': 'Name', 'type': 'string'},
                                 'role': {'title': 'Role', 'type': 'string'},
                                 'saas_mode': {'default': False,
                                               'title': 'Saas Mode',
                                               'type': 'boolean'},
                                 'territory': {'anyOf': [{'type': 'string'}, {'type': 'null'}],
                                               'title': 'Territory'}},
                  'required': ['id', 'email', 'name', 'role', 'territory'],
                  'title': 'UserResponse',
                  'type': 'object'}}


def test_auth_schemas_preserve_identity_and_contract():
    from backend.schemas import auth as auth_schemas
    for name, expected in EXPECTED_SCHEMAS.items():
        model = getattr(auth_schemas, name)
        assert getattr(main, name) is model
        assert model.model_json_schema() == expected
    assert auth_schemas.UserLogin(email='x', password='y').remember_me is False
    assert auth_schemas.UserProfileUpdate().email is None
    with pytest.raises(ValidationError):
        auth_schemas.ForgotPasswordRequest(email='not-an-email')
