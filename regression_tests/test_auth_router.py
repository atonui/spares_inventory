"""Authentication extraction contracts, using disposable application configuration."""
import pytest
from pydantic import ValidationError
import main
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from fastapi.routing import APIRoute
from regression_tests.test_stock_safety import api

ROOT = Path(__file__).resolve().parents[1]
AUTH_OPERATIONS = {
    ('GET', '/api/csrf-token'), ('GET', '/api/profile'), ('PUT', '/api/profile'),
    ('POST', '/api/profile/change-password'), ('POST', '/api/auth/revoke-other-sessions'),
    ('POST', '/api/forgot-password'), ('POST', '/api/reset-password'),
    ('GET', '/api/verify-reset-token/{token}'), ('POST', '/api/auth/login'),
    ('GET', '/api/auth/sessions'), ('DELETE', '/api/auth/sessions/{session_id}'),
    ('POST', '/api/auth/sessions/revoke-all'), ('POST', '/api/auth/logout'),
    ('GET', '/api/me'),
}


@pytest.fixture
def auth_api(api):
    main.limiter.reset()
    yield api
    main.limiter.reset()


def set_reset_token(db, token='auth-reset', expired=False):
    expiry = datetime.utcnow() + timedelta(hours=-1 if expired else 1)
    with sqlite3.connect(db) as conn:
        conn.execute('UPDATE users SET reset_token=?,reset_token_expires=? WHERE id=1',
                     (token, expiry.isoformat()))


def test_auth_routes_owned_once_by_extracted_router():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)]
    scoped = [r for r in routes if any((m, r.path) in AUTH_OPERATIONS for m in r.methods)]
    assert len(scoped) == 14
    assert {(m, r.path) for r in scoped for m in r.methods} == AUTH_OPERATIONS
    assert all(r.endpoint.__module__ == 'backend.routes.auth' for r in scoped)
    assert next(r for r in routes if r.path == '/api/equipment' and 'POST' in r.methods).endpoint.__module__ == 'main'


def test_auth_dependencies_keep_override_identity(auth_api):
    client, db, actor = auth_api
    route = next(r for r in main.app.routes if getattr(r, 'path', '') == '/api/profile'
                 and 'PUT' in getattr(r, 'methods', set()))
    assert {d.call for d in route.dependant.dependencies} == {main.get_current_user, main.verify_csrf}
    actor['id'] = 3
    assert client.get('/api/profile').json()['id'] == 3
    assert client.put('/api/profile', json={'email': 'changed@example.com'}).status_code == 200
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT email FROM users WHERE id=3').fetchone()[0] == 'changed@example.com'
    client.cookies.set('session_token', 'revoked')
    assert client.put('/api/profile', json={'email': 'denied@example.com'}).status_code == 401
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT email FROM users WHERE id=3').fetchone()[0] == 'changed@example.com'


def test_auth_runtime_collaborators_are_late_bound(auth_api, tmp_path, monkeypatch):
    client, db, _ = auth_api
    second = tmp_path / 'second.db'
    with sqlite3.connect(db) as source, sqlite3.connect(second) as target:
        source.backup(target)
        target.execute("UPDATE users SET name='Second database' WHERE id=1")
    monkeypatch.setattr(main, 'DATABASE', str(second))
    assert client.get('/api/profile').json()['name'] == 'Second database'
    monkeypatch.setattr(main, 'DATABASE', str(db))
    assert client.get('/api/profile').json()['name'] == 'User 1'
    verified, hashed, emails, activities = [], [], [], []
    def verify(password, password_hash):
        verified.append(password)
        return True
    def hash_password(password):
        hashed.append(password)
        return 'replacement-hash'
    monkeypatch.setattr(main, 'verify_password', verify)
    monkeypatch.setattr(main, 'hash_password', hash_password)
    monkeypatch.setattr(main, 'send_reset_email', lambda email, token: emails.append((email, token)))
    monkeypatch.setattr(main, 'log_activity', lambda **kw: activities.append(kw))
    for secure in [True, False]:
        monkeypatch.setattr(main.settings, 'COOKIE_SECURE', secure)
        response = client.post('/api/auth/login', json={'email': 'user1@example.com', 'password': 'probe'})
        assert response.status_code == 200
        assert ('; secure' in response.headers['set-cookie'].lower()) is secure
    assert verified == ['probe', 'probe']
    response = client.post('/api/forgot-password', json={'email': 'user1@example.com'})
    assert response.status_code == 200
    assert emails[0][0] == 'user1@example.com'
    assert any(a['action'] == 'password_reset_request' for a in activities)
    response = client.post('/api/reset-password', json={'token': emails[0][1], 'new_password': 'new-password'})
    assert response.status_code == 200
    assert hashed == ['new-password']
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT password_hash FROM users WHERE id=1').fetchone()[0] == 'replacement-hash'


@pytest.mark.parametrize('path,payload,limit,initial_status', [
    ('/api/auth/login', {'email': 'absent@example.com', 'password': 'wrong'}, 5, 401),
    ('/api/forgot-password', {'email': 'absent@example.com'}, 3, 200),
    ('/api/reset-password', {'token': 'absent', 'new_password': 'new-password'}, 5, 400),
])
def test_auth_public_rate_limits_preserved(auth_api, path, payload, limit, initial_status):
    client, _, _ = auth_api
    main.app.dependency_overrides.pop(main.verify_csrf)
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
    response = client.post('/api/auth/login', json={'email': 'user1@example.com', 'password': 'test-password', 'remember_me': remember})
    assert response.status_code == 200
    assert response.json()['user']['id'] == 1
    cookie = response.headers['set-cookie'].lower()
    assert f'max-age={seconds}' in cookie
    assert '; httponly' in cookie and '; secure' in cookie and 'samesite=lax' in cookie
    with sqlite3.connect(db) as conn:
        created, expires = conn.execute('SELECT created_at,expires_at FROM sessions ORDER BY id DESC LIMIT 1').fetchone()
    assert abs((datetime.fromisoformat(expires) - datetime.fromisoformat(created)).total_seconds() - seconds) < 2


def test_auth_login_lockout(auth_api):
    client, db, _ = auth_api
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE system_settings SET setting_value='2' WHERE setting_key='max_login_attempts'")
    assert client.post('/api/auth/login', json={'email': 'user1@example.com', 'password': 'wrong'}).status_code == 401
    assert client.post('/api/auth/login', json={'email': 'user1@example.com', 'password': 'wrong'}).status_code == 423
    response = client.post('/api/auth/login', json={'email': 'user1@example.com', 'password': 'test-password'})
    assert response.status_code == 423
    assert response.json()['detail'].startswith('Account locked.')
    with sqlite3.connect(db) as conn:
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
    with sqlite3.connect(db) as conn:
        password_hash, token = conn.execute('SELECT password_hash,reset_token FROM users WHERE id=1').fetchone()
        if expired:
            assert response.json()['detail'] == 'Token has expired'
            assert token == 'auth-reset'
        else:
            assert main.verify_password('new-password', password_hash)
            assert token is None
            assert conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=1 AND is_active=1').fetchone()[0] == 0
    if not expired:
        assert client.post('/api/reset-password', json={'token': 'auth-reset', 'new_password': 'another-password'}).status_code == 400


def test_auth_profile_sessions_and_logout(auth_api):
    client, db, _ = auth_api
    assert client.get('/api/me').json()['id'] == 1
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO sessions(user_id,session_token,expires_at) VALUES(1,'other-auth','2099-01-01')")
    sessions = client.get('/api/auth/sessions').json()
    assert len(sessions) == 2 and sum(s['is_current'] for s in sessions) == 1
    other = next(s['id'] for s in sessions if not s['is_current'])
    assert client.delete(f'/api/auth/sessions/{other}').json() == {'success': True, 'message': 'Session revoked'}
    assert client.delete('/api/auth/sessions/99999').status_code == 404
    response = client.post('/api/auth/logout')
    assert response.status_code == 200
    assert 'max-age=0' in response.headers['set-cookie'].lower()
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=1 AND is_active=1').fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='logout' AND user_id=1").fetchone()[0] == 1


def test_auth_profile_requires_real_csrf(auth_api):
    client, _, _ = auth_api
    main.app.dependency_overrides.pop(main.verify_csrf)
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
                                                'title': 'Email'}},
                       'title': 'UserProfileUpdate',
                       'type': 'object'},
 'UserResponse': {'properties': {'archived_at': {'anyOf': [{'type': 'string'}, {'type': 'null'}],
                                                 'default': None,
                                                 'title': 'Archived At'},
                                 'email': {'title': 'Email', 'type': 'string'},
                                 'id': {'title': 'Id', 'type': 'integer'},
                                 'name': {'title': 'Name', 'type': 'string'},
                                 'role': {'title': 'Role', 'type': 'string'},
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
