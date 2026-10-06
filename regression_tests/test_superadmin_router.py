"""Superadmin extraction contracts and disposable HTTP behaviour."""
import pytest
import main
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from fastapi.routing import APIRoute
from backend.database import connect_database
from regression_tests.test_session_write_routes import session_api, database_state

ROOT = Path(__file__).resolve().parents[1]
PREFIX = '/api/superadmin'
OPERATIONS = {
    ('POST', '/users/{target_id}/reset-password'), ('GET', '/dashboard'),
    ('GET', '/locked-accounts'), ('POST', '/unlock-account'), ('POST', '/unlock-accounts/bulk'),
    ('GET', '/sessions'), ('POST', '/sessions/force-logout'), ('POST', '/sessions/force-logout-all'),
    ('GET', '/security-config'), ('PUT', '/security-config/{key}'), ('GET', '/users'),
    ('PUT', '/users/{target_id}/role'), ('GET', '/database/tables'), ('POST', '/database/query'),
    ('GET', '/database/backup'), ('POST', '/database/restore'), ('POST', '/database/vacuum'),
    ('DELETE', '/database/logs/purge'), ('POST', '/announcement'), ('DELETE', '/announcement'),
    ('GET', '/announcement'), ('GET', '/audit-log'),
}


@pytest.fixture
def super_api(session_api):
    session_api[0].cookies.set('session_token', 'root-token')
    return session_api


@pytest.mark.parametrize('revoked', [False, True])
def test_superadmin_security_config_get_alias(super_api, revoked):
    client, path, control = super_api
    assert client.get(PREFIX + '/security-config').status_code == 422
    if revoked:
        control['damage'] = "UPDATE sessions SET is_active=0 WHERE session_token='root-token'"
    response = client.request('GET', PREFIX + '/security-config?key=max_login_attempts', json={'value': '7'})
    assert response.status_code == (401 if revoked else 200), response.text
    if revoked:
        assert database_state(path) == control['before']
    else:
        assert response.json() == {'success': True, 'key': 'max_login_attempts', 'value': 7}
        with closing(connect_database(path)) as conn:
            assert conn.execute("SELECT setting_value FROM system_settings WHERE setting_key='max_login_attempts'").fetchone()[0] == '7'
            assert conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='update_security_config'").fetchone()[0] == 1


def test_superadmin_announcement_remains_public(super_api):
    client, path, _ = super_api
    main.app.dependency_overrides.clear()
    client.cookies.clear()
    assert client.get(PREFIX + '/announcement').json() == {'announcement': None}
    payload = {'message': 'Public notice', 'level': 'info', 'created_at': '2026-01-01'}
    with closing(connect_database(path)) as conn, conn:
        conn.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('system_announcement',?)", (json.dumps(payload),))
    response = client.get(PREFIX + '/announcement')
    assert response.status_code == 200
    assert response.json() == {'announcement': payload}


@pytest.mark.parametrize('endpoint', ['/dashboard', '/locked-accounts', '/sessions', '/users', '/database/tables', '/audit-log'])
@pytest.mark.parametrize('actor', ['root-token', 'engineer-token'])
def test_superadmin_read_routes_preserved(super_api, endpoint, actor):
    client, path, _ = super_api
    client.cookies.set('session_token', actor)
    with closing(connect_database(path)) as conn, conn:
        conn.execute("UPDATE users SET account_locked_until='2099-01-01',failed_login_attempts=2 WHERE id=1")
        conn.execute("INSERT INTO activity_logs(user_id,username,action) VALUES(2,'superadmin','read-fixture')")
    response = client.get(PREFIX + endpoint)
    if actor == 'engineer-token':
        assert response.status_code == 403
        assert response.json()['detail'] == 'Superadmin access required'
        return
    assert response.status_code == 200, response.text
    data = response.json()
    if endpoint == '/dashboard':
        assert data['locked_accounts'] == 1 and data['active_sessions'] == 4
        assert data['users_by_role'] == {'admin': 1, 'superadmin': 1, 'engineer': 1, 'manager': 1}
        assert data['database_size_bytes'] == path.stat().st_size
    elif endpoint == '/locked-accounts':
        assert [r['id'] for r in data] == [1] and data[0]['failed_login_attempts'] == 2
    elif endpoint == '/sessions':
        assert {r['user_id'] for r in data} == {1, 2, 3, 4}
        assert all(r['is_active'] == 1 for r in data)
    elif endpoint == '/users':
        assert {r['id'] for r in data} == {1, 2, 3, 4}
        assert next(r for r in data if r['id'] == 1)['email'] == 'admin@example.test'
    elif endpoint == '/database/tables':
        assert data['users']['row_count'] == 4
        assert 'role' in {c['name'] for c in data['users']['columns']}
    else:
        assert any(r['action'] == 'read-fixture' and r['user_id'] == 2 for r in data)


def test_superadmin_readonly_sql_contract(super_api):
    client, _, _ = super_api
    response = client.post(PREFIX + '/database/query', json={'sql': 'SELECT name FROM users WHERE id=?', 'params': [3]})
    assert response.json() == {'columns': ['name'], 'rows': [{'name': 'Engineer'}], 'count': 1}
    response = client.post(PREFIX + '/database/query', json={'sql': 'SELECT a.id FROM users a CROSS JOIN users b CROSS JOIN users c CROSS JOIN users d CROSS JOIN users e'})
    assert response.status_code == 200 and response.json()['count'] == 500
    for sql, detail in [('DELETE FROM users', 'Only SELECT queries are allowed'), ("SELECT 'DROP'", "Keyword 'DROP' is not allowed")]:
        response = client.post(PREFIX + '/database/query', json={'sql': sql})
        assert response.status_code == 400 and response.json()['detail'] == detail


def test_superadmin_dynamic_database_paths(super_api, tmp_path, monkeypatch):
    import database_restore
    client, path, _ = super_api
    second = tmp_path / 'second.db'
    with closing(connect_database(path)) as source, closing(connect_database(second)) as target:
        source.backup(target)
        with target:
            target.execute("UPDATE users SET name='Second database' WHERE id=1")
    monkeypatch.setattr(main, 'DATABASE', str(second))
    dashboard = client.get(PREFIX + '/dashboard')
    assert dashboard.status_code == 200 and dashboard.json()['database_size_bytes'] == second.stat().st_size
    backup = client.get(PREFIX + '/database/backup')
    assert backup.status_code == 200
    name = backup.headers['content-disposition'].split('filename=')[1].strip('"')
    snapshot = tmp_path / 'download.db'
    try:
        snapshot.write_bytes(backup.content)
        with closing(connect_database(snapshot)) as conn:
            assert conn.execute('SELECT name FROM users WHERE id=1').fetchone()[0] == 'Second database'
    finally:
        (Path('/tmp') / name).unlink(missing_ok=True)
    response = client.post(PREFIX + '/database/vacuum')
    assert response.status_code == 200
    assert response.json()['after_bytes'] == second.stat().st_size
    destinations, default_calls, validations = [], [], []
    restore = database_restore.restore_database
    defaults = main.database_defaults
    validate = main.require_session
    def observe_defaults():
        value = defaults()
        default_calls.append(value)
        return value
    def observe_validation(conn, token, *, expected_user_id=None):
        validations.append((conn.in_transaction, token, expected_user_id))
        return validate(conn, token, expected_user_id=expected_user_id)
    def observe_restore(upload, target, user_id, **kwargs):
        destinations.append(target)
        assert kwargs['defaults'] == default_calls[-1]
        return restore(upload, target, user_id, **kwargs)
    monkeypatch.setattr(main, 'database_defaults', observe_defaults)
    monkeypatch.setattr(main, 'require_session', observe_validation)
    monkeypatch.setattr(database_restore, 'restore_database', observe_restore)
    response = client.post(PREFIX + '/database/restore', files={'file': ('upload.db', snapshot.read_bytes())})
    assert response.status_code == 200, response.text
    assert destinations == [str(second)] and default_calls
    assert (True, 'root-token', 2) in validations
    assert 'max-age=0' in response.headers['set-cookie'].lower()
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT name FROM users WHERE id=1').fetchone()[0] == 'Admin'
        assert conn.execute("SELECT is_active FROM sessions WHERE session_token='root-token'").fetchone()[0] == 1
    with closing(connect_database(second)) as conn:
        assert conn.execute('SELECT name FROM users WHERE id=1').fetchone()[0] == 'Second database'
        assert conn.execute('SELECT COUNT(*) FROM sessions WHERE is_active=1').fetchone()[0] == 0


def test_superadmin_callbacks_keep_borrowed_connection(super_api, monkeypatch):
    client, path, _ = super_api
    guards, audits = [], []
    guard, activity = main.require_superadmin, main.log_activity
    def record_guard(user_id, conn=None):
        if conn is not None:
            assert conn.in_transaction
            guards.append(conn)
        return guard(user_id, conn)
    def record_activity(*args, **kwargs):
        conn = kwargs.get('conn')
        assert conn is not None and conn.in_transaction
        audits.append(conn)
        return activity(*args, **kwargs)
    monkeypatch.setattr(main, 'require_superadmin', record_guard)
    monkeypatch.setattr(main, 'log_activity', record_activity)
    response = client.put(PREFIX + '/security-config/max_login_attempts', json={'value': '7'})
    assert response.status_code == 200 and guards[-1] is audits[-1]
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_admin_audit BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before = database_state(path)
    with pytest.raises(sqlite3.IntegrityError, match='audit unavailable'):
        client.put(PREFIX + '/security-config/max_login_attempts', json={'value': '8'})
    assert database_state(path) == before and guards[-1] is audits[-1]
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        client.portal.call(audits[-1].execute, 'SELECT 1')
    with closing(connect_database(path)) as conn:
        conn.execute('BEGIN IMMEDIATE')


def test_superadmin_reset_password_uses_current_hasher(super_api, monkeypatch):
    client, path, _ = super_api
    monkeypatch.setattr(main, 'hash_password', lambda password: 'changed-' + password)
    response = client.post(PREFIX + '/users/3/reset-password', json={'user_id': 3, 'new_password': 'new-password'})
    assert response.status_code == 200
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT password_hash FROM users WHERE id=3').fetchone()[0] == 'changed-new-password'
        assert conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=3 AND is_active=1').fetchone()[0] == 0


def test_superadmin_restore_upload_cap(super_api, monkeypatch):
    import database_restore
    client, _, _ = super_api
    def unexpected_restore(*args, **kwargs):
        pytest.fail('oversized upload reached restore')
    monkeypatch.setattr(database_restore, 'restore_database', unexpected_restore)
    response = client.post(PREFIX + '/database/restore', files={'file': ('large.db', b'x' * (20 * 1024 * 1024 + 1))})
    assert response.status_code == 413
    assert response.json()['detail'] == 'Maximum database size is 20 MB'


def test_superadmin_routes_owned_once_by_extracted_router():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute) and r.path.startswith(PREFIX + '/')]
    assert len(routes) == 22
    assert {(method, r.path[len(PREFIX):]) for r in routes for method in r.methods} == OPERATIONS
    assert all(r.endpoint.__module__ == 'backend.routes.superadmin' and r.tags == ['superadmin'] for r in routes)
    get = next(r for r in routes if r.path == PREFIX + '/security-config')
    put = next(r for r in routes if r.path == PREFIX + '/security-config/{key}')
    assert get.endpoint is put.endpoint
    assert next(r for r in main.app.routes if getattr(r, 'path', '') == '/api/stores' and 'POST' in getattr(r, 'methods', set())).endpoint.__module__ == 'main'


def test_superadmin_dependency_override_identity(super_api):
    client, path, control = super_api
    route = next(r for r in main.app.routes if getattr(r, 'path', '') == PREFIX + '/security-config/{key}')
    assert {d.call for d in route.dependant.dependencies} == {main.get_current_user, main.verify_csrf}
    assert client.put(PREFIX + '/security-config/max_login_attempts', json={'value': '7'}).status_code == 200
    control['damage'] = "UPDATE sessions SET is_active=0 WHERE session_token='root-token'"
    assert client.put(PREFIX + '/security-config/max_login_attempts', json={'value': '8'}).status_code == 401
    assert database_state(path) == control['before']


def test_superadmin_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.superadmin, backend.schemas.superadmin; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True,
                            text=True, env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr

EXPECTED_SCHEMAS = {'AccountUnlockRequest': {'properties': {'user_id': {'title': 'User Id', 'type': 'integer'}},
                          'required': ['user_id'],
                          'title': 'AccountUnlockRequest',
                          'type': 'object'},
 'BulkUnlockRequest': {'properties': {'user_ids': {'items': {'type': 'integer'},
                                                   'title': 'User Ids',
                                                   'type': 'array'}},
                       'required': ['user_ids'],
                       'title': 'BulkUnlockRequest',
                       'type': 'object'},
 'DatabaseQueryRequest': {'properties': {'params': {'anyOf': [{'items': {}, 'type': 'array'},
                                                              {'type': 'null'}],
                                                    'default': [],
                                                    'title': 'Params'},
                                         'sql': {'title': 'Sql', 'type': 'string'}},
                          'required': ['sql'],
                          'title': 'DatabaseQueryRequest',
                          'type': 'object'},
 'ForceLogoutRequest': {'properties': {'user_id': {'title': 'User Id', 'type': 'integer'}},
                        'required': ['user_id'],
                        'title': 'ForceLogoutRequest',
                        'type': 'object'},
 'SecurityConfigUpdate': {'properties': {'lockout_duration_minutes': {'anyOf': [{'type': 'integer'},
                                                                                {'type': 'null'}],
                                                                      'default': None,
                                                                      'title': 'Lockout Duration '
                                                                               'Minutes'},
                                         'max_login_attempts': {'anyOf': [{'type': 'integer'},
                                                                          {'type': 'null'}],
                                                                'default': None,
                                                                'title': 'Max Login Attempts'},
                                         'remember_me_duration_days': {'anyOf': [{'type': 'integer'},
                                                                                 {'type': 'null'}],
                                                                       'default': None,
                                                                       'title': 'Remember Me '
                                                                                'Duration Days'},
                                         'session_duration_hours': {'anyOf': [{'type': 'integer'},
                                                                              {'type': 'null'}],
                                                                    'default': None,
                                                                    'title': 'Session Duration '
                                                                             'Hours'}},
                          'title': 'SecurityConfigUpdate',
                          'type': 'object'},
 'SuperadminPasswordReset': {'properties': {'new_password': {'title': 'New Password',
                                                             'type': 'string'},
                                            'user_id': {'title': 'User Id', 'type': 'integer'}},
                             'required': ['user_id', 'new_password'],
                             'title': 'SuperadminPasswordReset',
                             'type': 'object'},
 'SystemAnnouncementRequest': {'properties': {'level': {'default': 'info',
                                                        'title': 'Level',
                                                        'type': 'string'},
                                              'message': {'title': 'Message', 'type': 'string'}},
                               'required': ['message'],
                               'title': 'SystemAnnouncementRequest',
                               'type': 'object'},
 'SystemSettingUpdate': {'properties': {'value': {'title': 'Value', 'type': 'string'}},
                         'required': ['value'],
                         'title': 'SystemSettingUpdate',
                         'type': 'object'},
 'UserRoleUpdate': {'properties': {'role': {'title': 'Role', 'type': 'string'}},
                    'required': ['role'],
                    'title': 'UserRoleUpdate',
                    'type': 'object'}}


def test_superadmin_schemas_preserve_identity_and_contract():
    from backend.schemas import superadmin as schemas
    for name, expected in EXPECTED_SCHEMAS.items():
        assert getattr(main,name) is getattr(schemas,name)
        assert getattr(schemas,name).model_json_schema() == expected
    first = schemas.DatabaseQueryRequest(sql='SELECT 1')
    second = schemas.DatabaseQueryRequest(sql='SELECT 1')
    assert first.params == second.params == []
    first.params.append('x')
    assert second.params == []
    assert schemas.SystemAnnouncementRequest(message='x').level == 'info'
    assert all(value is None for value in schemas.SecurityConfigUpdate().model_dump().values())
