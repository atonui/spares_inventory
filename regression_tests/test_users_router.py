"""User router composition and actual HTTP preservation coverage."""
from contextlib import closing
import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.routing import APIRoute
from pydantic import ValidationError

import main
from backend.database import connect_database
from backend.schemas.users import CreateUserRequest, UpdateUserRequest
from regression_tests.test_session_write_routes import session_api, database_state

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    ('GET', '/api/users'), ('POST', '/api/users'),
    ('PUT', '/api/users/{target_user_id}'), ('DELETE', '/api/users/{target_user_id}'),
    ('POST', '/api/users/{target_user_id}/restore'),
}


def test_users_router_registration_and_dependency_identity():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path == '/api/users' or r.path.startswith('/api/users/'))]
    assert len(routes) == 5
    assert {(method, r.path) for r in routes for method in r.methods} == OPERATIONS
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.users'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods != {'GET'}:
            expected.add(main.verify_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected
    read = next(r for r in routes if r.methods == {'GET'})
    assert read.response_model == list[main.UserResponse] or read.response_model == main.List[main.UserResponse]


def test_users_schema_reexports_and_defaults():
    assert main.CreateUserRequest is CreateUserRequest
    assert main.UpdateUserRequest is UpdateUserRequest
    assert main.UserRole == main.CreateUserRequest.model_fields['role'].annotation
    assert UpdateUserRequest().model_dump() == {
        'name': None, 'role': None, 'territory': None, 'password': None,
    }
    for role in ('engineer', 'manager', 'admin', 'superadmin'):
        assert CreateUserRequest(email='x', name='X', password='p', role=role).role == role
    with pytest.raises(ValidationError):
        CreateUserRequest(email='x', name='X', password='p', role='owner')


@pytest.mark.parametrize('actor', ['admin-token', 'root-token', 'manager-token', 'engineer-token'])
@pytest.mark.parametrize('include_archived', [False, True])
def test_users_list_preserves_archive_visibility_and_permissions(session_api, actor, include_archived):
    client, path, _ = session_api
    client.cookies.set('session_token', actor)
    with closing(connect_database(path)) as conn, conn:
        conn.execute("INSERT INTO users(id,email,name,password_hash,role,archived_at) VALUES(5,'archived@example.test','Archived','unused','engineer','2000-01-01')")
    response = client.get('/api/users', params={'include_archived': include_archived})
    if actor in ('manager-token', 'engineer-token'):
        assert response.status_code == 403, response.text
        return
    assert response.status_code == 200, response.text
    ids = {row['id'] for row in response.json()}
    assert (5 in ids) == include_archived
    assert all('password_hash' not in row for row in response.json())


def test_users_create_uses_current_hash_guard_and_audit_owner(session_api, monkeypatch):
    client, path, _ = session_api
    calls = []
    guard = main.require_user_management
    audit = main._record_mutation_activity
    monkeypatch.setattr(main, 'hash_password', lambda password: 'current-' + password)
    def record_guard(*args, **kwargs):
        conn = kwargs['conn']
        assert conn.in_transaction
        calls.append(conn)
        return guard(*args, **kwargs)
    def record_audit(conn, *args, **kwargs):
        assert conn is calls[-1] and conn.in_transaction
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'require_user_management', record_guard)
    monkeypatch.setattr(main, '_record_mutation_activity', record_audit)
    response = client.post('/api/users', json={
        'email': 'new@example.test', 'name': 'New', 'password': 'test-password', 'role': 'engineer',
    })
    assert response.status_code == 200, response.text
    with closing(connect_database(path)) as conn:
        assert conn.execute("SELECT password_hash FROM users WHERE email='new@example.test'").fetchone()[0] == 'current-test-password'
        assert conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='create_user'").fetchone()[0] == 1


def test_users_update_audit_failure_rolls_back(session_api, monkeypatch):
    client, path, _ = session_api
    def failed_audit(conn, *args, **kwargs):
        assert conn.in_transaction
        raise RuntimeError('audit unavailable')
    monkeypatch.setattr(main, '_record_mutation_activity', failed_audit)
    before = database_state(path)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        client.put('/api/users/4', json={'name': 'Changed'})
    assert database_state(path) == before


def test_users_archive_service_remains_late_bound(session_api, monkeypatch):
    client, _, _ = session_api
    calls = []
    def archive(*args, **kwargs):
        calls.append((args, kwargs))
        return {'success': True}
    monkeypatch.setattr(main, 'archive_record', archive)
    assert client.delete('/api/users/4').status_code == 200
    assert client.post('/api/users/4/restore').status_code == 200
    assert calls == [
        (('users', 4, 1), {'session_token': 'admin-token'}),
        (('users', 4, 1), {'restore': True, 'session_token': 'admin-token'}),
    ]


def test_users_imports_are_inert(tmp_path):
    script = (
        'import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
        'import backend.routes.users, backend.schemas.users; '
        'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before'
    )
    result = subprocess.run(
        [sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
        env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')},
    )
    assert result.returncode == 0, result.stderr
