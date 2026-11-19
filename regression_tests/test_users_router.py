"""User router composition and actual HTTP preservation coverage."""
import os
from pathlib import Path
import subprocess
import sys

import psycopg
import pytest
from fastapi.routing import APIRoute
from pydantic import ValidationError

import main
from backend.schemas.users import CreateUserRequest, UpdateUserRequest
from regression_tests.postgres_app import database_state

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    ('GET', '/api/users'), ('POST', '/api/users'),
    ('PUT', '/api/users/{target_user_id}'), ('DELETE', '/api/users/{target_user_id}'),
    ('POST', '/api/users/{target_user_id}/restore'),
    ('POST', '/api/users/{target_user_id}/remove'),
    ('POST', '/api/users/{target_user_id}/email-change-requests'),
    ('GET', '/api/users/{target_user_id}/email-change-request'),
    ('DELETE', '/api/users/{target_user_id}/email-change-request'),
}


def test_users_router_registration_and_dependency_identity():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path == '/api/users' or r.path.startswith('/api/users/'))
              and r.endpoint.__module__ == 'backend.routes.users']
    assert len(routes) == len(OPERATIONS)
    assert {(method, r.path) for r in routes for method in r.methods} == OPERATIONS
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.users'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods != {'GET'}:
            expected.add(main.verify_authenticated_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected
    read = next(r for r in routes if r.path == '/api/users' and r.methods == {'GET'})
    assert read.response_model == list[main.UserResponse] or read.response_model == main.List[main.UserResponse]

    invitation_routes = {(method, route.path) for route in main.app.routes
                         if isinstance(route, APIRoute)
                         and route.endpoint.__module__ == 'backend.routes.invitations'
                         for method in route.methods}
    assert invitation_routes == {
        ('POST', '/api/users/invitations'), ('GET', '/api/users/invitations'),
        ('DELETE', '/api/users/invitations/{invitation_id}'),
        ('POST', '/api/users/invitations/{invitation_id}/resend'),
        ('POST', '/api/invitations/accept'),
    }


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


@pytest.mark.parametrize('actor', ['admin', 'owner', 'manager', 'engineer'])
@pytest.mark.parametrize('include_archived', [False, True])
def test_users_list_preserves_archive_visibility_and_permissions(tenant_api, actor, include_archived):
    client = tenant_api.as_actor(actor)
    db = tenant_api.db
    db.execute("""INSERT INTO users(id,email,name,password_hash,archived_at) OVERRIDING SYSTEM VALUE
                  VALUES(50,'archived@example.test','Archived','unused','2000-01-01T00:00:00Z')""")
    db.execute("INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,50,'engineer')",
               (tenant_api.org_a,))
    db.commit()
    response = client.get('/api/users', params={'include_archived': include_archived})
    if actor in ('manager', 'engineer'):
        assert response.status_code == 403, response.text
        return
    assert response.status_code == 200, response.text
    ids = {row['id'] for row in response.json()}
    assert (50 in ids) == include_archived
    assert 5 not in ids and 6 not in ids  # other company's owner and the platform admin
    assert all('password_hash' not in row for row in response.json())


def test_users_cannot_be_created_directly_in_a_company(tenant_api):
    """Company accounts are created by invitation; the legacy password form is refused."""
    before = database_state(tenant_api.db)
    response = tenant_api.client.post('/api/users', json={
        'email': 'new@example.test', 'name': 'New', 'password': 'test-password', 'role': 'engineer',
    })
    assert response.status_code == 410, response.text
    assert response.json() == {'detail': 'Create users with an invitation instead'}
    assert database_state(tenant_api.db) == before


def test_users_update_audit_failure_rolls_back(tenant_api, monkeypatch):
    client = tenant_api.client
    def failed_audit(conn, *args, **kwargs):
        assert conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
        raise RuntimeError('audit unavailable')
    monkeypatch.setattr(main, '_record_mutation_activity', failed_audit)
    before = database_state(tenant_api.db)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        client.put('/api/users/4', json={'name': 'Changed'})
    assert database_state(tenant_api.db) == before


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
