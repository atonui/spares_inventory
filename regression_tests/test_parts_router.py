"""Parts administration extraction contracts and real HTTP behavior."""
import os
from pathlib import Path
import subprocess
import sys
import psycopg
import pytest
from fastapi.routing import APIRoute
import main
from regression_tests.postgres_app import database_state, fail_inserts

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    ('GET', '/api/parts'), ('POST', '/api/parts'), ('POST', '/api/parts/bulk-import'),
    ('PUT', '/api/parts/{part_id}'), ('DELETE', '/api/parts/{part_id}'),
    ('POST', '/api/parts/{part_id}/restore'),
}


def test_parts_registration_and_dependency_identity():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path == '/api/parts' or r.path.startswith('/api/parts/'))]
    assert len(routes) == 6
    assert {(m, r.path) for r in routes for m in r.methods} == OPERATIONS
    for r in routes:
        assert r.endpoint.__module__ == 'backend.routes.parts'
        assert r.tags == []
        expected = {main.get_current_user}
        if r.methods != {'GET'}:
            expected.add(main.verify_authenticated_csrf)
        assert {d.call for d in r.dependant.dependencies} == expected


def test_parts_model_reexports():
    from backend.schemas import parts
    for name in ('PartResponse', 'CreatePartRequest', 'UpdatePartRequest'):
        assert getattr(main, name) is getattr(parts, name)
    assert parts.UpdatePartRequest().model_dump() == {
        'part_number': None, 'description': None, 'category': None, 'unit_cost': None,
    }


@pytest.mark.parametrize('actor', ['admin', 'owner', 'engineer'])
@pytest.mark.parametrize('include_archived', [False, True])
def test_parts_listing_preserves_archive_permissions(tenant_api, actor, include_archived):
    client = tenant_api.as_actor(actor)
    tenant_api.db.execute("UPDATE parts SET archived_at='2000-01-01T00:00:00Z' WHERE id=2")
    tenant_api.db.commit()
    response = client.get('/api/parts', params={'include_archived': include_archived})
    if include_archived and actor == 'engineer':
        assert response.status_code == 403
    else:
        assert response.status_code == 200, response.text
        ids = {r['id'] for r in response.json()}
        assert (2 in ids) == include_archived
        assert 101 not in ids


@pytest.mark.parametrize('actor,create_status,update_status', [
    ('admin', 200, 200), ('owner', 200, 200),
    ('manager', 403, 403), ('engineer', 403, 403),
])
def test_parts_preserves_existing_create_and_update_roles(tenant_api, actor, create_status, update_status):
    client = tenant_api.as_actor(actor)
    created = client.post('/api/parts', json={
        'part_number': 'NEW', 'description': 'New', 'category': 'test', 'unit_cost': 1,
    })
    assert created.status_code == create_status, created.text
    updated = client.put('/api/parts/2', json={'description': 'Changed'})
    assert updated.status_code == update_status, updated.text


@pytest.mark.parametrize('encoding', ['utf-8', 'latin-1'])
def test_parts_import_preserves_decoding_duplicates_and_row_errors(tenant_api, encoding):
    client = tenant_api.client
    data = ('part_number,description,category,unit_cost\n'
            'NEW,Café,test,1.5\nNEW,Duplicate,test,2\n'
            ',Missing number,test,1\nBAD,Bad cost,test,invalid\n')
    response = client.post('/api/parts/bulk-import', files={'file': ('parts.csv', data.encode(encoding), 'text/csv')})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['added'] == 1 and result['skipped'] == 3
    assert len(result['skipped_details']) == 3
    assert 'already exists' in result['skipped_details'][0]
    assert 'missing required fields' in result['skipped_details'][1]
    assert 'BAD' in result['skipped_details'][2]
    db = tenant_api.db
    row = db.execute("SELECT organization_id,description,unit_cost FROM parts WHERE part_number='NEW'").fetchone()
    assert (row['organization_id'], row['description'], float(row['unit_cost'])) == (tenant_api.org_a, 'Café', 1.5)
    assert db.execute("SELECT COUNT(*) AS n FROM activity_logs WHERE action='bulk_import_parts'").fetchone()['n'] == 1


def test_parts_guard_audit_owner_and_rollback(tenant_api, monkeypatch):
    client = tenant_api.client
    guard = main.check_admin
    audit = main._record_mutation_activity
    owners = []
    def in_transaction(conn):
        return conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
    def borrowed_guard(user_id, conn=None):
        assert conn is not None and in_transaction(conn)
        owners.append(conn)
        return guard(user_id, conn)
    def borrowed_audit(conn, *args, **kwargs):
        assert conn is owners[-1] and in_transaction(conn)
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'check_admin', borrowed_guard)
    monkeypatch.setattr(main, '_record_mutation_activity', borrowed_audit)
    assert client.post('/api/parts', json={
        'part_number': 'NEW', 'description': 'New', 'category': 'test', 'unit_cost': 1,
    }).status_code == 200
    fail_inserts(tenant_api.db, 'activity_logs', 'audit unavailable')
    before = database_state(tenant_api.db)
    with pytest.raises(psycopg.errors.RaiseException, match='audit unavailable'):
        client.post('/api/parts', json={
            'part_number': 'ROLLBACK', 'description': 'New', 'category': 'test', 'unit_cost': 1,
        })
    assert database_state(tenant_api.db) == before


def test_parts_archive_and_restore_keep_shared_service(tenant_api):
    client = tenant_api.client
    archived_at = lambda: tenant_api.db.execute('SELECT archived_at FROM parts WHERE id=2').fetchone()['archived_at']
    assert client.delete('/api/parts/2').status_code == 200
    assert archived_at() is not None
    tenant_api.db.commit()
    assert client.post('/api/parts/2/restore').status_code == 200
    assert archived_at() is None


def test_other_company_parts_look_exactly_like_missing_parts(tenant_api):
    client = tenant_api.as_actor('admin')
    for call in (lambda pid: client.put(f'/api/parts/{pid}', json={'description': 'Taken'}),
                 lambda pid: client.delete(f'/api/parts/{pid}')):
        other, missing = call(101), call(99999)
        assert other.status_code == missing.status_code != 200
        assert other.json() == missing.json()
    assert tenant_api.db.execute('SELECT description, archived_at FROM parts WHERE id=101').fetchone() == {
        'description': 'Other company part', 'archived_at': None}


def test_parts_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.parts, backend.schemas.parts; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('part_number', ['', 'X' * 101])
def test_part_number_length_is_validated_on_create_and_update(tenant_api, part_number):
    client = tenant_api.client
    before = database_state(tenant_api.db)
    assert client.post('/api/parts', json={
        'part_number': part_number, 'description': 'Too long', 'category': 'test', 'unit_cost': 1,
    }).status_code == 422
    assert client.put('/api/parts/2', json={'part_number': part_number}).status_code == 422
    assert database_state(tenant_api.db) == before


def test_part_number_of_exactly_100_characters_is_accepted(tenant_api):
    response = tenant_api.client.post('/api/parts', json={
        'part_number': 'P' * 100, 'description': 'Limit', 'category': 'test', 'unit_cost': 1,
    })
    assert response.status_code == 200, response.text


def test_part_import_skips_part_numbers_over_the_limit(tenant_api):
    data = 'part_number,description,category,unit_cost\nOK-1,Fine,test,1\n' + 'Y' * 101 + ',Too long,test,1\n'
    response = tenant_api.client.post('/api/parts/bulk-import', files={'file': ('parts.csv', data.encode(), 'text/csv')})
    assert response.status_code == 200, response.text
    result = response.json()
    assert (result['added'], result['skipped']) == (1, 1)
    assert 'longer than 100 characters' in result['skipped_details'][0]
    assert tenant_api.db.execute("SELECT count(*) AS n FROM parts WHERE part_number LIKE 'YYYY%%'").fetchone()['n'] == 0
