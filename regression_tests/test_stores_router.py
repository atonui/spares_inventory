"""Store administration HTTP contracts and collaborator ownership."""
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
    ('GET', '/api/stores'), ('GET', '/api/store-options'), ('POST', '/api/stores'),
    ('POST', '/api/stores/bulk-import'), ('PUT', '/api/stores/{store_id}'),
    ('DELETE', '/api/stores/{store_id}'), ('POST', '/api/stores/{store_id}/restore'),
    ('GET', '/api/store-types'), ('POST', '/api/store-types'),
    ('PUT', '/api/store-types/{type_id}'), ('DELETE', '/api/store-types/{type_id}'),
    ('GET', '/api/store-types/validate/{type_code}'),
}


def test_other_company_stores_look_exactly_like_missing_stores(tenant_api):
    client = tenant_api.as_actor('admin')
    for method, body in (('put', {'name': 'Taken'}), ('delete', None)):
        other = getattr(client, method)('/api/stores/101', **({'json': body} if body else {}))
        missing = getattr(client, method)('/api/stores/99999', **({'json': body} if body else {}))
        assert other.status_code == missing.status_code != 200
        assert other.json() == missing.json()
    assert tenant_api.db.execute('SELECT name, archived_at FROM stores WHERE id=101').fetchone() == {
        'name': 'Other warehouse', 'archived_at': None}


def test_stores_registered_once_with_original_dependencies():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path == '/api/stores' or r.path == '/api/store-options' or r.path.startswith('/api/stores/')
                   or r.path.startswith('/api/store-types'))]
    assert len(routes) == 12
    assert {(m, r.path) for r in routes for m in r.methods} == OPERATIONS
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.stores'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods != {'GET'}:
            expected.add(main.verify_authenticated_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected


def test_store_schema_reexports():
    from backend.schemas import stores
    for name in ('StoreResponse', 'StoreOptionResponse', 'StoreTypeResponse', 'CreateStoreRequest',
                 'UpdateStoreRequest', 'CreateStoreTypeRequest', 'UpdateStoreTypeRequest'):
        assert getattr(main, name) is getattr(stores, name)
    assert stores.UpdateStoreRequest().model_dump() == {
        'name': None, 'type': None, 'location': None, 'assigned_user_id': None,
    }


@pytest.mark.parametrize('actor', ['admin', 'owner', 'engineer'])
@pytest.mark.parametrize('include_archived', [False, True])
def test_store_listing_archive_visibility(tenant_api, actor, include_archived):
    client = tenant_api.as_actor(actor)
    tenant_api.db.execute("UPDATE stores SET archived_at='2000-01-01T00:00:00Z' WHERE id=3")
    tenant_api.db.commit()
    response = client.get('/api/stores', params={'include_archived': include_archived})
    if include_archived and actor == 'engineer':
        assert response.status_code == 403, response.text
        return
    assert response.status_code == 200, response.text
    assert (3 in {r['id'] for r in response.json()}) == include_archived


def test_store_picker_options_return_only_id_and_name(tenant_api):
    client = tenant_api.as_actor('engineer')
    response = client.get('/api/store-options')
    assert response.status_code == 200, response.text
    options = response.json()
    assert options
    assert all(set(option) == {'id', 'name'} for option in options)
    assert all(option['name'] for option in options)
    assert {option['id'] for option in options} == {1, 2, 3}


def test_store_types_listing_and_validation_keep_inactive_access(tenant_api):
    client = tenant_api.as_actor('engineer')
    tenant_api.db.execute(
        "INSERT INTO store_types(organization_id,type_code,type_name,is_active,display_order) VALUES(%s,'inactive_type','Inactive',FALSE,99)",
        (tenant_api.org_a,))
    tenant_api.db.commit()
    active = client.get('/api/store-types')
    assert active.status_code == 200
    assert 'inactive_type' not in {r['type_code'] for r in active.json()}
    all_types = client.get('/api/store-types', params={'include_inactive': True})
    assert 'inactive_type' in {r['type_code'] for r in all_types.json()}
    response = client.get('/api/store-types/validate/inactive_type')
    assert response.json() == {'valid': True, 'is_active': False, 'type_name': 'Inactive'}
    assert client.get('/api/store-types/validate/missing_type').status_code == 404


def test_store_import_preserves_existing_type_and_row_skipping_rules(tenant_api):
    client = tenant_api.client
    tenant_api.db.execute("INSERT INTO store_types(organization_id,type_code,type_name) VALUES(%s,'custom_type','Custom')",
                          (tenant_api.org_a,))
    tenant_api.db.execute("UPDATE users SET archived_at='2000-01-01T00:00:00Z' WHERE id=3")
    tenant_api.db.commit()
    data = ('name,type,location,assigned_user_id\n'
            'Accepted,office,Office,\n'
            'Custom,custom_type,Office,\n'
            'Malformed,office,Office,invalid\n'
            'Archived owner,office,Office,3\n')
    response = client.post('/api/stores/bulk-import', files={'file': ('stores.csv', data.encode(), 'text/csv')})
    assert response.status_code == 200, response.text
    assert response.json() == {'success': True, 'added': 1, 'skipped': 3}
    db = tenant_api.db
    assert db.execute("SELECT organization_id FROM stores WHERE name='Accepted'").fetchall() == [{'organization_id': tenant_api.org_a}]
    assert db.execute("SELECT COUNT(*) AS n FROM activity_logs WHERE action='bulk_import_stores'").fetchone()['n'] == 1


@pytest.mark.parametrize('in_use', [False, True])
def test_store_type_delete_preserves_deactivate_or_delete(tenant_api, in_use):
    client = tenant_api.client
    created = client.post('/api/store-types', json={'type_code': 'new_type', 'type_name': 'New'})
    assert created.status_code == 200, created.text
    type_id = created.json()['id']
    if in_use:
        store = client.post('/api/stores', json={'name': 'Uses type', 'type': 'new_type'})
        assert store.status_code == 200, store.text
    response = client.delete(f'/api/store-types/{type_id}')
    assert response.status_code == 200, response.text
    assert response.json()['deactivated'] is in_use
    row = tenant_api.db.execute('SELECT is_active FROM store_types WHERE id=%s', (type_id,)).fetchone()
    assert (row is not None and row['is_active'] is False) if in_use else row is None


@pytest.mark.parametrize('payload', [
    {'type_code': 'UpperCase', 'type_name': 'Invalid'},
    {'type_code': 'new_type', 'type_name': 'New', 'display_order': -1},
])
def test_store_type_schema_validation_preserved(tenant_api, payload):
    before = database_state(tenant_api.db)
    assert tenant_api.client.post('/api/store-types', json=payload).status_code == 422
    assert database_state(tenant_api.db) == before


def test_store_guards_and_audit_borrow_owner_and_rollback(tenant_api, monkeypatch):
    client = tenant_api.client
    admin = main.check_admin
    active = main.require_active_record
    audit = main._record_mutation_activity
    owners = []
    def in_transaction(conn):
        return conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
    def guard(user_id, conn=None):
        assert conn is not None and in_transaction(conn)
        owners.append(conn)
        return admin(user_id, conn)
    def active_guard(conn, *args, **kwargs):
        assert in_transaction(conn)
        return active(conn, *args, **kwargs)
    def activity(conn, *args, **kwargs):
        assert conn is owners[-1] and in_transaction(conn)
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'check_admin', guard)
    monkeypatch.setattr(main, 'require_active_record', active_guard)
    monkeypatch.setattr(main, '_record_mutation_activity', activity)
    response = client.post('/api/stores', json={'name': 'New', 'type': 'office', 'assigned_user_id': 3})
    assert response.status_code == 200, response.text
    fail_inserts(tenant_api.db, 'activity_logs', 'audit unavailable')
    before = database_state(tenant_api.db)
    with pytest.raises(psycopg.errors.RaiseException, match='audit unavailable'):
        client.put('/api/stores/2', json={'name': 'Changed'})
    assert database_state(tenant_api.db) == before


def test_store_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.stores, backend.schemas.stores; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr
