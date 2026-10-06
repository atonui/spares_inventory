"""Store administration HTTP contracts and collaborator ownership."""
from contextlib import closing
import os
import sqlite3
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.routing import APIRoute

import main
from backend.database import connect_database
from regression_tests.test_session_write_routes import session_api, database_state

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    ('GET', '/api/stores'), ('POST', '/api/stores'),
    ('POST', '/api/stores/bulk-import'), ('PUT', '/api/stores/{store_id}'),
    ('DELETE', '/api/stores/{store_id}'), ('POST', '/api/stores/{store_id}/restore'),
    ('GET', '/api/store-types'), ('POST', '/api/store-types'),
    ('PUT', '/api/store-types/{type_id}'), ('DELETE', '/api/store-types/{type_id}'),
    ('GET', '/api/store-types/validate/{type_code}'),
}


def test_stores_registered_once_with_original_dependencies():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path == '/api/stores' or r.path.startswith('/api/stores/')
                   or r.path.startswith('/api/store-types'))]
    assert len(routes) == 11
    assert {(m, r.path) for r in routes for m in r.methods} == OPERATIONS
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.stores'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods != {'GET'}:
            expected.add(main.verify_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected


def test_store_schema_reexports():
    from backend.schemas import stores
    for name in ('StoreResponse', 'StoreTypeResponse', 'CreateStoreRequest',
                 'UpdateStoreRequest', 'CreateStoreTypeRequest', 'UpdateStoreTypeRequest'):
        assert getattr(main, name) is getattr(stores, name)
    assert stores.UpdateStoreRequest().model_dump() == {
        'name': None, 'type': None, 'location': None, 'assigned_user_id': None,
    }


@pytest.mark.parametrize('actor', ['admin-token', 'root-token', 'engineer-token'])
@pytest.mark.parametrize('include_archived', [False, True])
def test_store_listing_archive_visibility(session_api, actor, include_archived):
    client, path, _ = session_api
    client.cookies.set('session_token', actor)
    with closing(connect_database(path)) as conn, conn:
        conn.execute("UPDATE stores SET archived_at='2000-01-01' WHERE id=3")
    response = client.get('/api/stores', params={'include_archived': include_archived})
    if include_archived and actor == 'engineer-token':
        assert response.status_code == 403, response.text
        return
    assert response.status_code == 200, response.text
    assert (3 in {r['id'] for r in response.json()}) == include_archived


def test_store_types_listing_and_validation_keep_inactive_access(session_api):
    client, path, _ = session_api
    client.cookies.set('session_token', 'engineer-token')
    with closing(connect_database(path)) as conn, conn:
        conn.execute("INSERT INTO store_types(type_code,type_name,is_active,display_order) VALUES('inactive_type','Inactive',0,99)")
    active = client.get('/api/store-types')
    assert active.status_code == 200
    assert 'inactive_type' not in {r['type_code'] for r in active.json()}
    all_types = client.get('/api/store-types', params={'include_inactive': True})
    assert 'inactive_type' in {r['type_code'] for r in all_types.json()}
    response = client.get('/api/store-types/validate/inactive_type')
    assert response.json() == {'valid': True, 'is_active': False, 'type_name': 'Inactive'}
    assert client.get('/api/store-types/validate/missing_type').status_code == 404


def test_store_import_preserves_existing_type_and_row_skipping_rules(session_api):
    client, path, _ = session_api
    with closing(connect_database(path)) as conn, conn:
        conn.execute("INSERT INTO store_types(type_code,type_name) VALUES('custom_type','Custom')")
        conn.execute("UPDATE users SET archived_at='2000-01-01' WHERE id=3")
    data = ('name,type,location,assigned_user_id\n'
            'Accepted,office,Office,\n'
            'Custom,custom_type,Office,\n'
            'Malformed,office,Office,invalid\n'
            'Archived owner,office,Office,3\n')
    response = client.post('/api/stores/bulk-import', files={'file': ('stores.csv', data.encode(), 'text/csv')})
    assert response.status_code == 200, response.text
    assert response.json() == {'success': True, 'added': 1, 'skipped': 3}
    with closing(connect_database(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM stores WHERE name='Accepted'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='bulk_import_stores'").fetchone()[0] == 1


@pytest.mark.parametrize('in_use', [False, True])
def test_store_type_delete_preserves_deactivate_or_delete(session_api, in_use):
    client, path, _ = session_api
    created = client.post('/api/store-types', json={'type_code': 'new_type', 'type_name': 'New'})
    assert created.status_code == 200, created.text
    type_id = created.json()['id']
    if in_use:
        store = client.post('/api/stores', json={'name': 'Uses type', 'type': 'new_type'})
        assert store.status_code == 200, store.text
    response = client.delete(f'/api/store-types/{type_id}')
    assert response.status_code == 200, response.text
    assert response.json()['deactivated'] is in_use
    with closing(connect_database(path)) as conn:
        row = conn.execute('SELECT is_active FROM store_types WHERE id=?', (type_id,)).fetchone()
        assert (row is not None and row[0] == 0) if in_use else row is None


@pytest.mark.parametrize('payload', [
    {'type_code': 'UpperCase', 'type_name': 'Invalid'},
    {'type_code': 'new_type', 'type_name': 'New', 'display_order': -1},
])
def test_store_type_schema_validation_preserved(session_api, payload):
    client, path, _ = session_api
    before = database_state(path)
    assert client.post('/api/store-types', json=payload).status_code == 422
    assert database_state(path) == before


def test_store_guards_and_audit_borrow_owner_and_rollback(session_api, monkeypatch):
    client, path, _ = session_api
    admin = main.check_admin
    active = main.require_active_record
    audit = main._record_mutation_activity
    owners = []
    def guard(user_id, conn=None):
        assert conn is not None and conn.in_transaction
        owners.append(conn)
        return admin(user_id, conn)
    def active_guard(conn, *args, **kwargs):
        assert conn.in_transaction
        return active(conn, *args, **kwargs)
    def activity(conn, *args, **kwargs):
        assert conn is owners[-1] and conn.in_transaction
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'check_admin', guard)
    monkeypatch.setattr(main, 'require_active_record', active_guard)
    monkeypatch.setattr(main, '_record_mutation_activity', activity)
    response = client.post('/api/stores', json={'name': 'New', 'type': 'office', 'assigned_user_id': 3})
    assert response.status_code == 200, response.text
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_store_audit BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before = database_state(path)
    with pytest.raises(sqlite3.IntegrityError, match='audit unavailable'):
        client.put('/api/stores/2', json={'name': 'Changed'})
    assert database_state(path) == before
    with closing(connect_database(path)) as conn:
        conn.execute('BEGIN IMMEDIATE')


def test_store_router_uses_current_database_path(session_api, monkeypatch, tmp_path):
    client, path, _ = session_api
    target = tmp_path / 'switched.db'
    with closing(connect_database(path)) as source, closing(connect_database(target)) as destination:
        source.backup(destination)
    with closing(connect_database(target)) as conn, conn:
        conn.execute("UPDATE stores SET name='Changed target' WHERE id=1")
    monkeypatch.setattr(main, 'DATABASE', str(target))
    response = client.get('/api/stores')
    assert response.status_code == 200, response.text
    assert next(r for r in response.json() if r['id'] == 1)['name'] == 'Changed target'
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT name FROM stores WHERE id=1').fetchone()[0] != 'Changed target'


def test_store_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.stores, backend.schemas.stores; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr
