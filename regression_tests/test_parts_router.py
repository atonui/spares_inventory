"""Parts administration extraction contracts and real HTTP behavior."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import pytest
from fastapi.routing import APIRoute
import main
from backend.database import connect_database
from regression_tests.test_session_write_routes import session_api, database_state

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
            expected.add(main.verify_csrf)
        assert {d.call for d in r.dependant.dependencies} == expected


def test_parts_model_reexports():
    from backend.schemas import parts
    for name in ('PartResponse', 'CreatePartRequest', 'UpdatePartRequest'):
        assert getattr(main, name) is getattr(parts, name)
    assert parts.UpdatePartRequest().model_dump() == {
        'part_number': None, 'description': None, 'category': None, 'unit_cost': None,
    }


@pytest.mark.parametrize('actor', ['admin-token', 'root-token', 'engineer-token'])
@pytest.mark.parametrize('include_archived', [False, True])
def test_parts_listing_preserves_archive_permissions(session_api, actor, include_archived):
    client, path, _ = session_api
    client.cookies.set('session_token', actor)
    with closing(connect_database(path)) as conn, conn:
        conn.execute("UPDATE parts SET archived_at='2000-01-01' WHERE id=2")
    response = client.get('/api/parts', params={'include_archived': include_archived})
    if include_archived and actor == 'engineer-token':
        assert response.status_code == 403
    else:
        assert response.status_code == 200, response.text
        assert (2 in {r['id'] for r in response.json()}) == include_archived


@pytest.mark.parametrize('actor,create_status,update_status', [
    ('admin-token', 200, 200), ('root-token', 200, 403),
    ('manager-token', 403, 403), ('engineer-token', 403, 403),
])
def test_parts_preserves_existing_create_and_update_roles(session_api, actor, create_status, update_status):
    client, _, _ = session_api
    client.cookies.set('session_token', actor)
    created = client.post('/api/parts', json={
        'part_number': 'NEW', 'description': 'New', 'category': 'test', 'unit_cost': 1,
    })
    assert created.status_code == create_status, created.text
    updated = client.put('/api/parts/2', json={'description': 'Changed'})
    assert updated.status_code == update_status, updated.text


@pytest.mark.parametrize('encoding', ['utf-8', 'latin-1'])
def test_parts_import_preserves_decoding_duplicates_and_row_errors(session_api, encoding):
    client, path, _ = session_api
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
    with closing(connect_database(path)) as conn:
        row = conn.execute("SELECT description,unit_cost FROM parts WHERE part_number='NEW'").fetchone()
        assert tuple(row) == ('Café', 1.5)
        assert conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='bulk_import_parts'").fetchone()[0] == 1


def test_parts_guard_audit_owner_and_rollback(session_api, monkeypatch):
    client, path, _ = session_api
    guard = main.check_admin
    audit = main._record_mutation_activity
    owners = []
    def borrowed_guard(user_id, conn=None):
        assert conn is not None and conn.in_transaction
        owners.append(conn)
        return guard(user_id, conn)
    def borrowed_audit(conn, *args, **kwargs):
        assert conn is owners[-1] and conn.in_transaction
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'check_admin', borrowed_guard)
    monkeypatch.setattr(main, '_record_mutation_activity', borrowed_audit)
    assert client.post('/api/parts', json={
        'part_number': 'NEW', 'description': 'New', 'category': 'test', 'unit_cost': 1,
    }).status_code == 200
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_part_audit BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before = database_state(path)
    with pytest.raises(sqlite3.IntegrityError, match='audit unavailable'):
        client.post('/api/parts', json={
            'part_number': 'ROLLBACK', 'description': 'New', 'category': 'test', 'unit_cost': 1,
        })
    assert database_state(path) == before


def test_parts_archive_and_restore_keep_shared_service(session_api):
    client, path, _ = session_api
    assert client.delete('/api/parts/2').status_code == 200
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT archived_at FROM parts WHERE id=2').fetchone()[0] is not None
    assert client.post('/api/parts/2/restore').status_code == 200
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT archived_at FROM parts WHERE id=2').fetchone()[0] is None


def test_parts_router_uses_current_database_path(session_api, monkeypatch, tmp_path):
    client, path, _ = session_api
    target = tmp_path / 'parts-switched.db'
    with closing(connect_database(path)) as source, closing(connect_database(target)) as destination:
        source.backup(destination)
    with closing(connect_database(target)) as conn, conn:
        conn.execute("UPDATE parts SET description='Changed target' WHERE id=1")
    monkeypatch.setattr(main, 'DATABASE', str(target))
    response = client.get('/api/parts')
    assert response.status_code == 200, response.text
    assert next(r for r in response.json() if r['id'] == 1)['description'] == 'Changed target'
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT description FROM parts WHERE id=1').fetchone()[0] != 'Changed target'


def test_parts_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.parts, backend.schemas.parts; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr
