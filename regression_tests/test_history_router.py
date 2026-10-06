"""History extraction and existing visibility, filtering and retention contracts."""
from contextlib import closing
import json
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

OPERATIONS = {('GET', '/api/movements'), ('GET', '/api/logs/test'),
              ('GET', '/api/logs/activity'), ('GET', '/api/logs/activity/stats'),
              ('DELETE', '/api/logs/activity/cleanup')}


def test_history_registration_and_dependencies():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and any(r.path == path for _, path in OPERATIONS)]
    assert {(m, r.path) for r in routes for m in r.methods} == OPERATIONS
    assert len(routes) == 5
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.history'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods == {'DELETE'}:
            expected.add(main.verify_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected


def test_history_schema_reexports():
    from backend.schemas import history
    for name in ('MovementResponse', 'ActivityLogResponse'):
        assert getattr(main, name) is getattr(history, name)


def populate(path):
    with closing(connect_database(path)) as conn, conn:
        conn.execute("INSERT INTO work_orders(id,work_order_number,description) VALUES(10,'HISTORY-WO','History')")
        conn.executemany("INSERT INTO movements(id,from_store_id,to_store_id,part_id,quantity,movement_type,work_order_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)", [
            (10, 1, 2, 1, 2, 'transfer', None, 1, '2025-01-02 23:59:59'),
            (11, 2, None, 2, 3, 'consume', 10, 3, '2025-01-03 12:00:00'),
            (12, 1, 2, 1, 4, 'transfer', None, 4, '2025-01-04 12:00:00')])
        conn.execute("INSERT INTO stock_transfers(movement_id,status,source_min_threshold,completed_by,completed_at) VALUES(12,'received',0,3,'2025-01-05')")
        conn.executemany("INSERT INTO activity_logs(id,user_id,username,action,status,created_at) VALUES(?,?,?,?,?,?)", [
            (10, 1, 'Admin', 'login', 'success', '2025-01-02 23:59:59'),
            (11, 3, 'Engineer', 'login', 'error', '2025-01-03 12:00:00'),
            (12, 3, 'Engineer', 'view_parts', 'success', '2025-01-04 12:00:00'),
            (13, 4, 'Manager', 'consume_stock', 'success', '2000-01-01')])


@pytest.mark.parametrize('actor', ['admin-token', 'root-token', 'engineer-token', 'manager-token'])
def test_movements_global_visibility_and_enrichment(session_api, actor):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    response = client.get('/api/movements')
    assert response.status_code == 200, response.text
    rows = response.json()
    assert [r['id'] for r in rows] == [12, 11, 10]
    assert rows[0]['transfer_status'] == 'received'
    assert rows[0]['completed_at'] == '2025-01-05'
    assert rows[0]['completed_by_name'] is not None
    assert rows[1]['work_order'] == 'HISTORY-WO'
    assert rows[1]['transfer_status'] is None
    assert rows[2]['transfer_status'] == 'completed'


@pytest.mark.parametrize('params,ids', [
    ({'start_date': '2025-01-03', 'end_date': '2025-01-03'}, [11]),
    ({'end_date': '2025-01-02'}, [10]),
    ({'movement_type': 'transfer', 'part_id': 1, 'store_id': 1}, [12, 10]),
    ({'store_id': 2, 'limit': 1}, [12]), ({'part_id': 2}, [11])])
def test_movement_filters(session_api, params, ids):
    client, path, _ = session_api
    populate(path)
    response = client.get('/api/movements', params=params)
    assert response.status_code == 200, response.text
    assert [r['id'] for r in response.json()] == ids


@pytest.mark.parametrize('actor,ids', [('admin-token', [12, 11, 10, 13]),
    ('root-token', [12, 11, 10, 13]), ('engineer-token', [12, 11]), ('manager-token', [13])])
def test_activity_visibility_and_diagnostic(session_api, actor, ids):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    response = client.get('/api/logs/activity')
    assert response.status_code == 200, response.text
    assert [r['id'] for r in response.json()] == ids
    diagnostic = client.get('/api/logs/test').json()
    assert diagnostic['status'] == 'ok'
    assert diagnostic['table_exists'] is True
    assert diagnostic['log_count'] == 4
    assert diagnostic['can_view_logs'] == (actor == 'admin-token')


@pytest.mark.parametrize('actor,params,ids', [
    ('admin-token', {'target_user_id': 3, 'action': 'login', 'status': 'error'}, [11]),
    ('root-token', {'target_user_id': 3, 'limit': 1}, [12]),
    ('engineer-token', {'target_user_id': 1}, [12, 11]),
    ('admin-token', {'start_date': '2025-01-02', 'end_date': '2025-01-02'}, [10])])
def test_activity_filters_and_target_scope(session_api, actor, params, ids):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    response = client.get('/api/logs/activity', params=params)
    assert response.status_code == 200, response.text
    assert [r['id'] for r in response.json()] == ids


@pytest.mark.parametrize('actor,status', [('admin-token', 200), ('root-token', 403),
                                       ('engineer-token', 403), ('manager-token', 403)])
def test_stats_and_cleanup_existing_admin_policy(session_api, actor, status):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    stats = client.get('/api/logs/activity/stats', params={'start_date': '2025-01-02', 'end_date': '2025-01-03'})
    assert stats.status_code == status, stats.text
    if status == 200:
        data = stats.json()
        assert data['total_activities'] == 2
        assert data['by_action'] == [{'action': 'login', 'count': 2}]
        assert data['error_rate'] == {'errors': 1, 'successes': 1}
        assert len(data['by_user']) == 2
        assert [r['username'] for r in data['recent_logins']] == ['Engineer', 'Admin']
    before = database_state(path)
    cleanup = client.delete('/api/logs/activity/cleanup', params={'days': 1})
    assert cleanup.status_code == status, cleanup.text
    if status == 403:
        assert database_state(path) == before
    else:
        assert cleanup.json() == {'success': True, 'deleted_count': 3, 'days': 1}
        with closing(connect_database(path)) as conn:
            rows = conn.execute('SELECT action,details FROM activity_logs ORDER BY id').fetchall()
        assert [r['action'] for r in rows] == ['consume_stock', 'cleanup_logs']
        assert json.loads(rows[1]['details']) == {'days': 1, 'deleted_count': 3}


def test_cleanup_audit_failure_rolls_back(session_api):
    client, path, _ = session_api
    populate(path)
    with closing(connect_database(path)) as conn, conn:
        conn.execute("CREATE TRIGGER fail_history_audit BEFORE INSERT ON activity_logs WHEN NEW.action='cleanup_logs' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before = database_state(path)
    with pytest.raises(sqlite3.IntegrityError):
        client.delete('/api/logs/activity/cleanup?days=1')
    assert database_state(path) == before


def test_history_current_database_path(session_api, monkeypatch, tmp_path):
    client, path, _ = session_api
    alternate = tmp_path / 'alternate.db'
    with closing(connect_database(path)) as source, closing(connect_database(alternate)) as target:
        source.backup(target)
    populate(alternate)
    monkeypatch.setattr(main, 'DATABASE', str(alternate))
    assert [r['id'] for r in client.get('/api/movements').json()] == [12, 11, 10]
    assert len(client.get('/api/logs/activity').json()) == 4
    assert client.delete('/api/logs/activity/cleanup?days=1').json()['deleted_count'] == 3
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0] == 0


def test_history_imports_are_inert(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root) + os.pathsep + os.environ.get('PYTHONPATH', ''))
    result = subprocess.run([sys.executable, '-c',
        "import sys; import backend.routes.history, backend.schemas.history; assert 'main' not in sys.modules"],
        cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []
