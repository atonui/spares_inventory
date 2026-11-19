"""History extraction and existing visibility, filtering and retention contracts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import psycopg
import pytest
from fastapi.routing import APIRoute
import main
from regression_tests.postgres_app import ORG_A, ORG_B, database_state

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
            expected.add(main.verify_authenticated_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected


def test_history_schema_reexports():
    from backend.schemas import history
    for name in ('MovementResponse', 'ActivityLogResponse'):
        assert getattr(main, name) is getattr(history, name)


def populate(db):
    db.execute("""INSERT INTO work_orders(id,organization_id,work_order_number,description)
                  OVERRIDING SYSTEM VALUE VALUES(10,%s,'HISTORY-WO','History')""", (ORG_A,))
    with db.cursor() as cur:
        cur.executemany("""INSERT INTO movements(id,organization_id,from_store_id,to_store_id,part_id,quantity,movement_type,work_order_id,created_by,created_at)
                           OVERRIDING SYSTEM VALUE VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", [
            (10, ORG_A, 1, 2, 1, 2, 'transfer', None, 1, '2025-01-02T23:59:59.000000Z'),
            (11, ORG_A, 2, None, 2, 3, 'consume', 10, 3, '2025-01-03T12:00:00.000000Z'),
            (12, ORG_A, 1, 2, 1, 4, 'transfer', None, 4, '2025-01-04T12:00:00.000000Z'),
            # Another company's movement must never appear.
            (110, ORG_B, 101, None, 101, 1, 'consume', None, 5, '2025-01-03T12:00:00.000000Z')])
        cur.execute("""INSERT INTO stock_transfers(organization_id,movement_id,status,source_min_threshold,completed_by,completed_at)
                       VALUES(%s,12,'received',0,3,'2025-01-05T00:00:00.000000Z')""", (ORG_A,))
        cur.executemany("""INSERT INTO activity_logs(id,organization_id,user_id,username,action,status,created_at)
                           OVERRIDING SYSTEM VALUE VALUES(%s,%s,%s,%s,%s,%s,%s)""", [
            (10, ORG_A, 1, 'Admin', 'login', 'success', '2025-01-02T23:59:59.000000Z'),
            (11, ORG_A, 3, 'Engineer', 'login', 'error', '2025-01-03T12:00:00.000000Z'),
            (12, ORG_A, 3, 'Engineer', 'view_parts', 'success', '2025-01-04T12:00:00.000000Z'),
            (13, ORG_A, 4, 'Manager', 'consume_stock', 'success', '2000-01-01T00:00:00.000000Z'),
            (110, ORG_B, 5, 'Other', 'login', 'success', '2025-01-03T12:00:00.000000Z')])
        for table in ('work_orders', 'movements', 'activity_logs'):
            cur.execute("SELECT setval(pg_get_serial_sequence(%s, 'id'), 1000)", (table,))
    db.commit()


@pytest.mark.parametrize('actor', ['admin', 'owner', 'engineer', 'manager'])
def test_movements_global_visibility_and_enrichment(tenant_api, actor):
    populate(tenant_api.db)
    client = tenant_api.as_actor(actor)
    response = client.get('/api/movements')
    assert response.status_code == 200, response.text
    rows = response.json()
    assert [r['id'] for r in rows] == [12, 11, 10]
    assert rows[0]['transfer_status'] == 'received'
    assert rows[0]['completed_at'] == '2025-01-05T00:00:00.000000Z'
    assert rows[0]['completed_by_name'] is not None
    assert rows[1]['work_order'] == 'HISTORY-WO'
    assert rows[1]['transfer_status'] is None
    assert rows[2]['transfer_status'] == 'completed'


@pytest.mark.parametrize('params,ids', [
    ({'start_date': '2025-01-03', 'end_date': '2025-01-03'}, [11,10]),
    ({'end_date': '2025-01-02'}, []),
    ({'movement_type': 'transfer', 'part_id': 1, 'store_id': 1}, [12, 10]),
    ({'store_id': 2, 'limit': 1}, [12]), ({'part_id': 2}, [11])])
def test_movement_filters(tenant_api, params, ids):
    client = tenant_api.client
    populate(tenant_api.db)
    response = client.get('/api/movements', params=params)
    assert response.status_code == 200, response.text
    assert [r['id'] for r in response.json()] == ids


@pytest.mark.parametrize('actor,ids', [('admin', [12, 11, 10, 13]),
    ('owner', [12, 11, 10, 13]), ('engineer', [12, 11]), ('manager', [13])])
def test_activity_visibility_and_diagnostic(tenant_api, actor, ids):
    populate(tenant_api.db)
    client = tenant_api.as_actor(actor)
    response = client.get('/api/logs/activity')
    assert response.status_code == 200, response.text
    assert [r['id'] for r in response.json()] == ids
    diagnostic = client.get('/api/logs/test').json()
    assert diagnostic['status'] == 'ok'
    assert diagnostic['table_exists'] is True
    assert diagnostic['log_count'] == 4
    assert diagnostic['can_view_logs'] == (actor in ('admin', 'owner'))
    assert diagnostic['current_user'] == {'name': actor.title(), 'role': actor}


@pytest.mark.parametrize('actor,params,ids', [
    ('admin', {'target_user_id': 3, 'action': 'login', 'status': 'error'}, [11]),
    ('owner', {'target_user_id': 3, 'limit': 1}, [12]),
    ('engineer', {'target_user_id': 1}, [12, 11]),
    ('admin', {'target_user_id': 5}, []),
    ('admin', {'start_date': '2025-01-02', 'end_date': '2025-01-02'}, [])])
def test_activity_filters_and_target_scope(tenant_api, actor, params, ids):
    populate(tenant_api.db)
    client = tenant_api.as_actor(actor)
    response = client.get('/api/logs/activity', params=params)
    assert response.status_code == 200, response.text
    assert [r['id'] for r in response.json()] == ids


@pytest.mark.parametrize('actor,status', [('admin', 200), ('owner', 200),
                                       ('engineer', 403), ('manager', 403)])
def test_stats_and_cleanup_existing_admin_policy(tenant_api, actor, status):
    db = tenant_api.db
    populate(db)
    client = tenant_api.as_actor(actor)
    stats = client.get('/api/logs/activity/stats', params={'start_date': '2025-01-02', 'end_date': '2025-01-03'})
    assert stats.status_code == status, stats.text
    if status == 200:
        data = stats.json()
        assert data['total_activities'] == 2
        assert data['by_action'] == [{'action': 'login', 'count': 2}]
        assert data['error_rate'] == {'errors': 1, 'successes': 1}
        assert len(data['by_user']) == 2
        assert [r['username'] for r in data['recent_logins']] == ['Engineer', 'Admin']
    before = database_state(db)
    cleanup = client.delete('/api/logs/activity/cleanup', params={'days': 1})
    assert cleanup.status_code == status, cleanup.text
    if status == 403:
        assert database_state(db) == before
    else:
        assert cleanup.json() == {'success': True, 'deleted_count': 3, 'days': 1}
        rows = db.execute('SELECT action,details FROM activity_logs WHERE organization_id=%s ORDER BY id', (ORG_A,)).fetchall()
        assert [r['action'] for r in rows] == ['consume_stock', 'cleanup_logs']
        # Cleanup never reaches another company's logs.
        assert db.execute('SELECT id FROM activity_logs WHERE organization_id=%s', (ORG_B,)).fetchall() == [{'id': 110}]
        assert json.loads(rows[1]['details']) == {'days': 1, 'deleted_count': 3}


def test_cleanup_audit_failure_rolls_back(tenant_api):
    from regression_tests.postgres_app import fail_inserts
    populate(tenant_api.db)
    fail_inserts(tenant_api.db, 'activity_logs', 'audit unavailable')
    before = database_state(tenant_api.db)
    with pytest.raises(psycopg.errors.RaiseException, match='audit unavailable'):
        tenant_api.client.delete('/api/logs/activity/cleanup?days=1')
    assert database_state(tenant_api.db) == before


def test_history_imports_are_inert(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root) + os.pathsep + os.environ.get('PYTHONPATH', ''))
    result = subprocess.run([sys.executable, '-c',
        "import sys; import backend.routes.history, backend.schemas.history; assert 'main' not in sys.modules"],
        cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('actor,params,expected_ids', [
    ('admin', {'action': 'login', 'start_date': '2025-01-03', 'end_date': '2025-01-03'}, [11, 10]),
    ('engineer', {'action': 'login'}, [11]),
])
def test_activity_history_executes_one_query(tenant_api, monkeypatch, actor, params, expected_ids):
    """One request must not scan and normalise the same history rows twice."""
    populate(tenant_api.db)
    client = tenant_api.as_actor(actor)
    statements = []
    original_connection = main.get_db_connection

    class TracingCursor(psycopg.Cursor):
        def execute(self, query, *args, **kwargs):
            statements.append(' '.join(str(query).split()))
            return super().execute(query, *args, **kwargs)

    def traced_connection():
        conn = original_connection()
        conn.cursor_factory = TracingCursor
        return conn

    monkeypatch.setattr(main, 'get_db_connection', traced_connection)
    response = client.get('/api/logs/activity', params=params)
    assert response.status_code == 200, response.text
    assert [row['id'] for row in response.json()] == expected_ids
    assert all(row['created_at'].endswith('Z') for row in response.json())
    assert json.loads(response.headers['X-Report-Time-Context'])['timezone'] == 'Africa/Nairobi'
    history_reads = [statement for statement in statements if 'FROM activity_logs' in statement]
    assert len(history_reads) == 1, history_reads
