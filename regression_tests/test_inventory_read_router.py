"""Read route extraction, active inventory visibility and report wiring."""
from contextlib import closing
import os
from pathlib import Path
import subprocess
import sys
import pytest
from fastapi.routing import APIRoute
from fastapi import FastAPI
from fastapi.testclient import TestClient
import main
from backend.database import connect_database
from regression_tests.test_session_write_routes import session_api, database_state

READS = {'/api/inventory', '/api/stats', '/api/inventory/transfers'}
REPORTS = {'/api/reports/consumption', '/api/reports/consumption.csv'}


def test_read_router_registration():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute) and r.path in READS | REPORTS]
    assert len(routes) == 5
    for route in routes:
        assert route.methods == {'GET'}
        assert route.tags == []
        expected_module = 'backend.routes.inventory_reads' if route.path in READS else 'backend.routes.reports'
        assert route.endpoint.__module__ == expected_module
        assert main.get_current_user in {d.call for d in route.dependant.dependencies}
        assert main.verify_csrf not in {d.call for d in route.dependant.dependencies}


def test_read_schema_reexports():
    from backend.schemas import inventory_reads
    for name in ('InventoryResponse', 'StatsResponse'):
        assert getattr(main, name) is getattr(inventory_reads, name)
    assert inventory_reads.StatsResponse(total_parts=0, total_stores=0, low_stock=0, my_parts=0).in_transit_quantity == 0


def populate(path):
    with closing(connect_database(path)) as conn, conn:
        conn.execute("INSERT INTO work_orders(id,work_order_number) VALUES(10,'READ-WO')")
        conn.execute('UPDATE inventory SET quantity=0,min_threshold=2 WHERE id=1')
        conn.executemany('INSERT INTO inventory(id,store_id,part_id,quantity,min_threshold,work_order_id) VALUES(?,?,?,?,?,?)', [
            (10, 2, 1, 3, 4, None), (11, 2, 1, 1, 9, 10), (12, 3, 2, 0, 0, None)])
        conn.execute("INSERT INTO movements(id,from_store_id,to_store_id,part_id,quantity,movement_type,created_by,created_at) VALUES(10,2,1,1,4,'transfer',3,'2025-01-02'),(11,1,2,1,8,'transfer',1,'2025-01-01')")
        conn.execute("INSERT INTO stock_transfers(movement_id,status,source_min_threshold) VALUES(10,'in_transit',0),(11,'received',0)")


@pytest.mark.parametrize('actor,my_parts', [('admin-token', 0), ('root-token', 0),
                                        ('engineer-token', 1), ('manager-token', 0)])
def test_inventory_global_visibility_zero_and_allocated_rows(session_api, actor, my_parts):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    before = database_state(path)
    response = client.get('/api/inventory')
    assert response.status_code == 200, response.text
    rows = response.json()
    assert {r['id'] for r in rows} == {1, 10, 11, 12}
    assert [r['part_number'] for r in rows] == ['EMPTY', 'PART', 'PART', 'PART']
    assert next(r for r in rows if r['id'] == 1)['quantity'] == 0
    allocated = next(r for r in rows if r['id'] == 11)
    assert allocated['is_allocated'] is True and allocated['work_order'] == 'READ-WO'
    assert allocated['store_owner'] == 3
    assert client.get('/api/stats').json() == {
        'in_transit_quantity': 4, 'total_parts': 2, 'total_stores': 3, 'low_stock': 2, 'my_parts': my_parts}
    assert database_state(path) == before


def test_archived_inventory_excluded_from_listing_and_global_stats(session_api):
    client, path, _ = session_api
    populate(path)
    with closing(connect_database(path)) as conn, conn:
        conn.execute("UPDATE stores SET archived_at='2000-01-01' WHERE id=2")
        conn.execute("UPDATE parts SET archived_at='2000-01-01' WHERE id=2")
    client.cookies.set('session_token', 'engineer-token')
    assert [r['id'] for r in client.get('/api/inventory').json()] == [1]
    # Ownership count historically includes archived stock; preserve this extraction contract.
    assert client.get('/api/stats').json() == {
        'in_transit_quantity': 4, 'total_parts': 1, 'total_stores': 2, 'low_stock': 1, 'my_parts': 1}


@pytest.mark.parametrize('actor,receive,returned', [('admin-token', True, True),
    ('root-token', True, True), ('engineer-token', True, True), ('manager-token', True, False)])
def test_pending_transfers_global_listing_and_confirmation_flags(session_api, actor, receive, returned):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    response = client.get('/api/inventory/transfers')
    assert response.status_code == 200, response.text
    rows = response.json()
    assert len(rows) == 1 and rows[0]['id'] == 10
    assert rows[0]['quantity'] == 4 and rows[0]['status'] == 'in_transit'
    assert rows[0]['can_receive'] is receive and rows[0]['can_return'] is returned


@pytest.mark.parametrize('endpoint', sorted(READS | REPORTS))
def test_read_routes_require_real_session(session_api, endpoint):
    client, _, _ = session_api
    client.cookies.clear()
    assert client.get(endpoint).status_code == 401


def test_reads_and_reports_use_current_database_configuration(session_api, monkeypatch, tmp_path):
    client, path, _ = session_api
    alternate = tmp_path / 'alternate.db'
    with closing(connect_database(path)) as source, closing(connect_database(alternate)) as target:
        source.backup(target)
    populate(alternate)
    with closing(connect_database(alternate)) as conn, conn:
        conn.execute("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,work_order_id,created_by,created_at) VALUES(2,1,7,'consume',10,3,'2025-01-01')")
    monkeypatch.setattr(main, 'DATABASE', str(alternate))
    assert len(client.get('/api/inventory').json()) == 4
    assert client.get('/api/stats').json()['in_transit_quantity'] == 4
    assert len(client.get('/api/inventory/transfers').json()) == 1
    report = client.get('/api/reports/consumption').json()
    assert report['totals'] == {'events': 1, 'quantity': 7, 'parts': 1}
    assert report['rows'][0]['work_order'] == 'READ-WO'
    assert 'READ-WO' in client.get('/api/reports/consumption.csv').text


def test_read_module_imports_are_inert(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root) + os.pathsep + os.environ.get('PYTHONPATH', ''))
    result = subprocess.run([sys.executable, '-c',
        "import sys; import backend.routes.inventory_reads, backend.routes.reports, backend.schemas.inventory_reads, stock_reports; assert 'main' not in sys.modules"],
        cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []


def test_legacy_report_registration_keeps_filters_and_export(session_api):
    from stock_reports import register_stock_report_routes, local_timestamp, csv_cell
    _, path, _ = session_api
    populate(path)
    app = FastAPI()
    register_stock_report_routes(app, get_connection=lambda: connect_database(path),
        current_user=lambda: 1, require_active=main.require_active_record)
    with TestClient(app) as client:
        assert client.get('/api/reports/consumption').json()['totals'] == {'events': 0, 'quantity': 0, 'parts': 0}
        assert client.get('/api/reports/consumption?limit=0').status_code == 422
        response = client.get('/api/reports/consumption.csv')
        assert response.status_code == 200
        assert response.headers['cache-control'] == 'no-store'
        assert response.text.startswith('\ufeffMovement ID,Recorded time (Africa/Nairobi)')
    assert local_timestamp('2025-01-01 00:00:00') == '2025-01-01T03:00:00+03:00'
    assert csv_cell('=FORMULA') == "'=FORMULA"
