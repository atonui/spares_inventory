"""Read route extraction, active inventory visibility and report wiring."""
import os
from pathlib import Path
import subprocess
import sys
import pytest
from fastapi.routing import APIRoute
import main
from regression_tests.postgres_app import database_state

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


def populate(api):
    with api.legacy_db as conn:
        conn.execute("INSERT INTO work_orders(id,work_order_number) VALUES(10,'READ-WO')")
        conn.execute('UPDATE inventory SET quantity=0,min_threshold=2 WHERE id=1')
        conn.executemany('INSERT INTO inventory(id,store_id,part_id,quantity,min_threshold,work_order_id) VALUES(?,?,?,?,?,?)', [
            (10, 2, 1, 3, 4, None), (11, 2, 1, 1, 9, 10), (12, 3, 2, 0, 0, None)])
        conn.execute("INSERT INTO movements(id,from_store_id,to_store_id,part_id,quantity,movement_type,created_by,created_at) VALUES(10,2,1,1,4,'transfer',3,'2025-01-02T00:00:00.000000Z'),(11,1,2,1,8,'transfer',1,'2025-01-01T00:00:00.000000Z')")
        conn.execute("INSERT INTO stock_transfers(movement_id,status,source_min_threshold) VALUES(10,'in_transit',0),(11,'received',0)")


@pytest.mark.parametrize('actor,my_parts', [('admin', 0), ('owner', 0),
                                        ('engineer', 1), ('manager', 0)])
def test_inventory_global_visibility_zero_and_allocated_rows(tenant_api, actor, my_parts):
    populate(tenant_api)
    client = tenant_api.as_actor(actor)
    before = database_state(tenant_api.db)
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
    assert database_state(tenant_api.db) == before


def test_archived_inventory_excluded_from_listing_and_global_stats(tenant_api):
    populate(tenant_api)
    with tenant_api.legacy_db as conn:
        conn.execute("UPDATE stores SET archived_at='2000-01-01T00:00:00.000000Z' WHERE id=2")
        conn.execute("UPDATE parts SET archived_at='2000-01-01T00:00:00.000000Z' WHERE id=2")
    client = tenant_api.as_actor('engineer')
    assert [r['id'] for r in client.get('/api/inventory').json()] == [1]
    # Ownership count historically includes archived stock; preserve this extraction contract.
    assert client.get('/api/stats').json() == {
        'in_transit_quantity': 4, 'total_parts': 1, 'total_stores': 2, 'low_stock': 1, 'my_parts': 1}


@pytest.mark.parametrize('actor,receive,returned', [('admin', True, True),
    ('owner', True, True), ('engineer', True, True), ('manager', True, False)])
def test_pending_transfers_global_listing_and_confirmation_flags(tenant_api, actor, receive, returned):
    populate(tenant_api)
    client = tenant_api.as_actor(actor)
    response = client.get('/api/inventory/transfers')
    assert response.status_code == 200, response.text
    rows = response.json()
    assert len(rows) == 1 and rows[0]['id'] == 10
    assert rows[0]['quantity'] == 4 and rows[0]['status'] == 'in_transit'
    assert rows[0]['can_receive'] is receive and rows[0]['can_return'] is returned


@pytest.mark.parametrize('endpoint', sorted(READS | REPORTS))
def test_read_routes_require_real_session(tenant_api, endpoint):
    client = tenant_api.client
    client.cookies.clear()
    assert client.get(endpoint).status_code == 401


def test_reads_never_include_another_companys_stock(tenant_api):
    populate(tenant_api)
    client = tenant_api.as_actor('admin')
    assert 101 not in {r['id'] for r in client.get('/api/inventory').json()}
    other = tenant_api.as_actor('other')
    assert {r['id'] for r in other.get('/api/inventory').json()} == {101}
    assert other.get('/api/inventory/transfers').json() == []
    assert other.get('/api/stats').json()['total_stores'] == 1


def test_read_module_imports_are_inert(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root) + os.pathsep + os.environ.get('PYTHONPATH', ''))
    result = subprocess.run([sys.executable, '-c',
        "import sys; import backend.routes.inventory_reads, backend.routes.reports, backend.schemas.inventory_reads, stock_reports; assert 'main' not in sys.modules"],
        cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []


def test_report_helpers_localise_time_and_neutralise_formulas():
    from stock_reports import local_timestamp, csv_cell
    assert local_timestamp('2025-01-01T00:00:00.000000Z') == '2025-01-01T03:00:00+03:00'
    assert csv_cell('=FORMULA') == "'=FORMULA"
