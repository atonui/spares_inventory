"""Every timestamp the PostgreSQL app writes uses the canonical UTC text format."""
import pytest

from regression_tests.test_auth_router import auth_api  # noqa: F401  (fixture)


def canonical(value):
    from backend.temporal import serialize_instant, parse_api_instant
    assert value == serialize_instant(parse_api_instant(value))


def test_every_column_default_uses_the_canonical_clock(tenant_api):
    db = tenant_api.db
    defaults = db.execute(
        """SELECT table_name, column_name, column_default FROM information_schema.columns
           WHERE table_schema = current_schema() AND column_default LIKE '%%to_char%%'"""
    ).fetchall()
    assert len(defaults) >= 30
    for row in defaults:
        canonical(db.execute('SELECT ' + row['column_default'] + ' AS stamp').fetchone()['stamp'])


def test_stock_receipt_writes_canonical_timestamps(tenant_api):
    response = tenant_api.client.post('/api/inventory/add', json={'store_id': 1, 'part_id': 1, 'quantity': 2})
    assert response.status_code == 200, response.text
    db = tenant_api.db
    canonical(db.execute('SELECT updated_at FROM inventory WHERE id=1').fetchone()['updated_at'])
    canonical(db.execute('SELECT created_at FROM movements ORDER BY id DESC LIMIT 1').fetchone()['created_at'])


@pytest.mark.parametrize('operation', ['minimum', 'count'])
def test_count_and_minimum_writers_use_canonical_clock(tenant_api, operation):
    client = tenant_api.client
    if operation == 'minimum':
        response = client.put('/api/inventory/minimum',
                              json={'store_id': 1, 'part_id': 1, 'min_threshold': 3, 'expected_minimum': 0})
    else:
        sheet = client.get('/api/inventory/count-sheet/1').json()
        preview = client.post('/api/inventory/count-preview', json={
            'sheet_token': sheet['sheet_token'],
            'rows': [{'inventory_id': 1, 'counted_quantity': 8, 'reason': 'Physical count'}]}).json()
        response = client.post('/api/inventory/count-confirm',
                               json={'preview_token': preview['preview_token'], 'confirmed': True})
    assert response.status_code == 200, response.text
    canonical(tenant_api.db.execute('SELECT updated_at FROM inventory WHERE id=1').fetchone()['updated_at'])


def test_login_writes_canonical_expiry_and_last_login(auth_api):
    client, db, _ = auth_api
    response = client.post('/api/auth/login', json={'email': 'admin@example.test', 'password': 'test-password'})
    assert response.status_code == 200
    canonical(db.execute('SELECT expires_at FROM sessions ORDER BY id DESC LIMIT 1').fetchone()[0])
    canonical(db.execute('SELECT last_login FROM users WHERE id=1').fetchone()[0])
