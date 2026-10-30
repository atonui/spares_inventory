"""Bounded native reads include empty stores and shared transfer permissions."""
from contextlib import closing

import pytest

from backend.database import connect_database
from regression_tests.test_api_v1_inventory import v1_inventory_client
from regression_tests.test_session_write_routes import session_api
from regression_tests.test_inventory_read_router import populate


def get(client, path, **params):
    return client.get(path, params=params, headers={'Authorization': 'Bearer admin-token'})


@pytest.mark.parametrize('path', ['/api/v1/stores', '/api/v1/inventory/transfers'])
def test_native_reads_reject_cookies_and_invalid_limits(v1_inventory_client, path):
    client, _ = v1_inventory_client
    client.cookies.set('session_token', 'admin-token')
    assert client.get(path).status_code == 401
    client.cookies.clear()
    assert get(client, path, limit=0).status_code == 422
    assert get(client, path, limit=101).status_code == 422
    assert get(client, path, cursor='tampered').status_code == 400


def test_empty_stores_and_keyset_pagination(v1_inventory_client):
    client, database_path = v1_inventory_client
    with closing(connect_database(database_path)) as conn, conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(20,'Empty destination','central')")
        conn.execute("INSERT INTO stores(id,name,type,archived_at) VALUES(21,'Archived','central','2025-01-01T00:00:00')")
    ids = []
    cursor = None
    while True:
        response = get(client, '/api/v1/stores', limit=1, **({'cursor': cursor} if cursor else {}))
        assert response.status_code == 200, response.text
        payload = response.json()
        ids.extend(item['id'] for item in payload['items'])
        cursor = payload['page']['next_cursor']
        if cursor is None:
            break
    assert 20 in ids and 21 not in ids
    assert ids == sorted(set(ids))


def test_pending_transfers_use_shared_permissions_and_utc(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    response = get(client, '/api/v1/inventory/transfers', limit=1)
    assert response.status_code == 200, response.text
    item = response.json()['items'][0]
    assert item['id'] == 10
    assert item['status'] == 'in_transit'
    assert item['can_receive'] is True
    assert item['can_return'] is True
    assert item['created_at'].endswith('Z')
    assert 'source_owner' not in item
    assert response.json()['page']['next_cursor'] is None


def test_store_cursor_cannot_be_used_for_transfers(v1_inventory_client):
    client, _ = v1_inventory_client
    page = get(client, '/api/v1/stores', limit=1).json()
    cursor = page['page']['next_cursor']
    assert cursor
    assert get(client, '/api/v1/inventory/transfers', cursor=cursor).status_code == 400


def test_transfer_pages_continue_after_previous_transfer_is_completed(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    with closing(connect_database(database_path)) as conn, conn:
        conn.execute("UPDATE stock_transfers SET status='in_transit' WHERE movement_id=11")
    first = get(client, '/api/v1/inventory/transfers', limit=1).json()
    assert [row['id'] for row in first['items']] == [10]
    with closing(connect_database(database_path)) as conn, conn:
        conn.execute("UPDATE stock_transfers SET status='received' WHERE movement_id=10")
    second = get(client, '/api/v1/inventory/transfers', limit=1, cursor=first['page']['next_cursor'])
    assert second.status_code == 200
    assert [row['id'] for row in second.json()['items']] == [11]
    assert second.json()['page']['next_cursor'] is None


def test_transfer_action_flags_follow_the_actor_assignment(v1_inventory_client):
    import main
    client, database_path = v1_inventory_client
    populate(database_path)
    main.app.dependency_overrides[main.get_current_user] = lambda: 4
    response = client.get('/api/v1/inventory/transfers', headers={'Authorization': 'Bearer manager-token'})
    assert response.status_code == 200, response.text
    item = response.json()['items'][0]
    # Manager 4 neither owns the source nor dispatched the movement.
    assert item['can_return'] is False
    # The destination is the unassigned central store, matching desktop policy.
    assert item['can_receive'] is True
