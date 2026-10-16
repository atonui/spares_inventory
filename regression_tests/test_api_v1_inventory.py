"""Pagination contract tests for the versioned inventory API."""

from contextlib import closing
import random
import string

import pytest

from backend.database import connect_database
from regression_tests.test_inventory_read_router import populate
from regression_tests.test_session_write_routes import session_api


@pytest.fixture
def v1_inventory_client(session_api):
    import main

    client, database_path, _control = session_api
    previous = main.app.dependency_overrides[main.get_current_user]
    main.app.dependency_overrides[main.get_current_user] = lambda: 1
    client.cookies.clear()
    try:
        yield client, database_path
    finally:
        main.app.dependency_overrides[main.get_current_user] = previous


def get_page(client, **params):
    return client.get(
        "/api/v1/inventory",
        params=params,
        headers={"Authorization": "Bearer admin-token"},
    )


def test_v1_inventory_default_limit_and_response_envelope(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)

    response = get_page(client)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == {"items", "page"}
    assert payload["page"]["limit"] == 50
    assert len(payload["items"]) == 4
    assert payload["page"]["next_cursor"] is None


def test_v1_inventory_limit_bounds(v1_inventory_client):
    client, _ = v1_inventory_client

    maximum = get_page(client, limit=100)
    too_many = get_page(client, limit=101)
    zero = get_page(client, limit=0)

    assert maximum.status_code == 200
    assert maximum.json()["page"]["limit"] == 100
    assert too_many.status_code == 422
    assert too_many.json()["error"]["code"] == "validation_error"
    assert zero.status_code == 422
    assert zero.json()["error"]["code"] == "validation_error"


def test_v1_inventory_rejects_cookie_only_authentication(v1_inventory_client):
    client, _ = v1_inventory_client
    client.cookies.set("session_token", "admin-token")

    response = client.get("/api/v1/inventory")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_v1_inventory_empty_result_has_no_next_cursor(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    with closing(connect_database(database_path)) as conn, conn:
        conn.execute("UPDATE parts SET archived_at='2025-01-01T00:00:00Z'")

    response = get_page(client)

    assert response.status_code == 200, response.text
    assert response.json() == {
        "items": [],
        "page": {"limit": 50, "next_cursor": None},
    }


def test_v1_inventory_pages_are_stable_with_duplicate_sort_keys(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    collected = []
    cursor = None

    while True:
        page = get_page(client, limit=2, **({"cursor": cursor} if cursor else {}))
        assert page.status_code == 200, page.text
        payload = page.json()
        collected.extend(row["id"] for row in payload["items"])
        cursor = payload["page"]["next_cursor"]
        if cursor is None:
            break

    assert collected == [12, 10, 11, 1]
    assert len(collected) == len(set(collected))


def test_v1_inventory_includes_rows_inserted_after_current_key(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    first = get_page(client, limit=1)
    assert first.status_code == 200, first.text
    cursor = first.json()["page"]["next_cursor"]

    with closing(connect_database(database_path)) as conn, conn:
        conn.execute(
            "INSERT INTO inventory(id,store_id,part_id,quantity,min_threshold) VALUES(13,3,1,5,0)"
        )

    subsequent = get_page(client, limit=10, cursor=cursor)

    assert subsequent.status_code == 200, subsequent.text
    assert 13 in [row["id"] for row in subsequent.json()["items"]]


def test_v1_cursor_stays_usable_with_unbounded_sort_values(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    generator = random.Random(37)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    long_part_number = "".join(generator.choices(alphabet, k=3000))
    long_store_name = "".join(generator.choices(alphabet, k=3000))
    with closing(connect_database(database_path)) as conn, conn:
        conn.execute("UPDATE parts SET part_number=? WHERE id=2", (long_part_number,))
        conn.execute("UPDATE parts SET part_number=? WHERE id=1", ("Z" * 3000,))
        conn.execute("UPDATE stores SET name=? WHERE id=3", (long_store_name,))

    first = get_page(client, limit=1)
    assert first.status_code == 200, first.text
    cursor = first.json()["page"]["next_cursor"]
    assert cursor and len(cursor) <= 2048

    second = get_page(client, limit=1, cursor=cursor)

    assert second.status_code == 200, second.text
    assert second.json()["items"]


def test_inventory_cursor_round_trips_and_rejects_tampering():
    from backend.services.api_v1_pagination import (
        decode_inventory_cursor,
        encode_inventory_cursor,
    )

    cursor = encode_inventory_cursor("test-secret", 123)
    decoded = decode_inventory_cursor("test-secret", cursor)

    assert decoded.inventory_id == 123
    with pytest.raises(ValueError):
        decode_inventory_cursor("test-secret", cursor + "tampered")
    with pytest.raises(ValueError):
        decode_inventory_cursor("another-secret", cursor)


def test_legacy_inventory_remains_unpaginated_array(v1_inventory_client):
    client, database_path = v1_inventory_client
    populate(database_path)
    client.cookies.set("session_token", "admin-token")
    response = client.get("/api/inventory")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert {row["id"] for row in response.json()} == {1, 10, 11, 12}
