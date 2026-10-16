"""PostgreSQL tenant-isolation tests for the versioned inventory API."""

import psycopg
import pytest
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def v1_postgres_api(postgres_schema, monkeypatch):
    import os
    from uuid import uuid4

    import main
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now
    from datetime import timedelta
    from fastapi.testclient import TestClient

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)

    def create_member(label, role="engineer", platform_admin=False):
        organization_id = connection.execute(
            "INSERT INTO organizations(name,slug) VALUES (%s,%s) RETURNING id",
            (label, f"{label.lower()}-{uuid4().hex}"),
        ).fetchone()["id"]
        user_id = connection.execute(
            "INSERT INTO users(email,name,password_hash) VALUES (%s,%s,'unused') RETURNING id",
            (f"{label.lower()}-{uuid4().hex}@example.test", label),
        ).fetchone()["id"]
        if role is not None:
            connection.execute(
                "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
                (organization_id, user_id, role),
            )
        if platform_admin:
            connection.execute(
                "INSERT INTO platform_admins(user_id) VALUES (%s)", (user_id,)
            )
        token = f"api-v1-{label.lower().replace(' ', '-')}-{uuid4().hex}"
        connection.execute(
            "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
            (
                user_id,
                hash_session_credential(token),
                serialize_instant(utc_now() + timedelta(hours=1)),
            ),
        )
        return organization_id, user_id, token

    org_a, user_a, token_a = create_member("Tenant A")
    org_b, user_b, token_b = create_member("Tenant B")
    _org_admin, user_platform, token_platform = create_member(
        "Platform Only", role=None, platform_admin=True
    )

    for organization_id, number, store_name in (
        (org_a, "AAA-1", "A Store"),
        (org_a, "AAA-2", "A Store"),
        (org_b, "BBB-1", "B Store"),
    ):
        part_id = connection.execute(
            "INSERT INTO parts(organization_id,part_number,description) VALUES (%s,%s,%s) RETURNING id",
            (organization_id, number, f"Description {number}"),
        ).fetchone()["id"]
        store_id = connection.execute(
            "INSERT INTO stores(organization_id,name,type) VALUES (%s,%s,'warehouse') RETURNING id",
            (organization_id, store_name,)
        ).fetchone()["id"]
        connection.execute(
            "INSERT INTO inventory(organization_id,store_id,part_id,quantity,min_threshold) VALUES (%s,%s,%s,4,0)",
            (organization_id, store_id, part_id),
        )

    runtime_role = "api_v1_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    connection.execute(
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(schema), sql.Identifier(runtime_role)
        )
    )
    connection.execute(
        sql.SQL("GRANT SELECT ON users, sessions, organization_memberships, platform_admins, inventory, parts, stores, work_orders TO {}").format(
            sql.Identifier(runtime_role)
        )
    )
    connection.commit()

    def scoped_connection():
        scoped = psycopg.connect(
            os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row
        )
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        scoped.commit()
        return scoped

    monkeypatch.setattr(main, "get_db_connection", scoped_connection)

    def set_principal(user_id):
        main.app.dependency_overrides[main.get_current_user] = lambda: user_id

    def request_inventory(client, user_id, token, **params):
        set_principal(user_id)
        return client.get(
            "/api/v1/inventory",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )

    try:
        with TestClient(main.app) as client:
            yield {
                "client": client,
                "connection": connection,
                "org_a": org_a,
                "user_a": user_a,
                "token_a": token_a,
                "org_b": org_b,
                "user_b": user_b,
                "token_b": token_b,
                "user_platform": user_platform,
                "token_platform": token_platform,
                "request_inventory": request_inventory,
            }
    finally:
        main.app.dependency_overrides.clear()
        connection.rollback()
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
        connection.commit()


def test_v1_inventory_is_scoped_to_authenticated_company(v1_postgres_api):
    api = v1_postgres_api

    response = api["request_inventory"](
        api["client"], api["user_a"], api["token_a"], limit=100
    )

    assert response.status_code == 200, response.text
    assert [row["part_number"] for row in response.json()["items"]] == ["AAA-1", "AAA-2"]


def test_v1_cursor_replay_cannot_cross_company_scope(v1_postgres_api):
    api = v1_postgres_api
    first = api["request_inventory"](
        api["client"], api["user_a"], api["token_a"], limit=1
    )
    assert first.status_code == 200, first.text
    cursor = first.json()["page"]["next_cursor"]
    assert cursor

    replay = api["request_inventory"](
        api["client"], api["user_b"], api["token_b"], limit=10, cursor=cursor
    )

    assert replay.status_code == 200, replay.text
    # The cursor's row ID is absent in tenant B's RLS view.
    assert replay.json()["items"] == []


def test_v1_client_tenant_hints_do_not_expand_scope(v1_postgres_api):
    api = v1_postgres_api
    api["client"].headers["X-Tenant-ID"] = str(api["org_b"])
    response = api["request_inventory"](
        api["client"], api["user_a"], api["token_a"], limit=100,
        tenant_id=str(api["org_b"]),
    )

    assert response.status_code == 200, response.text
    assert [row["part_number"] for row in response.json()["items"]] == ["AAA-1", "AAA-2"]


def test_v1_platform_admin_without_membership_cannot_read_inventory(v1_postgres_api):
    api = v1_postgres_api

    response = api["request_inventory"](
        api["client"], api["user_platform"], api["token_platform"]
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_v1_errors_redact_internal_details(v1_postgres_api):
    api = v1_postgres_api
    response = api["request_inventory"](
        api["client"], api["user_a"], api["token_a"], cursor="internal-secret-invalid"
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert "internal-secret" not in response.text
    assert response.headers["x-request-id"] == response.json()["error"]["request_id"]
