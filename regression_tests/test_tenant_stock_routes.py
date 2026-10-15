"""Tenant boundaries for operational inventory reads."""

import asyncio
import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture(autouse=True)
def migrated_tenant_schema(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    apply_postgres_migrations(postgres_schema[0])


def test_inventory_read_route_only_returns_session_company_rows(postgres_schema):
    from backend.routes.inventory_reads import create_inventory_read_router
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    organization_a, user_id, token = seed_user(connection, role="engineer")
    organization_b = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Tenant B', 'stock-tenant-b') RETURNING id"
    ).fetchone()["id"]
    seeded = []
    for organization_id, suffix in ((organization_a, "A"), (organization_b, "B")):
        part_id = connection.execute(
            "INSERT INTO parts(organization_id, part_number, description) VALUES (%s, %s, %s) RETURNING id",
            (organization_id, f"PART-{suffix}", f"Part {suffix}"),
        ).fetchone()["id"]
        store_id = connection.execute(
            "INSERT INTO stores(organization_id, name, type) VALUES (%s, %s, 'warehouse') RETURNING id",
            (organization_id, f"Store {suffix}"),
        ).fetchone()["id"]
        connection.execute(
            "INSERT INTO inventory(organization_id, store_id, part_id, quantity) VALUES (%s, %s, %s, 4)",
            (organization_id, store_id, part_id),
        )
        seeded.append((part_id, store_id))

    role = "stock_read_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, organization_memberships, platform_admins, inventory, parts, stores, work_orders TO {}"
    ).format(sql.Identifier(role)))
    connection.commit()

    def scoped_connection():
        scoped = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        scoped.commit()
        return scoped

    router = create_inventory_read_router(
        get_connection=scoped_connection,
        current_user=lambda: None,
        transfer_permission=lambda *_args: (False, False),
    )
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/inventory")
    request = type("RequestStub", (), {"cookies": {"session_token": token}})()
    try:
        rows = asyncio.run(endpoint(user_id=user_id, request=request))
        assert [(row["part_number"], row["quantity"]) for row in rows] == [("PART-A", 4)]
    finally:
        connection.rollback()
        connection.execute("RESET ROLE")
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        connection.commit()
