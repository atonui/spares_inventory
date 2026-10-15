"""PostgreSQL RLS must isolate rows on a reused, restricted connection."""

from uuid import uuid4

import pytest
from psycopg import errors
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def runtime_role(postgres_schema):
    connection, schema = postgres_schema
    role = "tenant_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL("GRANT SELECT, INSERT ON stores TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, organization_memberships, platform_admins TO {}"
    ).format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE stores_id_seq TO {}").format(
        sql.Identifier(role)
    ))
    connection.commit()
    try:
        yield role
    finally:
        connection.rollback()
        connection.execute("RESET ROLE")
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        connection.commit()


def seed_stores(connection):
    organizations = [
        connection.execute(
            "INSERT INTO organizations(name, slug) VALUES (%s, %s) RETURNING id",
            (name, name.lower()),
        ).fetchone()["id"]
        for name in ("Tenant A", "Tenant B")
    ]
    stores = []
    for organization_id, name in zip(organizations, ("A Warehouse", "B Warehouse")):
        store_id = connection.execute(
            """INSERT INTO stores(organization_id, name, type)
               VALUES (%s, %s, 'warehouse') RETURNING id""",
            (organization_id, name),
        ).fetchone()["id"]
        stores.append((organization_id, store_id))
    connection.commit()
    return organizations, stores


def test_missing_context_denies_tenant_reads_and_writes(postgres_schema, runtime_role):
    connection, _ = postgres_schema
    _, stores = seed_stores(connection)
    connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
    connection.commit()

    with connection.transaction():
        assert connection.execute("SELECT count(*) AS count FROM stores").fetchone()["count"] == 0
    with pytest.raises(errors.InsufficientPrivilege):
        with connection.transaction():
            connection.execute(
                "INSERT INTO stores(organization_id, name, type) VALUES (%s, 'No context', 'warehouse')",
                (stores[0][0],),
            )


def test_context_scopes_reads_and_transaction_end_clears_it(postgres_schema, runtime_role):
    from backend.services.tenant_context import set_tenant_context

    connection, _ = postgres_schema
    organizations, _ = seed_stores(connection)
    connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
    connection.commit()

    with pytest.raises(RuntimeError):
        with connection.transaction():
            set_tenant_context(connection, organizations[0])
            assert connection.execute("SELECT count(*) AS count FROM stores").fetchone()["count"] == 1
            raise RuntimeError("roll back organization A")

    with connection.transaction():
        assert connection.execute("SELECT count(*) AS count FROM stores").fetchone()["count"] == 0
        set_tenant_context(connection, organizations[1])
        rows = connection.execute("SELECT name FROM stores").fetchall()
        assert rows == [{"name": "B Warehouse"}]


def test_context_cannot_write_another_organizations_rows(postgres_schema, runtime_role):
    from backend.services.tenant_context import set_tenant_context

    connection, _ = postgres_schema
    organizations, _ = seed_stores(connection)
    connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
    connection.commit()

    with pytest.raises(errors.InsufficientPrivilege):
        with connection.transaction():
            set_tenant_context(connection, organizations[0])
            connection.execute(
                "INSERT INTO stores(organization_id, name, type) VALUES (%s, 'Spoofed', 'warehouse')",
                (organizations[1],),
            )


def test_authenticated_transaction_uses_membership_from_session(postgres_schema, runtime_role):
    from backend.services.tenant_context import authenticated_tenant_transaction
    from regression_tests.test_tenant_context import seed_user

    connection, _ = postgres_schema
    organizations, _ = seed_stores(connection)
    _org_id, user_id, token = seed_user(connection, role="engineer")
    connection.execute(
        "UPDATE organization_memberships SET organization_id = %s WHERE user_id = %s",
        (organizations[0], user_id),
    )
    connection.commit()
    schema = connection.execute("SELECT current_schema() AS name").fetchone()["name"]

    def scoped_connection():
        scoped = psycopg.connect(
            connection.info.dsn,
            row_factory=psycopg.rows.dict_row,
            connect_timeout=5,
        )
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        scoped.commit()
        return scoped

    with authenticated_tenant_transaction(
        scoped_connection,
        session_token=token,
    ) as (tenant_connection, principal):
        assert principal.organization_id == _org_id
        rows = tenant_connection.execute("SELECT name FROM stores ORDER BY name").fetchall()

    assert rows == [{"name": "A Warehouse"}]
