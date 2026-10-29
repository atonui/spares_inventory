"""Company timezone settings stay inside authenticated tenant scope."""

import asyncio
import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def migrated_tenant_schema(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    apply_postgres_migrations(postgres_schema[0])


def test_timezone_context_and_update_are_company_scoped(postgres_schema, migrated_tenant_schema):
    from backend.routes.timezone_settings import create_timezone_settings_router
    from backend.schemas.timezone_settings import BusinessTimezoneUpdate
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.principals import AuthenticatedPrincipal
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    organization_a, user_id, token = seed_user(connection, role="owner")
    organization_b = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Tenant B', 'timezone-tenant-b') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_settings(organization_id,business_timezone) VALUES (%s,'Europe/London')",
        (organization_a,),
    )
    connection.execute(
        "INSERT INTO organization_settings(organization_id,business_timezone) VALUES (%s,'Asia/Tokyo')",
        (organization_b,),
    )
    role = "timezone_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, organization_memberships, platform_admins, organizations TO {}"
    ).format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT SELECT, UPDATE ON organization_settings TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT INSERT ON activity_logs TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE activity_logs_id_seq TO {}").format(
        sql.Identifier(role)
    ))
    connection.commit()

    def scoped_connection():
        scoped = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        scoped.commit()
        return scoped

    router = create_timezone_settings_router(
        get_connection=scoped_connection,
        authenticated_writer=lambda principal, session: authenticated_write_transaction(
            scoped_connection, user_id=principal, session_token=session
        ),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
    )
    read = next(route.endpoint for route in router.routes if route.path == "/api/timezone-context")
    update = next(route.endpoint for route in router.routes if route.path == "/api/organisation/timezone")
    request = type("RequestStub", (), {
        "cookies": {"session_token": token},
        "client": None,
        "headers": {},
    })()
    try:
        initial = asyncio.run(read(user_id=user_id, request=request))
        assert initial["business_timezone"] == "Europe/London"
        changed = asyncio.run(update(
            body=BusinessTimezoneUpdate(timezone="America/New_York", expected_revision=1),
            request=request,
            user_id=AuthenticatedPrincipal(user_id, organization_a, "owner", False),
            csrf_valid=True,
        ))
        assert changed["business_timezone"] == "America/New_York"
        assert changed["revision"] == 2
        assert connection.execute(
            "SELECT business_timezone FROM organization_settings WHERE organization_id=%s",
            (organization_b,),
        ).fetchone()["business_timezone"] == "Asia/Tokyo"
        assert connection.execute(
            "SELECT count(*) AS count FROM activity_logs WHERE organization_id=%s AND action='update_business_timezone'",
            (organization_a,),
        ).fetchone()["count"] == 1
    finally:
        connection.rollback()
        connection.execute("RESET ROLE")
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        connection.commit()
