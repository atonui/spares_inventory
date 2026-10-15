"""Equipment writes and history records follow the authenticated company."""

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


def test_equipment_create_and_history_use_session_company(postgres_schema, migrated_tenant_schema):
    from backend.routes.equipment import create_equipment_router
    from backend.schemas.equipment import CreateEquipmentRequest
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.stock_access import require_active_record
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    organization_a, user_id, token = seed_user(connection, role="owner")
    organization_b = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Tenant B', 'equipment-tenant-b') RETURNING id"
    ).fetchone()["id"]
    role = "equipment_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, organization_memberships, platform_admins, equipment TO {}"
    ).format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT INSERT ON equipment, equipment_history TO {}").format(
        sql.Identifier(role)
    ))
    connection.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE equipment_id_seq, equipment_history_id_seq TO {}").format(
        sql.Identifier(role)
    ))
    connection.commit()

    def scoped_connection():
        scoped = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        scoped.commit()
        return scoped

    router = create_equipment_router(
        get_connection=scoped_connection,
        authenticated_writer=lambda principal, session, **kwargs: authenticated_write_transaction(
            scoped_connection, user_id=principal, session_token=session, **kwargs
        ),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
        admin_guard=lambda *_args, **_kwargs: True,
        active_record_guard=require_active_record,
        endpoint_log=lambda *_args, **_kwargs: lambda endpoint: endpoint,
        mutation_activity=lambda *_args, **_kwargs: None,
    )
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/equipment" and "POST" in route.methods)
    request = type("RequestStub", (), {"cookies": {"session_token": token}})()
    try:
        result = asyncio.run(endpoint(
            request_data=CreateEquipmentRequest(
                equipment_name="Pressure gauge", make="Acme", model="PG-1",
                serial_number="SERIAL-A",
            ),
            user_id=user_id,
            csrf_valid=True,
            request=request,
        ))
        equipment_id = result["id"]
        equipment = connection.execute(
            "SELECT organization_id FROM equipment WHERE id=%s", (equipment_id,)
        ).fetchone()
        history = connection.execute(
            "SELECT organization_id,created_by FROM equipment_history WHERE equipment_id=%s",
            (equipment_id,),
        ).fetchone()
        assert equipment["organization_id"] == organization_a
        assert history["organization_id"] == organization_a
        assert history["created_by"] == user_id
        assert connection.execute(
            "SELECT count(*) AS count FROM equipment WHERE organization_id=%s", (organization_b,)
        ).fetchone()["count"] == 0
    finally:
        connection.rollback()
        connection.execute("RESET ROLE")
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        connection.commit()
