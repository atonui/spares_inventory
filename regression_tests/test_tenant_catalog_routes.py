"""Company boundaries for catalog and work-order reads."""

import asyncio
import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from fastapi import APIRouter

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.mark.parametrize("role, expected", [("owner", True), ("admin", True), ("manager", False), ("engineer", False)])
def test_company_admin_guard_uses_membership_role(role, expected):
    from uuid import uuid4

    from backend.services.authorization import check_admin
    from backend.services.principals import AuthenticatedPrincipal

    assert check_admin(AuthenticatedPrincipal(12, uuid4(), role, False)) is expected


def test_work_order_query_binds_principal_company_and_role():
    from uuid import uuid4

    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.work_orders import list_work_orders

    class Connection:
        query = None
        params = None

        def execute(self, query, params):
            self.query = query
            self.params = params
            return [{"id": 1, "work_order_number": "WO-1"}]

    organization_id = uuid4()
    connection = Connection()
    principal = AuthenticatedPrincipal(7, organization_id, "manager", False)

    rows = list_work_orders(connection, principal)

    assert rows == [{"id": 1, "work_order_number": "WO-1"}]
    assert "wo.organization_id = %s" in connection.query
    assert connection.params == [organization_id, 7]


def test_platform_only_principal_cannot_list_company_work_orders():
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.work_orders import list_work_orders
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as error:
        list_work_orders(object(), AuthenticatedPrincipal(7, None, None, True))

    assert error.value.status_code == 403


def test_database_placeholder_translation_keeps_question_marks_in_literals():
    from backend.database_sql import _postgres_placeholders

    statement = "SELECT '?' AS marker FROM stores WHERE id = ? AND note = \"?\""

    assert _postgres_placeholders(statement) == "SELECT '?' AS marker FROM stores WHERE id = %s AND note = \"?\""


def test_parts_route_sets_session_derived_tenant_context(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.parts import create_parts_router
    from backend.schemas.parts import CreatePartRequest
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.principals import AuthenticatedPrincipal
    from regression_tests.test_tenant_context import seed_user

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)
    organization_a, _user_id, token = seed_user(connection, role="owner")
    organization_b = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Tenant B', 'tenant-b') RETURNING id"
    ).fetchone()["id"]
    for organization_id, part_number in ((organization_a, "PART-1"), (organization_b, "PART-2")):
        connection.execute(
            "INSERT INTO parts(organization_id, part_number, description) VALUES (%s, %s, %s)",
            (organization_id, part_number, part_number),
        )

    role = "route_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role))
    )
    connection.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, organization_memberships, platform_admins TO {}"
    ).format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT SELECT, INSERT ON parts TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE parts_id_seq TO {}").format(sql.Identifier(role)))
    connection.commit()

    def scoped_connection():
        scoped = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        scoped.commit()
        return scoped

    router = create_parts_router(
        get_connection=scoped_connection,
        authenticated_writer=lambda principal, session: authenticated_write_transaction(
            scoped_connection,
            user_id=principal,
            session_token=session,
        ),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
        admin_guard=lambda *_args, **_kwargs: True,
        archive_admin_guard=lambda *_args, **_kwargs: None,
        archive_service=lambda *_args, **_kwargs: None,
        endpoint_log=lambda *_args, **_kwargs: lambda endpoint: endpoint,
        mutation_activity=lambda *_args, **_kwargs: None,
    )
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/parts")
    request = type("RequestStub", (), {"cookies": {"session_token": token}})()
    try:
        rows = asyncio.run(endpoint(include_archived=False, user_id=_user_id, request=request))
        assert [row["part_number"] for row in rows] == ["PART-1"]
        principal = AuthenticatedPrincipal(_user_id, organization_a, "owner", False)
        create_endpoint = next(
            route.endpoint
            for route in router.routes
            if route.path == "/api/parts" and "POST" in route.methods
        )
        created = asyncio.run(
            create_endpoint(
                request_data=CreatePartRequest(
                    part_number="PART-3", description="Created by tenant route",
                    category="test", unit_cost=1,
                ),
                user_id=principal,
                csrf_valid=True,
                request=request,
            )
        )
        assert created["success"] is True
        owner_rows = connection.execute(
            "SELECT part_number FROM parts WHERE organization_id = %s ORDER BY part_number",
            (organization_a,),
        ).fetchall()
        assert [row["part_number"] for row in owner_rows] == ["PART-1", "PART-3"]
    finally:
        connection.rollback()
        connection.execute("RESET ROLE")
        connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        connection.commit()


def _seed_company(connection, slug, engineer_email, work_order_number, assigned_engineer_id=None):
    organization_id = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES (%s, %s) RETURNING id",
        (slug.title(), slug),
    ).fetchone()["id"]
    engineer_id = connection.execute(
        "INSERT INTO users(email, name, password_hash) VALUES (%s, %s, 'unused') RETURNING id",
        (engineer_email, engineer_email),
    ).fetchone()["id"]
    connection.execute(
        """INSERT INTO organization_memberships(organization_id, user_id, company_role)
           VALUES (%s, %s, 'engineer')""",
        (organization_id, engineer_id),
    )
    connection.execute(
        """INSERT INTO work_orders(
               organization_id, work_order_number, assigned_engineer_id, created_at
           ) VALUES (%s, %s, %s, '2026-01-01T00:00:00.000000Z')""",
        (organization_id, work_order_number, assigned_engineer_id or engineer_id),
    )
    return organization_id, engineer_id


def test_work_order_list_is_scoped_even_when_local_numbers_overlap(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.work_orders import list_work_orders

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    organization_a, engineer_a = _seed_company(
        connection, "company-a", "a@example.test", "WO-1"
    )
    _organization_b, _engineer_b = _seed_company(
        connection, "company-b", "b@example.test", "WO-1"
    )
    connection.commit()
    principal = AuthenticatedPrincipal(engineer_a, organization_a, "manager", False)

    with connection.transaction():
        connection.execute(
            "SELECT set_config('app.organization_id', %s, true)", (str(organization_a),)
        )
        result = list_work_orders(connection, principal)

    assert [row["work_order_number"] for row in result] == ["WO-1"]
    assert result[0]["assigned_engineer_id"] == engineer_a


def test_part_natural_key_is_unique_per_company(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from psycopg.errors import UniqueViolation

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    organization_a = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Tenant A', 'part-tenant-a') RETURNING id"
    ).fetchone()["id"]
    organization_b = connection.execute(
        "INSERT INTO organizations(name, slug) VALUES ('Tenant B', 'part-tenant-b') RETURNING id"
    ).fetchone()["id"]
    for organization_id in (organization_a, organization_b):
        connection.execute(
            "INSERT INTO parts(organization_id, part_number, description) VALUES (%s, 'P-100', 'Part')",
            (organization_id,),
        )
    connection.commit()

    with pytest.raises(UniqueViolation):
        with connection.transaction():
            connection.execute(
                "INSERT INTO parts(organization_id, part_number, description) VALUES (%s, 'P-100', 'Duplicate')",
                (organization_a,),
            )


def test_engineer_only_sees_assigned_work_orders_within_company(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.work_orders import list_work_orders

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    organization_id, engineer_id = _seed_company(
        connection, "company-a", "engineer@example.test", "WO-1"
    )
    other_engineer_id = connection.execute(
        "INSERT INTO users(email, name, password_hash) VALUES ('other@example.test', 'Other', 'unused') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_memberships(organization_id, user_id, company_role) VALUES (%s, %s, 'engineer')",
        (organization_id, other_engineer_id),
    )
    connection.execute(
        """INSERT INTO work_orders(organization_id, work_order_number, assigned_engineer_id)
           VALUES (%s, 'WO-2', %s)""",
        (organization_id, other_engineer_id),
    )
    connection.commit()
    principal = AuthenticatedPrincipal(engineer_id, organization_id, "engineer", False)

    with connection.transaction():
        connection.execute(
            "SELECT set_config('app.organization_id', %s, true)", (str(organization_id),)
        )
        result = list_work_orders(connection, principal)

    assert [row["work_order_number"] for row in result] == ["WO-1"]
