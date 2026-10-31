"""Cross-check company capability and platform status against tenant RLS."""

from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_company_roles_and_platform_status_remain_independent(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.authorization import (
        require_company_admin, require_platform_admin, require_superadmin,
    )
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.tenant_context import set_tenant_context

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    org_a = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('A','matrix-a') RETURNING id"
    ).fetchone()["id"]
    org_b = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('B','matrix-b') RETURNING id"
    ).fetchone()["id"]
    people = (
        (1, "owner@example.com", org_a, "owner", True),
        (2, "admin@example.com", org_a, "admin", False),
        (3, "manager@example.com", org_a, "manager", False),
        (4, "engineer@example.com", org_a, "engineer", False),
        (5, "platform-only@example.com", None, None, True),
        (6, "another-platform-only@example.com", None, None, True),
    )
    for user_id, email, org, role, is_platform in people:
        admin.execute(
            "INSERT INTO users(id,email,name,password_hash) VALUES (%s,%s,%s,'unused')",
            (user_id, email, email),
        )
        if org:
            admin.execute(
                "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
                (org, user_id, role),
            )
        if is_platform:
            admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (user_id,))
    for org, name in ((org_a, "A stock"), (org_b, "B stock")):
        admin.execute("INSERT INTO stores(organization_id,name,type) VALUES (%s,%s,'warehouse')", (org, name))

    principals = {
        user_id: AuthenticatedPrincipal(user_id, org, role, is_platform)
        for user_id, _email, org, role, is_platform in people
    }
    for user_id, _email, _org, role, is_platform in people:
        principal = principals[user_id]
        if role in {"owner", "admin"}:
            assert require_company_admin(principal) is principal
        else:
            with pytest.raises(HTTPException) as denied:
                require_company_admin(principal)
            assert denied.value.status_code == 403
        if is_platform:
            assert require_platform_admin(principal) is principal
            assert require_superadmin(principal) is None
        else:
            with pytest.raises(HTTPException):
                require_platform_admin(principal)

    runtime_role = "matrix_runtime_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(runtime_role)
    ))
    admin.execute(sql.SQL("GRANT SELECT ON stores TO {}").format(sql.Identifier(runtime_role)))
    admin.commit()
    dsn = conninfo_to_dict(__import__("os").environ["TEST_DATABASE_URL"])
    with psycopg.connect(**dsn, row_factory=dict_row) as reader:
        reader.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        reader.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        reader.commit()
        assert reader.execute("SELECT count(*) AS n FROM stores").fetchone()["n"] == 0
        set_tenant_context(reader, org_a)
        assert reader.execute("SELECT name FROM stores ORDER BY name").fetchall() == [{"name": "A stock"}]
        reader.commit()
        reader.execute("SELECT 1")
        set_tenant_context(reader, org_b)
        assert reader.execute("SELECT name FROM stores ORDER BY name").fetchall() == [{"name": "B stock"}]
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(runtime_role)))
    admin.commit()
