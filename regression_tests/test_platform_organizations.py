"""Platform provisioning uses separate authority and transaction context."""

import asyncio
import os
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql
from cryptography.fernet import Fernet

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def platform_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.platform_organizations import create_platform_organizations_router
    from backend.services.principals import AuthenticatedPrincipal
    from backend.temporal import serialize_instant, utc_now
    from backend.services.session_credentials import hash_session_credential

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    admin_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('platform@example.test','Platform','hash') RETURNING id"
    ).fetchone()["id"]
    token = "platform-token-" + uuid4().hex
    admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (admin_id,))
    admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (admin_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    org_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Existing Tenant',%s) RETURNING id",
        ("existing-" + uuid4().hex,),
    ).fetchone()["id"]
    member_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('member@example.test','Member','hash') RETURNING id"
    ).fetchone()["id"]
    admin.execute(
        "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,'manager')",
        (org_id, member_id),
    )
    runtime_role = "platform_route_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(runtime_role)
    ))
    admin.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, platform_admins TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON organization_memberships TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, INSERT ON organizations TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT INSERT ON organization_settings, organization_invitations, mail_outbox, platform_audit_events TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON organization_invitations TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON mail_outbox TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT USAGE, SELECT ON SEQUENCE organization_invitations_id_seq, mail_outbox_id_seq, platform_audit_events_id_seq TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.commit()

    def get_connection():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        conn.commit()
        return conn

    router = create_platform_organizations_router(
        get_connection=get_connection, current_user=lambda: None,
        csrf_dependency=lambda: None,
        encryption_key=Fernet.generate_key().decode(),
        frontend_url="https://inventory.example.test",
    )
    def endpoint(method, path):
        return next(route.endpoint for route in router.routes if route.path == path and method in route.methods)

    request = SimpleNamespace(cookies={"session_token": token})
    principal = AuthenticatedPrincipal(admin_id, None, None, True)
    yield SimpleNamespace(admin=admin, endpoint=endpoint, request=request, principal=principal,
                          org_id=org_id, member_id=member_id)
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
    admin.commit()


def test_platform_provisions_tenant_and_encrypted_owner_invitation(platform_api):
    from backend.schemas.invitations import OrganizationCreateRequest

    api = platform_api
    create = api.endpoint("POST", "/api/platform/organizations")
    result = asyncio.run(create(
        body=OrganizationCreateRequest(
            name="Acme Services", slug="acme-services", owner_email="owner@example.com"
        ),
        request=api.request, user_id=api.principal, csrf_valid=True,
    ))
    assert result["organization"]["slug"] == "acme-services"
    assert "token" not in str(result).lower()
    assert api.admin.execute("SELECT count(*) AS n FROM organization_settings").fetchone()["n"] == 1
    invitation = api.admin.execute(
        "SELECT company_role, token_hash FROM organization_invitations"
    ).fetchone()
    assert invitation["company_role"] == "owner"
    assert len(invitation["token_hash"]) == 64
    assert api.admin.execute("SELECT count(*) AS n FROM mail_outbox").fetchone()["n"] == 1
    assert api.admin.execute("SELECT count(*) AS n FROM platform_audit_events").fetchone()["n"] == 1


def test_platform_role_update_requires_explicit_tenant_path(platform_api):
    from backend.schemas.invitations import CompanyRoleUpdateRequest

    api = platform_api
    route = api.endpoint("PUT", "/api/platform/organizations/{organization_id}/members/{user_id}/role")
    result = asyncio.run(route(
        organization_id=str(api.org_id), user_id=api.member_id,
        body=CompanyRoleUpdateRequest(role="engineer"), request=api.request,
        actor=api.principal, csrf_valid=True,
    ))
    assert result["success"] is True
    membership = api.admin.execute(
        "SELECT company_role FROM organization_memberships WHERE organization_id=%s AND user_id=%s",
        (api.org_id, api.member_id),
    ).fetchone()
    assert membership["company_role"] == "engineer"
    assert api.admin.execute(
        "SELECT action FROM platform_audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()["action"] == "company_role_changed"
