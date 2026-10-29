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
        "GRANT SELECT, UPDATE ON users TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT SELECT ON sessions TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON platform_admins TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON organization_memberships TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE ON organizations TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, INSERT ON organization_settings, organization_invitations, platform_audit_events TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON organization_invitations TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT INSERT (organization_id, message_type, recipient_email, encrypted_payload, idempotency_key), "
        "SELECT (id, idempotency_key), UPDATE (idempotency_key) ON mail_outbox TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT ON platform_mail_outbox_counts TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT SELECT ON platform_organization_invitation_mail_counts TO {}").format(sql.Identifier(runtime_role)))
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
                          org_id=org_id, member_id=member_id, runtime_role=runtime_role,
                          schema=schema, runtime_connection=get_connection)
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


def test_platform_dashboard_preserves_mail_count_fields_from_counts_view(platform_api):
    api = platform_api
    dashboard = api.endpoint("GET", "/api/platform/dashboard")
    result = asyncio.run(dashboard(request=api.request, actor=api.principal))

    assert result["mail_pending"] == 0
    assert result["mail_failed"] == 0
    assert {
        "organizations_total",
        "organizations_active",
        "identities_active",
        "platform_admins",
        "mail_pending",
        "mail_failed",
    } == set(result)


def test_platform_organization_directory_search_filters_paginates_and_returns_aggregates(platform_api):
    api = platform_api
    acme_id = api.admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Acme Repair','acme-repair') RETURNING id"
    ).fetchone()["id"]
    api.admin.execute("INSERT INTO organization_settings(organization_id) VALUES (%s)", (acme_id,))
    for email, active in (("acme-one@example.test", True), ("acme-two@example.test", False)):
        user_id = api.admin.execute(
            "INSERT INTO users(email,name,password_hash) VALUES (%s,%s,'hash') RETURNING id",
            (email, email),
        ).fetchone()["id"]
        api.admin.execute(
            "INSERT INTO organization_memberships(organization_id,user_id,company_role,is_active) VALUES (%s,%s,'engineer',%s)",
            (acme_id, user_id, active),
        )
    api.admin.execute(
        """INSERT INTO mail_outbox
           (organization_id,message_type,recipient_email,encrypted_payload,idempotency_key,status)
           VALUES (%s,'organization_invitation','a@example.test','cipher','acme-pending','pending'),
                  (%s,'organization_invitation','b@example.test','cipher','acme-failed','failed')""",
        (acme_id, acme_id),
    )
    api.admin.execute(
        "INSERT INTO organizations(name,slug,is_active) VALUES ('Zebra Parts','zebra-parts',FALSE)"
    )
    api.admin.commit()

    list_orgs = api.endpoint("GET", "/api/platform/organizations")
    filtered = asyncio.run(list_orgs(
        request=api.request, actor=api.principal,
        search="Acme", status="active", limit=10, offset=0,
    ))
    assert filtered["total"] == 1
    assert filtered["rows"][0]["name"] == "Acme Repair"
    assert filtered["rows"][0]["active_member_count"] == 1
    assert filtered["rows"][0]["pending_invitation_mail_count"] == 1
    assert filtered["rows"][0]["failed_invitation_mail_count"] == 1
    assert set(filtered["rows"][0]) == {
        "id", "name", "slug", "is_active", "created_at", "active_member_count",
        "pending_invitation_mail_count", "failed_invitation_mail_count",
    }

    page = asyncio.run(list_orgs(
        request=api.request, actor=api.principal, status="all", limit=1, offset=1,
    ))
    assert page["total"] == 3
    assert page["offset"] == 1
    assert len(page["rows"]) == 1
    assert page["rows"][0]["name"] == "Existing Tenant"


@pytest.mark.parametrize("kwargs", [
    {"limit": 0}, {"limit": 101}, {"offset": -1},
    {"status": "all-tenants"}, {"search": "x" * 101},
])
def test_platform_organization_directory_rejects_invalid_filters_before_connecting(kwargs):
    from backend.routes.platform_organizations import create_platform_organizations_router

    router = create_platform_organizations_router(
        get_connection=lambda: pytest.fail("invalid directory filters must fail before connecting"),
        current_user=lambda: None, csrf_dependency=lambda: None,
        encryption_key="unused", frontend_url="https://example.test",
    )
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/platform/organizations")
    with pytest.raises(HTTPException) as error:
        asyncio.run(endpoint(request=SimpleNamespace(cookies={}), actor=1, **kwargs))
    assert error.value.status_code == 422


def test_platform_admin_grant_request_trims_and_validates_exact_email():
    from pydantic import ValidationError
    from backend.schemas.platform_organizations import PlatformAdminGrantRequest

    request = PlatformAdminGrantRequest(email="  Ops.Team+Platform@example.com  ")
    assert request.email == "Ops.Team+Platform@example.com"
    with pytest.raises(ValidationError):
        PlatformAdminGrantRequest(email="not-an-email")


def test_platform_suspend_reactivate_audits_reason_and_is_idempotent(platform_api):
    from backend.schemas.platform_organizations import PlatformOrganizationStatusRequest

    api = platform_api
    status = api.endpoint("PUT", "/api/platform/organizations/{organization_id}/status")
    suspend = PlatformOrganizationStatusRequest(action="suspend", reason="Customer requested a temporary pause")
    result = asyncio.run(status(
        organization_id=str(api.org_id), body=suspend, request=api.request,
        actor=api.principal, csrf_valid=True,
    ))
    assert result == {"success": True, "is_active": False, "changed": True}
    assert api.admin.execute("SELECT is_active FROM organizations WHERE id=%s", (api.org_id,)).fetchone()["is_active"] is False
    audit = api.admin.execute(
        "SELECT action, details FROM platform_audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert audit["action"] == "organization_suspended"
    assert audit["details"] == {"reason": "Customer requested a temporary pause"}

    repeated = asyncio.run(status(
        organization_id=str(api.org_id), body=suspend, request=api.request,
        actor=api.principal, csrf_valid=True,
    ))
    assert repeated == {"success": True, "is_active": False, "changed": False}
    assert api.admin.execute("SELECT count(*) AS n FROM platform_audit_events").fetchone()["n"] == 1

    reactivate = PlatformOrganizationStatusRequest(action="reactivate", reason="Customer confirmed reopening")
    result = asyncio.run(status(
        organization_id=str(api.org_id), body=reactivate, request=api.request,
        actor=api.principal, csrf_valid=True,
    ))
    assert result == {"success": True, "is_active": True, "changed": True}
    assert api.admin.execute("SELECT count(*) AS n FROM platform_audit_events").fetchone()["n"] == 2


def test_platform_status_unknown_organization_returns_404(platform_api):
    from backend.schemas.platform_organizations import PlatformOrganizationStatusRequest

    api = platform_api
    status = api.endpoint("PUT", "/api/platform/organizations/{organization_id}/status")
    with pytest.raises(HTTPException) as error:
        asyncio.run(status(
            organization_id=str(uuid4()),
            body=PlatformOrganizationStatusRequest(action="suspend", reason="Security incident review"),
            request=api.request, actor=api.principal, csrf_valid=True,
        ))
    assert error.value.status_code == 404


def test_platform_status_requires_platform_admin(platform_api):
    from backend.schemas.platform_organizations import PlatformOrganizationStatusRequest
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    api = platform_api
    user_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Tenant','hash') RETURNING id",
        (f"tenant-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    token = "tenant-token-" + uuid4().hex
    api.admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (user_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    api.admin.commit()
    status = api.endpoint("PUT", "/api/platform/organizations/{organization_id}/status")
    request = SimpleNamespace(cookies={"session_token": token})
    with pytest.raises(HTTPException) as error:
        asyncio.run(status(
            organization_id=str(api.org_id),
            body=PlatformOrganizationStatusRequest(action="suspend", reason="Security incident review"),
            request=request, actor=user_id, csrf_valid=True,
        ))
    assert error.value.status_code == 403


def test_platform_admin_list_does_not_expose_non_admin_identities(platform_api):
    api = platform_api
    tenant_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Private tenant identity','hash') RETURNING id",
        (f"private-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    api.admin.commit()
    list_admins = api.endpoint("GET", "/api/platform/admins")
    rows = asyncio.run(list_admins(request=api.request, actor=api.principal))
    assert rows == [{
        "id": api.principal.user_id,
        "email": "platform@example.test",
        "name": "Platform",
    }]
    assert tenant_id not in {row["id"] for row in rows}


def test_platform_admin_grant_matches_exact_active_email_and_is_idempotent(platform_api):
    from backend.schemas.platform_organizations import PlatformAdminGrantRequest

    api = platform_api
    target_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Platform candidate','hash') RETURNING id",
        (f"candidate+platform-{uuid4().hex}@example.com",),
    ).fetchone()["id"]
    decoy_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Similar address','hash') RETURNING id",
        (f"candidate@example.com",),
    ).fetchone()["id"]
    target_email = api.admin.execute(
        "SELECT email FROM users WHERE id = %s", (target_id,)
    ).fetchone()["email"]
    api.admin.commit()

    grant = api.endpoint("POST", "/api/platform/admins")
    body = PlatformAdminGrantRequest(email=f"  {target_email.upper()}  ")
    first = asyncio.run(grant(body=body, request=api.request, actor=api.principal, csrf_valid=True))
    assert first == {"success": True, "created": True}
    second = asyncio.run(grant(body=body, request=api.request, actor=api.principal, csrf_valid=True))
    assert second == {"success": True, "created": False}
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_admins WHERE user_id = %s", (target_id,)
    ).fetchone()["total"] == 1
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_admins WHERE user_id = %s", (decoy_id,)
    ).fetchone()["total"] == 0
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_audit_events WHERE action = 'platform_admin_granted'"
    ).fetchone()["total"] == 1


@pytest.mark.parametrize("archived", [False, True])
def test_platform_admin_grant_rejects_unknown_or_archived_email(platform_api, archived):
    from backend.schemas.platform_organizations import PlatformAdminGrantRequest

    api = platform_api
    email = f"archived-{uuid4().hex}@example.com" if archived else f"missing-{uuid4().hex}@example.com"
    if archived:
        api.admin.execute(
            "INSERT INTO users(email,name,password_hash,archived_at) VALUES (%s,'Archived','hash',%s)",
            (email, "2026-10-27T00:00:00Z"),
        )
        api.admin.commit()
    grant = api.endpoint("POST", "/api/platform/admins")
    with pytest.raises(HTTPException) as error:
        asyncio.run(grant(
            body=PlatformAdminGrantRequest(email=email), request=api.request,
            actor=api.principal, csrf_valid=True,
        ))
    assert error.value.status_code == 404


def test_platform_admin_cannot_remove_own_access_even_when_another_admin_exists(platform_api):
    api = platform_api
    other_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Other admin','hash') RETURNING id",
        (f"other-admin-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    api.admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (other_id,))
    api.admin.commit()

    revoke = api.endpoint("DELETE", "/api/platform/admins/{target_user_id}")
    with pytest.raises(HTTPException) as error:
        asyncio.run(revoke(
            target_user_id=api.principal.user_id, request=api.request,
            actor=api.principal, csrf_valid=True,
        ))
    assert error.value.status_code == 409
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_admins"
    ).fetchone()["total"] == 2


def test_last_platform_admin_cannot_be_removed(platform_api):
    api = platform_api
    revoke = api.endpoint("DELETE", "/api/platform/admins/{target_user_id}")
    with pytest.raises(HTTPException) as error:
        asyncio.run(revoke(
            target_user_id=api.principal.user_id, request=api.request,
            actor=api.principal, csrf_valid=True,
        ))
    assert error.value.status_code == 409
    assert api.admin.execute("SELECT count(*) AS total FROM platform_admins").fetchone()["total"] == 1


def test_platform_admin_grant_requires_platform_authority(platform_api):
    from backend.schemas.platform_organizations import PlatformAdminGrantRequest
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    api = platform_api
    tenant_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Tenant identity','hash') RETURNING id",
        (f"tenant-grant-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    token = "tenant-grant-token-" + uuid4().hex
    api.admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (tenant_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    api.admin.commit()
    grant = api.endpoint("POST", "/api/platform/admins")
    with pytest.raises(HTTPException) as error:
        asyncio.run(grant(
            body=PlatformAdminGrantRequest(email="target@example.com"),
            request=SimpleNamespace(cookies={"session_token": token}),
            actor=tenant_id, csrf_valid=True,
        ))
    assert error.value.status_code == 403


def test_concurrent_platform_admin_revokes_cannot_remove_last_admin(platform_api):
    from concurrent.futures import ThreadPoolExecutor
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    api = platform_api
    second_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Second admin','hash') RETURNING id",
        (f"second-admin-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    api.admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (second_id,))
    second_token = "second-admin-token-" + uuid4().hex
    api.admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (second_id, hash_session_credential(second_token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    api.admin.commit()
    revoke = api.endpoint("DELETE", "/api/platform/admins/{target_user_id}")

    def attempt(target_id, request, actor):
        try:
            return asyncio.run(revoke(
                target_user_id=target_id, request=request, actor=actor, csrf_valid=True,
            ))
        except HTTPException as error:
            return error.status_code

    second_request = SimpleNamespace(cookies={"session_token": second_token})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda args: attempt(*args), [
            (second_id, api.request, api.principal),
            (api.principal.user_id, second_request, second_id),
        ]))
    assert sum(result == {"success": True} for result in results) == 1
    assert 409 in results
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_admins pa JOIN users u ON u.id=pa.user_id WHERE u.archived_at IS NULL"
    ).fetchone()["total"] == 1
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_audit_events WHERE action = 'platform_admin_revoked'"
    ).fetchone()["total"] == 1


def test_platform_web_role_cannot_read_mail_outbox_rows(platform_api):
    from psycopg.errors import InsufficientPrivilege

    api = platform_api
    connection = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
    try:
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(api.schema)))
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(api.runtime_role)))
        connection.commit()
        assert connection.execute("SELECT count(*) AS total FROM users").fetchone()["total"] >= 2
        table_privileges = connection.execute(
            """SELECT has_table_privilege(current_user, 'mail_outbox', 'SELECT') AS can_select,
                      has_table_privilege(current_user, 'mail_outbox', 'UPDATE') AS can_update,
                      has_table_privilege(current_user, 'mail_outbox', 'DELETE') AS can_delete"""
        ).fetchone()
        assert table_privileges == {"can_select": False, "can_update": False, "can_delete": False}
        with pytest.raises(InsufficientPrivilege):
            connection.execute("SELECT recipient_email FROM mail_outbox").fetchall()
        connection.rollback()
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(api.runtime_role)))
        connection.commit()
        with pytest.raises(InsufficientPrivilege):
            connection.execute("SELECT * FROM mail_outbox").fetchall()
    finally:
        connection.close()


@pytest.mark.parametrize("columns", ["encrypted_payload", "id, status"])
def test_platform_web_role_cannot_read_mail_outbox_sensitive_columns(platform_api, columns):
    from psycopg.errors import InsufficientPrivilege

    api = platform_api
    connection = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
    try:
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(api.schema)))
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(api.runtime_role)))
        connection.commit()

        with pytest.raises(InsufficientPrivilege):
            connection.execute(f"SELECT {columns} FROM mail_outbox").fetchall()
    finally:
        connection.close()


def test_platform_web_role_can_idempotently_enqueue_mail(platform_api):
    from backend.services.mail_outbox import enqueue_mail

    api = platform_api
    connection = api.runtime_connection()
    try:
        first = enqueue_mail(
            connection, organization_id=api.org_id,
            message_type="organization_invitation", recipient_email="owner@example.test",
            encrypted_payload="ciphertext", idempotency_key="platform-owner-invite",
        )
        second = enqueue_mail(
            connection, organization_id=api.org_id,
            message_type="organization_invitation", recipient_email="owner@example.test",
            encrypted_payload="ciphertext", idempotency_key="platform-owner-invite",
        )
        assert first == second
    finally:
        connection.rollback()
        connection.close()


def test_platform_role_update_requires_explicit_tenant_path(platform_api):
    from backend.schemas.platform_organizations import PlatformCompanyRoleUpdateRequest

    api = platform_api
    route = api.endpoint("PUT", "/api/platform/organizations/{organization_id}/members/{user_id}/role")
    result = asyncio.run(route(
        organization_id=str(api.org_id), user_id=api.member_id,
        body=PlatformCompanyRoleUpdateRequest(role="engineer", reason="Correct role after customer review"), request=api.request,
        actor=api.principal, csrf_valid=True,
    ))
    assert result["success"] is True
    membership = api.admin.execute(
        "SELECT company_role FROM organization_memberships WHERE organization_id=%s AND user_id=%s",
        (api.org_id, api.member_id),
    ).fetchone()
    assert membership["company_role"] == "engineer"
    audit = api.admin.execute(
        "SELECT action, details FROM platform_audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert audit["action"] == "company_role_changed"
    assert audit["details"]["reason"] == "Correct role after customer review"
