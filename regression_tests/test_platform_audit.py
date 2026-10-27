"""Platform audit reader validation, ordering, scoping, and redaction."""

import asyncio
import json
import os
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_platform_organization_status_requires_valid_action_and_reason():
    from backend.schemas.platform_organizations import PlatformOrganizationStatusRequest

    request = PlatformOrganizationStatusRequest(action="suspend", reason="  Billing dispute confirmed  ")
    assert request.reason == "Billing dispute confirmed"
    with pytest.raises(ValidationError):
        PlatformOrganizationStatusRequest(action="pause", reason="not valid")
    with pytest.raises(ValidationError):
        PlatformOrganizationStatusRequest(action="suspend", reason="short")


def test_platform_audit_writer_and_reader_apply_action_specific_detail_allowlists():
    from backend.services.platform_audit import record_platform_audit_event, safe_platform_audit_details

    class Capture:
        args = None
        def execute(self, query, args):
            self.args = args

    conn = Capture()
    record_platform_audit_event(
        conn, 12, "company_role_changed", "success", "org-id",
        {"target_user_id": 8, "role": "admin", "token": "secret"},
    )
    assert json.loads(conn.args[-1]) == {"target_user_id": 8, "role": "admin"}
    assert safe_platform_audit_details("company_role_changed", {
        "target_user_id": True, "role": ["malformed"], "password": "secret",
    }) == {}
    assert safe_platform_audit_details("organization_suspended", {
        "reason": "Customer requested a temporary pause", "token": "secret",
    }) == {"reason": "Customer requested a temporary pause"}


@pytest.fixture
def platform_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    admin_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Platform','hash') RETURNING id",
        (f"platform-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    token = "platform-token-" + uuid4().hex
    admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (admin_id,))
    admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (admin_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    org_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Audit Tenant',%s) RETURNING id",
        ("audit-" + uuid4().hex,),
    ).fetchone()["id"]
    runtime_role = "platform_audit_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(runtime_role)
    ))
    admin.execute(sql.SQL("GRANT SELECT ON users, sessions, platform_admins, organizations, platform_audit_events TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE platform_audit_events_id_seq TO {}").format(sql.Identifier(runtime_role)))
    admin.commit()

    def get_connection():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        conn.commit()
        return conn

    yield SimpleNamespace(
        admin=admin, org_id=org_id, principal=AuthenticatedPrincipal(admin_id, None, None, True),
        request=SimpleNamespace(cookies={"session_token": token}), runtime_connection=get_connection,
    )
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
    admin.commit()


def test_platform_audit_reader_filters_pages_and_redacts_details(platform_api):
    from backend.routes.platform_audit import create_platform_audit_router
    from backend.temporal import serialize_instant, utc_now

    api = platform_api
    now = utc_now()
    secret = "encrypted-mail-payload-do-not-return"
    api.admin.execute(
        """INSERT INTO platform_audit_events
           (actor_user_id, organization_id, action, result, details, created_at)
           VALUES (%s,%s,'company_role_changed','success',%s::jsonb,%s),
                 (%s,%s,'company_role_changed','success',%s::jsonb,%s),
                 (%s,NULL,'platform_admin_granted','success',%s::jsonb,%s)""",
        (api.principal.user_id, api.org_id, '{"target_user_id":55,"role":"manager","token":"' + secret + '"}',
         serialize_instant(now), api.principal.user_id, api.org_id,
         '{"target_user_id":56,"role":"engineer"}', serialize_instant(now - timedelta(minutes=1)),
         api.principal.user_id, '{"target_user_id":57,"password":"hidden"}', serialize_instant(now)),
    )
    other_org_id = api.admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Other Tenant',%s) RETURNING id",
        ("other-audit-" + uuid4().hex,),
    ).fetchone()["id"]
    api.admin.execute(
        """INSERT INTO platform_audit_events
           (actor_user_id, organization_id, action, result, details, created_at)
           VALUES (%s,%s,'platform_admin_revoked','success','{}'::jsonb,%s)""",
        (api.principal.user_id, other_org_id, serialize_instant(now)),
    )
    router = create_platform_audit_router(get_connection=api.runtime_connection, current_user=lambda: None)
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/platform/audit-events")
    result = asyncio.run(endpoint(
        request=api.request, actor=api.principal, organization_id=str(api.org_id),
        action="company_role_changed", limit=1, offset=0,
    ))
    assert result["total"] == 2
    assert len(result["rows"]) == 1
    assert result["rows"][0]["details"] == {"target_user_id": 55, "role": "manager"}
    assert secret not in str(result)

    next_page = asyncio.run(endpoint(
        request=api.request, actor=api.principal, organization_id=str(api.org_id),
        action="company_role_changed", limit=1, offset=1,
    ))
    assert next_page["rows"][0]["details"]["target_user_id"] == 56
    all_rows = asyncio.run(endpoint(request=api.request, actor=api.principal, limit=10, offset=0))
    assert all_rows["total"] == 4
    assert all_rows["rows"][0]["id"] > all_rows["rows"][1]["id"]
    assert {row["organization_id"] for row in all_rows["rows"] if row["organization_id"]} == {
        str(api.org_id), str(other_org_id),
    }
    assert all_rows["rows"][-1]["details"] == {"target_user_id": 56, "role": "engineer"}


@pytest.mark.parametrize("kwargs", [
    {"limit": 0}, {"limit": 101}, {"offset": -1},
    {"organization_id": "not-a-uuid"}, {"start_at": "2026-10-27T00:00:00"},
    {"start_at": "2026-10-28T00:00:00Z", "end_at": "2026-10-27T00:00:00Z"},
    {"action": "x" * 101}, {"result": "   "},
])
def test_platform_audit_rejects_invalid_filters_before_database_access(kwargs):
    from backend.routes.platform_audit import create_platform_audit_router

    router = create_platform_audit_router(
        get_connection=lambda: pytest.fail("invalid filters must fail before connecting"),
        current_user=lambda: None,
    )
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/platform/audit-events")
    with pytest.raises(HTTPException) as error:
        asyncio.run(endpoint(request=SimpleNamespace(cookies={}), actor=1, **kwargs))
    assert error.value.status_code == 422


def test_non_platform_identity_cannot_read_platform_audit(platform_api):
    from backend.routes.platform_audit import create_platform_audit_router
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    api = platform_api
    user_id = api.admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES (%s,'Member','hash') RETURNING id",
        (f"nonadmin-{uuid4().hex}@example.test",),
    ).fetchone()["id"]
    token = "not-platform-" + uuid4().hex
    api.admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (user_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    api.admin.commit()
    request = SimpleNamespace(cookies={"session_token": token})
    router = create_platform_audit_router(get_connection=api.runtime_connection, current_user=lambda: None)
    endpoint = next(route.endpoint for route in router.routes if route.path == "/api/platform/audit-events")
    with pytest.raises(HTTPException) as error:
        asyncio.run(endpoint(request=request, actor=SimpleNamespace(user_id=user_id)))
    assert error.value.status_code == 403
