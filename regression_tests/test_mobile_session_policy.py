"""Organization and platform policy for native mobile session lifetimes."""

import asyncio
import os
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException, Response
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_effective_mobile_duration_reads_rls_scoped_org_policy_and_restores_scope():
    from backend.services.mobile_session_policy import effective_mobile_session_duration_hours

    class Connection:
        scope = "previous-scope"

        def execute(self, statement, params=()):
            if "FROM system_settings" in statement:
                return SimpleNamespace(fetchone=lambda: {"setting_value": "72"})
            if "current_setting" in statement:
                return SimpleNamespace(fetchone=lambda: {"organization_id": self.scope})
            if "set_config" in statement:
                self.scope = params[0]
                return SimpleNamespace(fetchone=lambda: None)
            if "FROM organization_settings" in statement:
                assert self.scope == "org-a"
                return SimpleNamespace(fetchone=lambda: {"mobile_session_duration_hours": 36})
            raise AssertionError("Unexpected query")

    conn = Connection()
    assert effective_mobile_session_duration_hours(conn, "org-a") == 36
    assert conn.scope == "previous-scope"


@pytest.fixture
def mobile_policy_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.organization_settings import create_organization_settings_router
    from backend.routes.platform_settings import create_platform_settings_router
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    org_a = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Tenant A','mobile-policy-a') RETURNING id"
    ).fetchone()["id"]
    org_b = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Tenant B','mobile-policy-b') RETURNING id"
    ).fetchone()["id"]
    admin.execute(
        "INSERT INTO organization_settings(organization_id) VALUES (%s),(%s)", (org_a, org_b)
    )
    admin_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('mobile-policy-admin@example.test','Admin','x') RETURNING id"
    ).fetchone()["id"]
    admin.execute(
        "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,'owner')",
        (org_a, admin_id),
    )
    platform_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('mobile-policy-platform@example.test','Platform','x') RETURNING id"
    ).fetchone()["id"]
    admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (platform_id,))
    org_token, platform_token = "mobile-org-token", "mobile-platform-token"
    for user_id, token in ((admin_id, org_token), (platform_id, platform_token)):
        admin.execute(
            "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
            (user_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
        )
    mobile_created = utc_now() - timedelta(hours=12)
    mobile_session_id = admin.execute(
        """INSERT INTO sessions(user_id,session_token_hash,expires_at,absolute_expires_at,created_at,is_mobile)
           VALUES (%s,%s,%s,%s,%s,TRUE) RETURNING id""",
        (admin_id, hash_session_credential("mobile-policy-active-session"),
         serialize_instant(utc_now() + timedelta(hours=90)),
         serialize_instant(utc_now() + timedelta(hours=100)), serialize_instant(mobile_created)),
    ).fetchone()["id"]
    admin.execute(
        """INSERT INTO session_refresh_credentials(session_id,token_hash,issued_at,expires_at)
           VALUES (%s,%s,%s,%s)""",
        (mobile_session_id, hash_session_credential("mobile-policy-active-refresh"),
         serialize_instant(mobile_created), serialize_instant(utc_now() + timedelta(hours=100))),
    )
    role = "mobile_policy_runtime_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
    admin.execute(sql.SQL(
        "GRANT SELECT, UPDATE ON users, sessions, organization_memberships, organizations, organization_settings TO {}"
    ).format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT ON platform_admins, system_settings TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT INSERT, UPDATE ON system_settings TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT INSERT ON platform_audit_events TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE platform_audit_events_id_seq TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON mobile_device_sessions TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON session_refresh_credentials TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT ON organizations TO {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("GRANT SELECT, UPDATE ON sessions TO {}").format(sql.Identifier(role)))
    admin.commit()

    def get_connection():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        conn.commit()
        return conn

    org_router = create_organization_settings_router(
        get_connection=get_connection,
        authenticated_writer=lambda actor, token: authenticated_write_transaction(
            get_connection, user_id=actor, session_token=token
        ), current_user=lambda: None, csrf_dependency=lambda: None,
    )
    platform_router = create_platform_settings_router(
        get_connection=get_connection, current_user=lambda: None, csrf_dependency=lambda: None,
    )
    def endpoint(router, method, path):
        return next(r.endpoint for r in router.routes if method in r.methods and r.path == path)
    req_org = SimpleNamespace(cookies={"session_token": org_token})
    req_platform = SimpleNamespace(cookies={"session_token": platform_token})
    yield SimpleNamespace(
        admin=admin, org_a=org_a, org_b=org_b, admin_id=admin_id, platform_id=platform_id,
        mobile_session_id=mobile_session_id, mobile_created=mobile_created,
        org_router=org_router, platform_router=platform_router, endpoint=endpoint,
        org_request=req_org, platform_request=req_platform,
        org_principal=AuthenticatedPrincipal(admin_id, org_a, "owner", False),
        platform_principal=AuthenticatedPrincipal(platform_id, None, None, True),
    )
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    admin.commit()


def test_org_admin_can_set_mobile_session_lifetime_with_platform_cap(mobile_policy_api):
    from backend.schemas.organization_settings import MobileSessionPolicyUpdate
    from backend.schemas.superadmin import SystemSettingUpdate

    api = mobile_policy_api
    read = api.endpoint(api.org_router, "GET", "/api/organization/mobile-session-policy")
    update = api.endpoint(api.org_router, "PUT", "/api/organization/mobile-session-policy")
    initial = asyncio.run(read(request=api.org_request, user_id=api.org_principal))
    assert initial == {"duration_hours": 720, "max_duration_hours": 720}
    changed = asyncio.run(update(
        body=MobileSessionPolicyUpdate(duration_hours=48), request=api.org_request,
        user_id=api.org_principal, csrf_valid=True,
    ))
    assert changed == {"duration_hours": 48, "max_duration_hours": 720}
    assert api.admin.execute(
        "SELECT mobile_session_duration_hours FROM organization_settings WHERE organization_id=%s",
        (api.org_a,),
    ).fetchone()["mobile_session_duration_hours"] == 48
    assert api.admin.execute(
        "SELECT mobile_session_duration_hours FROM organization_settings WHERE organization_id=%s",
        (api.org_b,),
    ).fetchone()["mobile_session_duration_hours"] == 720
    deadline = api.admin.execute(
        "SELECT absolute_expires_at FROM sessions WHERE id=%s", (api.mobile_session_id,)
    ).fetchone()["absolute_expires_at"]
    from backend.temporal import serialize_instant
    assert deadline == serialize_instant(api.mobile_created + timedelta(hours=48))
    refresh_deadline = api.admin.execute(
        "SELECT expires_at FROM session_refresh_credentials WHERE session_id=%s", (api.mobile_session_id,)
    ).fetchone()["expires_at"]
    assert refresh_deadline == deadline
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        MobileSessionPolicyUpdate(duration_hours=721)
    platform_update = api.endpoint(api.platform_router, "PUT", "/api/platform/security-config/{key}")
    asyncio.run(platform_update(
        key="mobile_session_max_duration_hours", body=SystemSettingUpdate(value="24"),
        request=api.platform_request, actor=api.platform_principal, csrf_valid=True,
    ))
    with pytest.raises(HTTPException) as error:
        asyncio.run(update(
            body=MobileSessionPolicyUpdate(duration_hours=48), request=api.org_request,
            user_id=api.org_principal, csrf_valid=True,
        ))
    assert error.value.status_code == 400


def test_platform_mobile_max_reduces_company_policies(mobile_policy_api):
    from backend.schemas.superadmin import SystemSettingUpdate

    api = mobile_policy_api
    update = api.endpoint(api.platform_router, "PUT", "/api/platform/security-config/{key}")
    result = asyncio.run(update(
        key="mobile_session_max_duration_hours", body=SystemSettingUpdate(value="24"),
        request=api.platform_request, actor=api.platform_principal, csrf_valid=True,
    ))
    assert result == {"success": True, "key": "mobile_session_max_duration_hours", "value": 24}
    assert api.admin.execute(
        "SELECT max(mobile_session_duration_hours) AS max_hours FROM organization_settings"
    ).fetchone()["max_hours"] == 24
    deadline = api.admin.execute(
        "SELECT absolute_expires_at FROM sessions WHERE id=%s", (api.mobile_session_id,)
    ).fetchone()["absolute_expires_at"]
    from backend.temporal import serialize_instant
    assert deadline == serialize_instant(api.mobile_created + timedelta(hours=24))

