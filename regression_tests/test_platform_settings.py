"""PostgreSQL platform routes for announcements and supported global settings."""

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


@pytest.fixture
def platform_settings_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.platform_settings import create_platform_settings_router
    from backend.routes.superadmin import create_superadmin_router
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    admin_id = admin.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('platform-settings@example.test','Settings admin','hash') RETURNING id"
    ).fetchone()["id"]
    token = "platform-settings-token-" + uuid4().hex
    admin.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (admin_id,))
    admin.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (admin_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    runtime_role = "platform_settings_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(runtime_role),
    ))
    admin.execute(sql.SQL(
        "GRANT SELECT ON users, sessions, platform_admins, organization_memberships, organizations TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT SELECT, INSERT, UPDATE ON system_settings TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT SELECT, INSERT, DELETE ON platform_announcements TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT INSERT ON platform_audit_events TO {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT USAGE, SELECT ON SEQUENCE system_settings_id_seq, platform_announcements_id_seq, platform_audit_events_id_seq TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.commit()

    def get_connection():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        conn.commit()
        return conn

    platform_router = create_platform_settings_router(
        get_connection=get_connection,
        current_user=lambda: None,
        csrf_dependency=lambda: None,
    )
    legacy_router = create_superadmin_router(
        get_connection=get_connection,
        database_path=lambda: "unused",
        authenticated_writer=lambda *args, **kwargs: None,
        current_user=lambda: None,
        csrf_dependency=lambda: None,
        superadmin_guard=lambda *args, **kwargs: None,
        password_hash=lambda value: value,
        activity_log=lambda *args, **kwargs: None,
        authenticated_activity=lambda *args, **kwargs: None,
        database_defaults=lambda: {},
        session_validator=lambda *args, **kwargs: None,
    )

    def endpoint(router, method, path):
        return next(route.endpoint for route in router.routes if route.path == path and method in route.methods)

    request = SimpleNamespace(cookies={"session_token": token})
    principal = AuthenticatedPrincipal(admin_id, None, None, True)
    yield SimpleNamespace(
        admin=admin,
        settings_endpoint=lambda method, path: endpoint(platform_router, method, path),
        public_announcement_endpoint=endpoint(legacy_router, "GET", "/api/superadmin/announcement"),
        request=request,
        principal=principal,
        runtime_connection=get_connection,
        runtime_role=runtime_role,
        schema=schema,
    )
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
    admin.commit()


def test_platform_announcement_uses_postgres_table_utc_and_revision_conflicts(platform_settings_api):
    from backend.schemas.superadmin import SystemAnnouncementRequest
    from backend.services.announcements import eligible_notice
    from backend.temporal import serialize_instant, utc_now

    api = platform_settings_api
    manage = api.settings_endpoint("GET", "/api/platform/announcement/manage")
    first = asyncio.run(manage(request=api.request, response=Response(), actor=api.principal))
    assert first["announcement"] is None
    assert first["business_timezone"] == "UTC"
    assert first["timezone_revision"] == 0

    starts_at = (utc_now() + timedelta(hours=2)).replace(microsecond=0)
    starts_local = starts_at.strftime("%Y-%m-%dT%H:%M:%S")
    body = SystemAnnouncementRequest(
        message="Planned platform maintenance",
        level="warning",
        audience="roles",
        roles=["manager"],
        starts_local=starts_local,
        timezone_revision=0,
        dismissible=True,
        expected_revision=None,
    )
    save = api.settings_endpoint("POST", "/api/platform/announcement")
    result = asyncio.run(save(body=body, request=api.request, actor=api.principal, csrf_valid=True))
    assert result["success"] is True

    saved = asyncio.run(manage(request=api.request, response=Response(), actor=api.principal))
    assert saved["status"] == "scheduled"
    assert saved["announcement"]["audience"] == "roles"
    assert saved["announcement"]["roles"] == ["manager"]
    assert saved["announcement"]["starts_at"] == serialize_instant(starts_at)
    assert eligible_notice(None, saved["announcement"], viewer={"user_id": 4, "role": "manager"}, now=starts_at, check_dismissal=False)
    assert eligible_notice(None, saved["announcement"], viewer={"user_id": 5, "role": "engineer"}, now=starts_at, check_dismissal=False) is None
    stored = api.admin.execute("SELECT revision, payload FROM platform_announcements").fetchone()
    assert stored["revision"] == saved["announcement"]["revision"]
    assert stored["payload"]["message"] == "Planned platform maintenance"

    stale = SystemAnnouncementRequest(
        message="Stale update", timezone_revision=0, expected_revision="old-revision",
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(save(body=stale, request=api.request, actor=api.principal, csrf_valid=True))
    assert error.value.status_code == 409
    assert api.admin.execute(
        "SELECT details FROM platform_audit_events WHERE action='platform_announcement_saved'"
    ).fetchone()["details"]["audience"] == "roles"

    wrong_timezone_revision = SystemAnnouncementRequest(
        message="Stale timezone", timezone_revision=1,
        expected_revision=saved["announcement"]["revision"],
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(save(body=wrong_timezone_revision, request=api.request, actor=api.principal, csrf_valid=True))
    assert error.value.status_code == 409

    remove = api.settings_endpoint("DELETE", "/api/platform/announcement")
    asyncio.run(remove(
        request=api.request, expected_revision=saved["announcement"]["revision"],
        actor=api.principal, csrf_valid=True,
    ))
    assert asyncio.run(manage(request=api.request, response=Response(), actor=api.principal))["announcement"] is None
    assert api.admin.execute(
        "SELECT count(*) AS total FROM platform_audit_events WHERE action='platform_announcement_removed'"
    ).fetchone()["total"] == 1


def test_platform_public_announcement_keeps_contract_and_anonymous_eligibility(platform_settings_api):
    from backend.schemas.superadmin import SystemAnnouncementRequest
    from backend.services.announcements import eligible_notice
    from backend.temporal import utc_now

    api = platform_settings_api
    save = api.settings_endpoint("POST", "/api/platform/announcement")
    body = SystemAnnouncementRequest(
        message="Public service notice", audience="everyone", dismissible=True,
        timezone_revision=0, expected_revision=None,
    )
    asyncio.run(save(body=body, request=api.request, actor=api.principal, csrf_valid=True))

    public = api.public_announcement_endpoint
    anonymous = asyncio.run(public(request=SimpleNamespace(cookies={})))
    assert anonymous["announcement"]["message"] == "Public service notice"
    assert anonymous["dismissal_mode"] == "browser"
    assert anonymous["viewer_key"] == "anonymous"

    authenticated = asyncio.run(public(request=api.request))
    assert authenticated["announcement"]["message"] == "Public service notice"
    assert authenticated["dismissal_mode"] == "browser"
    assert eligible_notice(None, authenticated["announcement"], viewer=None, now=utc_now(), check_dismissal=False)

    authenticated_only = SystemAnnouncementRequest(
        message="Signed-in notice", audience="authenticated", dismissible=True,
        timezone_revision=0, expected_revision=authenticated["announcement"]["revision"],
    )
    asyncio.run(save(body=authenticated_only, request=api.request, actor=api.principal, csrf_valid=True))
    assert asyncio.run(public(request=SimpleNamespace(cookies={})))["announcement"] is None
    assert asyncio.run(public(request=api.request))["announcement"]["audience"] == "authenticated"


def test_platform_security_settings_validate_audit_and_feed_auth_configuration(platform_settings_api):
    from backend.schemas.superadmin import SystemSettingUpdate
    from backend.services.security_settings import load_security_settings

    api = platform_settings_api
    get_settings = api.settings_endpoint("GET", "/api/platform/security-config")
    update = api.settings_endpoint("PUT", "/api/platform/security-config/{key}")
    assert asyncio.run(get_settings(request=api.request, response=Response(), actor=api.principal)) == {}

    result = asyncio.run(update(
        key="max_login_attempts", body=SystemSettingUpdate(value="8"),
        request=api.request, actor=api.principal, csrf_valid=True,
    ))
    assert result == {"success": True, "key": "max_login_attempts", "value": 8}
    assert asyncio.run(get_settings(request=api.request, response=Response(), actor=api.principal))["max_login_attempts"]["setting_value"] == "8"
    effective = load_security_settings(api.runtime_connection, defaults={
        "max_login_attempts": 5,
        "lockout_duration_minutes": 15,
        "session_duration_hours": 24,
        "remember_me_duration_days": 30,
    })
    assert effective["max_login_attempts"] == 8
    assert api.admin.execute(
        "SELECT details FROM platform_audit_events WHERE action='global_security_setting_changed'"
    ).fetchone()["details"] == {"key": "max_login_attempts", "value": 8}

    for key, value in (("unknown", "1"), ("max_login_attempts", "101"),
                       ("lockout_duration_minutes", "0"), ("session_duration_hours", "abc")):
        with pytest.raises(HTTPException) as error:
            asyncio.run(update(
                key=key, body=SystemSettingUpdate(value=value), request=api.request,
                actor=api.principal, csrf_valid=True,
            ))
        assert error.value.status_code == 400

