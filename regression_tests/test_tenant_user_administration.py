"""Tenant membership administration must never mutate global company roles."""

import asyncio
import os
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


def _member(conn, organization_id, email, role, *, active=True):
    from backend.temporal import serialize_instant, utc_now
    from backend.services.session_credentials import hash_session_credential
    from datetime import timedelta

    user_id = conn.execute(
        "INSERT INTO users(email,name,password_hash,territory) VALUES (%s,%s,'hash','East') RETURNING id",
        (email, email.split("@")[0]),
    ).fetchone()["id"]
    conn.execute(
        "INSERT INTO organization_memberships(organization_id,user_id,company_role,is_active) VALUES (%s,%s,%s,%s)",
        (organization_id, user_id, role, active),
    )
    token = "token-" + email
    conn.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
        (user_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    return user_id, token


@pytest.fixture
def tenant_user_api(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.users import create_users_router
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.principals import AuthenticatedPrincipal

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)
    org_a = connection.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Tenant A','user-admin-a') RETURNING id"
    ).fetchone()["id"]
    org_b = connection.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Tenant B','user-admin-b') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_settings(organization_id) VALUES (%s),(%s)", (org_a, org_b)
    )
    owner_id, owner_token = _member(connection, org_a, "owner@example.test", "owner")
    admin_id, admin_token = _member(connection, org_a, "admin@example.test", "admin")
    manager_id, manager_token = _member(connection, org_a, "manager@example.test", "manager")
    foreign_id, foreign_token = _member(connection, org_b, "foreign@example.test", "engineer")
    role = "users_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    for table in ("users", "sessions", "organization_memberships", "organizations", "organization_settings"):
        connection.execute(sql.SQL("GRANT SELECT, UPDATE ON {} TO {}").format(
            sql.Identifier(table), sql.Identifier(role)
        ))
    connection.execute(sql.SQL("GRANT DELETE ON organization_memberships TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT SELECT ON platform_admins TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT SELECT ON platform_support_sessions TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT UPDATE (ended_at) ON platform_support_sessions TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT INSERT ON platform_audit_events TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE platform_audit_events_id_seq TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT INSERT ON activity_logs TO {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE activity_logs_id_seq TO {}").format(
        sql.Identifier(role)
    ))
    connection.commit()

    def get_connection():
        scoped = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        scoped.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        scoped.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        scoped.commit()
        return scoped

    router = create_users_router(
        get_connection=get_connection,
        authenticated_writer=lambda principal, token: authenticated_write_transaction(
            get_connection, user_id=principal, session_token=token
        ),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
        user_management_guard=lambda *args, **kwargs: None,
        archive_admin_guard=lambda *args, **kwargs: None,
        archive_service=lambda *args, **kwargs: None,
        password_hash=lambda value: "hashed:" + value,
        endpoint_log=lambda *args, **kwargs: (lambda fn: fn),
        mutation_activity=lambda *args, **kwargs: None,
    )

    def endpoint(method, path):
        return next(route.endpoint for route in router.routes if route.path == path and method in route.methods)

    def principal(user_id, organization_id=org_a, company_role="owner"):
        return AuthenticatedPrincipal(user_id, organization_id, company_role, False)

    yield SimpleNamespace(
        connection=connection, org_a=org_a, org_b=org_b, owner_id=owner_id,
        owner_token=owner_token, admin_id=admin_id, admin_token=admin_token,
        manager_id=manager_id, manager_token=manager_token, foreign_id=foreign_id,
        foreign_token=foreign_token, endpoint=endpoint, principal=principal,
    )
    connection.rollback()
    connection.execute("RESET ROLE")
    connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    connection.commit()


def _request(token):
    return SimpleNamespace(cookies={"session_token": token}, client=None, headers={})


def test_archive_user_management_uses_current_company_roles(tenant_user_api):
    from backend.services.authorization import require_user_management

    api = tenant_user_api
    owner = api.principal(api.owner_id, company_role="owner")
    admin = api.principal(api.admin_id, company_role="admin")

    # Both users retain the legacy global role "engineer".
    require_user_management(owner, target_user_id=api.admin_id, conn=api.connection)
    require_user_management(admin, target_user_id=api.manager_id, conn=api.connection)

    with pytest.raises(HTTPException) as denied_admin_target:
        require_user_management(admin, target_user_id=api.admin_id, conn=api.connection)
    assert denied_admin_target.value.status_code == 403

    with pytest.raises(HTTPException) as denied_owner_target:
        require_user_management(owner, target_user_id=api.owner_id, conn=api.connection)
    assert denied_owner_target.value.status_code == 403

    # A stale owner principal cannot overrule the current membership role.
    stale_owner = api.principal(api.admin_id, company_role="owner")
    with pytest.raises(HTTPException) as denied_stale_role:
        require_user_management(stale_owner, requested_role="admin", conn=api.connection)
    assert denied_stale_role.value.status_code == 403


def test_company_user_update_rejects_foreign_membership_id(tenant_user_api):
    from backend.schemas.users import UpdateUserRequest

    api = tenant_user_api
    update = api.endpoint("PUT", "/api/users/{target_user_id}")
    with pytest.raises(HTTPException) as error:
        asyncio.run(update(
            target_user_id=api.foreign_id,
            request_data=UpdateUserRequest(name="Tampered"),
            user_id=api.principal(api.owner_id), csrf_valid=True, request=_request(api.owner_token),
        ))
    assert error.value.status_code == 404


def test_company_role_update_changes_membership_not_global_user_role(tenant_user_api):
    from backend.schemas.users import UpdateUserRequest

    api = tenant_user_api
    update = api.endpoint("PUT", "/api/users/{target_user_id}")
    asyncio.run(update(
        target_user_id=api.manager_id,
        request_data=UpdateUserRequest(role="engineer"),
        user_id=api.principal(api.owner_id), csrf_valid=True, request=_request(api.owner_token),
    ))
    membership = api.connection.execute(
        "SELECT company_role FROM organization_memberships WHERE user_id=%s", (api.manager_id,)
    ).fetchone()
    assert membership["company_role"] == "engineer"
    assert api.connection.execute(
        "SELECT count(*) AS count FROM information_schema.columns "
        "WHERE table_schema=current_schema() AND table_name='users' AND column_name='role'"
    ).fetchone()["count"] == 0


def test_member_deactivation_revokes_sessions(tenant_user_api):
    api = tenant_user_api
    delete = api.endpoint("DELETE", "/api/users/{target_user_id}")
    asyncio.run(delete(
        target_user_id=api.manager_id,
        user_id=api.principal(api.owner_id), csrf_valid=True, request=_request(api.owner_token),
    ))
    assert api.connection.execute(
        "SELECT is_active FROM organization_memberships WHERE user_id=%s", (api.manager_id,)
    ).fetchone()["is_active"] is False
    assert api.connection.execute(
        "SELECT is_active FROM sessions WHERE user_id=%s", (api.manager_id,)
    ).fetchone()["is_active"] is False


def test_member_removal_deletes_only_membership_and_revokes_sessions(tenant_user_api):
    api = tenant_user_api
    activity_id = api.connection.execute(
        """INSERT INTO activity_logs(user_id, username, action, organization_id)
           VALUES (%s, 'manager', 'existing-company-history', %s) RETURNING id""",
        (api.manager_id, api.org_a),
    ).fetchone()["id"]
    remove = api.endpoint("POST", "/api/users/{target_user_id}/remove")
    result = asyncio.run(remove(
        target_user_id=api.manager_id,
        user_id=api.principal(api.owner_id), csrf_valid=True, request=_request(api.owner_token),
    ))

    assert result == {"success": True, "message": "Company membership removed"}
    assert api.connection.execute(
        "SELECT count(*) AS count FROM organization_memberships WHERE user_id=%s", (api.manager_id,)
    ).fetchone()["count"] == 0
    assert api.connection.execute(
        "SELECT count(*) AS count FROM users WHERE id=%s", (api.manager_id,)
    ).fetchone()["count"] == 1
    assert api.connection.execute(
        "SELECT is_active FROM sessions WHERE user_id=%s", (api.manager_id,)
    ).fetchone()["is_active"] is False
    assert api.connection.execute(
        "SELECT user_id, action FROM activity_logs WHERE id=%s", (activity_id,)
    ).fetchone() == {"user_id": api.manager_id, "action": "existing-company-history"}


@pytest.mark.parametrize(("operation", "end_reason"), [
    ("remove", "membership_removed"),
    ("deactivate", "membership_deactivated"),
])
def test_member_session_revocation_ends_support_access_in_same_transaction(tenant_user_api, operation, end_reason):
    from backend.temporal import serialize_instant, utc_now

    api = tenant_user_api
    auth_id = api.connection.execute(
        "SELECT id FROM sessions WHERE user_id=%s", (api.manager_id,)
    ).fetchone()["id"]
    support_id = uuid4()
    now = utc_now()
    api.connection.execute(
        """INSERT INTO platform_support_sessions
           (id,actor_user_id,auth_session_id,organization_id,reason,created_at,expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (support_id, api.manager_id, auth_id, api.org_a, "Investigate access issue",
         serialize_instant(now), serialize_instant(now + timedelta(minutes=15))),
    )
    api.connection.commit()
    if operation == "remove":
        endpoint = api.endpoint("POST", "/api/users/{target_user_id}/remove")
    else:
        endpoint = api.endpoint("DELETE", "/api/users/{target_user_id}")
    asyncio.run(endpoint(
        target_user_id=api.manager_id,
        user_id=api.principal(api.owner_id), csrf_valid=True, request=_request(api.owner_token),
    ))
    ended = api.connection.execute(
        "SELECT ended_at FROM platform_support_sessions WHERE id=%s", (support_id,)
    ).fetchone()["ended_at"]
    event = api.connection.execute(
        "SELECT actor_user_id,organization_id,details FROM platform_audit_events WHERE action='support_session_ended'"
    ).fetchone()
    assert ended is not None
    assert event["actor_user_id"] == api.owner_id
    assert event["organization_id"] == api.org_a
    assert event["details"]["support_session_id"] == str(support_id)
    assert event["details"]["target_user_id"] == api.manager_id
    assert event["details"]["end_reason"] == end_reason


def test_member_removal_is_tenant_scoped_and_protects_owner(tenant_user_api):
    api = tenant_user_api
    remove = api.endpoint("POST", "/api/users/{target_user_id}/remove")
    for target_user_id, status in ((api.foreign_id, 404), (api.owner_id, 403)):
        with pytest.raises(HTTPException) as error:
            asyncio.run(remove(
                target_user_id=target_user_id,
                user_id=api.principal(api.owner_id), csrf_valid=True, request=_request(api.owner_token),
            ))
        assert error.value.status_code == status


def test_admin_cannot_remove_another_admin(tenant_user_api):
    api = tenant_user_api
    api.connection.execute(
        "UPDATE organization_memberships SET company_role='admin' WHERE organization_id=%s AND user_id=%s",
        (api.org_a, api.manager_id),
    )
    remove = api.endpoint("POST", "/api/users/{target_user_id}/remove")
    with pytest.raises(HTTPException) as error:
        asyncio.run(remove(
            target_user_id=api.admin_id,
            user_id=api.principal(api.manager_id, company_role="admin"), csrf_valid=True,
            request=_request(api.manager_token),
        ))
    assert error.value.status_code == 403


def test_member_removal_uses_current_actor_role_after_ownership_transfer(tenant_user_api):
    api = tenant_user_api
    api.connection.execute(
        "UPDATE organization_memberships SET company_role='admin' WHERE organization_id=%s AND user_id=%s",
        (api.org_a, api.owner_id),
    )
    remove = api.endpoint("POST", "/api/users/{target_user_id}/remove")
    with pytest.raises(HTTPException) as error:
        asyncio.run(remove(
            target_user_id=api.admin_id,
            user_id=api.principal(api.owner_id, company_role="owner"), csrf_valid=True,
            request=_request(api.owner_token),
        ))
    assert error.value.status_code == 403
    assert api.connection.execute(
        "SELECT count(*) AS count FROM organization_memberships WHERE user_id=%s", (api.admin_id,)
    ).fetchone()["count"] == 1


def test_admin_cannot_modify_owner_or_admin_membership(tenant_user_api):
    from backend.schemas.users import UpdateUserRequest

    api = tenant_user_api
    update = api.endpoint("PUT", "/api/users/{target_user_id}")
    for target_user_id in (api.owner_id, api.admin_id):
        with pytest.raises(HTTPException) as error:
            asyncio.run(update(
                target_user_id=target_user_id,
                request_data=UpdateUserRequest(name="Changed"),
                user_id=api.principal(api.admin_id, company_role="admin"), csrf_valid=True,
                request=_request(api.admin_token),
            ))
        assert error.value.status_code == 403


def test_manager_cannot_manage_users(tenant_user_api):
    api = tenant_user_api
    get_users = api.endpoint("GET", "/api/users")
    with pytest.raises(HTTPException) as error:
        asyncio.run(get_users(
            include_archived=False,
            user_id=api.principal(api.manager_id, company_role="manager"),
            request=_request(api.manager_token),
        ))
    assert error.value.status_code == 403
