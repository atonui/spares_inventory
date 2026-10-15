"""Organization name and timezone updates share tenant scope and revision."""

import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def organization_settings_api(postgres_schema):
    from datetime import timedelta

    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.organization_settings import create_organization_settings_router
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.principals import AuthenticatedPrincipal
    from backend.temporal import serialize_instant, utc_now

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)
    org_a = connection.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Tenant A','settings-a') RETURNING id"
    ).fetchone()["id"]
    org_b = connection.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Tenant B','settings-b') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_settings(organization_id,business_timezone) VALUES (%s,'Africa/Nairobi'),(%s,'Asia/Tokyo')",
        (org_a, org_b),
    )
    owner_id = connection.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('settings-owner@example.test','Owner','x') RETURNING id"
    ).fetchone()["id"]
    manager_id = connection.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('settings-manager@example.test','Manager','x') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,'owner'),(%s,%s,'manager')",
        (org_a, owner_id, org_a, manager_id),
    )
    owner_token = "settings-owner-token"
    manager_token = "settings-manager-token"
    for user_id, token in ((owner_id, owner_token), (manager_id, manager_token)):
        connection.execute(
            "INSERT INTO sessions(user_id,session_token,expires_at) VALUES (%s,%s,%s)",
            (user_id, token, serialize_instant(utc_now() + timedelta(hours=1))),
        )
    role = "settings_runtime_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL(
        "GRANT SELECT, UPDATE ON users, sessions, organization_memberships, organizations, organization_settings TO {}"
    ).format(sql.Identifier(role)))
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

    router = create_organization_settings_router(
        get_connection=get_connection,
        authenticated_writer=lambda principal, token: authenticated_write_transaction(
            get_connection, user_id=principal, session_token=token
        ),
        current_user=lambda: None,
        csrf_dependency=lambda: None,
    )
    def endpoint(method, path):
        return next(route.endpoint for route in router.routes if route.path == path and method in route.methods)
    def principal(user_id, role_name="owner"):
        return AuthenticatedPrincipal(user_id, org_a, role_name, False)

    yield SimpleNamespace(
        connection=connection, org_a=org_a, org_b=org_b, owner_id=owner_id,
        owner_token=owner_token, manager_id=manager_id, manager_token=manager_token,
        endpoint=endpoint, principal=principal,
    )
    connection.rollback()
    connection.execute("RESET ROLE")
    connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    connection.commit()


def _request(token):
    return SimpleNamespace(cookies={"session_token": token}, client=None, headers={})


def test_company_settings_update_is_revision_guarded(organization_settings_api):
    from backend.schemas.organization_settings import OrganizationSettingsUpdate

    api = organization_settings_api
    update = api.endpoint("PUT", "/api/organization/settings")
    changed = asyncio.run(update(
        body=OrganizationSettingsUpdate(
            name="New Name", business_timezone="Europe/London", expected_revision=1
        ),
        request=_request(api.owner_token), user_id=api.principal(api.owner_id), csrf_valid=True,
    ))
    assert changed["name"] == "New Name"
    assert changed["business_timezone"] == "Europe/London"
    assert changed["revision"] == 2
    with pytest.raises(HTTPException) as error:
        asyncio.run(update(
            body=OrganizationSettingsUpdate(
                name="Stale", business_timezone="Asia/Tokyo", expected_revision=1
            ),
            request=_request(api.owner_token), user_id=api.principal(api.owner_id), csrf_valid=True,
        ))
    assert error.value.status_code == 409


def test_company_settings_are_isolated_between_organizations(organization_settings_api):
    from backend.schemas.organization_settings import OrganizationSettingsUpdate

    api = organization_settings_api
    update = api.endpoint("PUT", "/api/organization/settings")
    asyncio.run(update(
        body=OrganizationSettingsUpdate(
            name="Changed A", business_timezone="America/New_York", expected_revision=1
        ),
        request=_request(api.owner_token), user_id=api.principal(api.owner_id), csrf_valid=True,
    ))
    other = api.connection.execute(
        "SELECT o.name,s.business_timezone,s.revision FROM organizations o "
        "JOIN organization_settings s ON s.organization_id=o.id WHERE o.id=%s",
        (api.org_b,),
    ).fetchone()
    assert other == {"name": "Tenant B", "business_timezone": "Asia/Tokyo", "revision": 1}


def test_manager_cannot_manage_settings(organization_settings_api):
    from backend.schemas.organization_settings import OrganizationSettingsUpdate

    api = organization_settings_api
    update = api.endpoint("PUT", "/api/organization/settings")
    with pytest.raises(HTTPException) as error:
        asyncio.run(update(
            body=OrganizationSettingsUpdate(
                name="Denied", business_timezone="Africa/Nairobi", expected_revision=1
            ),
            request=_request(api.manager_token),
            user_id=api.principal(api.manager_id, "manager"), csrf_valid=True,
        ))
    assert error.value.status_code == 403


def test_owner_transfer_keeps_exactly_one_active_owner(organization_settings_api):
    from backend.schemas.organization_settings import OwnerTransferRequest

    api = organization_settings_api
    transfer = api.endpoint("POST", "/api/organization/owner-transfer")
    result = asyncio.run(transfer(
        body=OwnerTransferRequest(target_user_id=api.manager_id),
        request=_request(api.owner_token), user_id=api.principal(api.owner_id), csrf_valid=True,
    ))
    owners = api.connection.execute(
        "SELECT user_id FROM organization_memberships WHERE organization_id=%s "
        "AND company_role='owner' AND is_active=TRUE",
        (api.org_a,),
    ).fetchall()
    assert result["owner_user_id"] == api.manager_id
    assert owners == [{"user_id": api.manager_id}]
    assert api.connection.execute(
        "SELECT company_role FROM organization_memberships WHERE user_id=%s", (api.owner_id,)
    ).fetchone()["company_role"] == "admin"


def test_settings_schema_rejects_blank_name_and_unknown_timezone():
    from pydantic import ValidationError

    from backend.schemas.organization_settings import OrganizationSettingsUpdate

    with pytest.raises(ValidationError):
        OrganizationSettingsUpdate(name="  ", business_timezone="Africa/Nairobi", expected_revision=1)
    with pytest.raises(ValidationError):
        OrganizationSettingsUpdate(name="Company", business_timezone="Mars/Olympus", expected_revision=1)
