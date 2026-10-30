"""Company invitation routes derive tenant authority from the session."""

import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql
from cryptography.fernet import Fernet

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def invitation_api(postgres_schema):
    from datetime import timedelta

    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.routes.invitations import create_invitation_router
    from backend.services.authenticated_transactions import authenticated_write_transaction
    from backend.services.principals import AuthenticatedPrincipal
    from backend.temporal import serialize_instant, utc_now
    from backend.services.session_credentials import hash_session_credential

    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    org_id = admin.execute(
        "INSERT INTO organizations(name,slug) VALUES ('Route Tenant',%s) RETURNING id",
        ("route-invite-" + uuid4().hex,),
    ).fetchone()["id"]
    admin.execute("INSERT INTO organization_settings(organization_id) VALUES (%s)", (org_id,))
    identities = {}
    for email, role in (("owner@example.test", "owner"), ("admin@example.test", "admin"),
                        ("manager@example.test", "manager")):
        user_id = admin.execute(
            "INSERT INTO users(email,name,password_hash) VALUES (%s,%s,'hash') RETURNING id",
            (email, role),
        ).fetchone()["id"]
        token = "token-" + uuid4().hex
        admin.execute(
            "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
            (org_id, user_id, role),
        )
        admin.execute(
            "INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)",
            (user_id, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
        )
        identities[role] = (user_id, token)

    runtime_role = "invite_route_" + uuid4().hex
    admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(runtime_role)
    ))
    for table in ("users", "sessions", "organization_memberships", "organizations", "platform_admins"):
        admin.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(
            sql.Identifier(table), sql.Identifier(runtime_role)
        ))
    admin.execute(sql.SQL(
        "GRANT SELECT, INSERT, UPDATE ON organization_invitations TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT INSERT (organization_id, message_type, recipient_email, encrypted_payload, idempotency_key), "
        "SELECT (id, idempotency_key), UPDATE (idempotency_key) ON mail_outbox TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT SELECT ON platform_mail_outbox_counts TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL(
        "GRANT USAGE, SELECT ON SEQUENCE organization_invitations_id_seq, mail_outbox_id_seq TO {}"
    ).format(sql.Identifier(runtime_role)))
    admin.commit()

    def get_connection():
        conn = psycopg.connect(os.environ["TEST_DATABASE_URL"], row_factory=psycopg.rows.dict_row)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(runtime_role)))
        conn.commit()
        return conn

    router = create_invitation_router(
        get_connection=get_connection,
        authenticated_writer=lambda principal, token: authenticated_write_transaction(
            get_connection, user_id=principal, session_token=token
        ),
        current_user=lambda: None, csrf_dependency=lambda: None,
        authenticated_csrf_dependency=lambda: None,
        password_hash=lambda value: "hash:" + value,
        password_verify=lambda plain, hashed: hashed == "hash:" + plain,
        encryption_key=Fernet.generate_key().decode(),
        frontend_url="https://inventory.example.test", limiter=None,
    )

    def endpoint(method, path):
        return next(route.endpoint for route in router.routes if route.path == path and method in route.methods)

    def principal(role):
        user_id, _token = identities[role]
        return AuthenticatedPrincipal(user_id, org_id, role, False)

    def request(role):
        return SimpleNamespace(cookies={"session_token": identities[role][1]})

    yield SimpleNamespace(
        admin=admin, org_id=org_id, endpoint=endpoint, principal=principal,
        request=request, identities=identities,
    )
    admin.rollback()
    admin.execute("RESET ROLE")
    admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(runtime_role)))
    admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(runtime_role)))
    admin.commit()


def test_owner_can_invite_admin_without_returning_token(invitation_api):
    from backend.schemas.invitations import InvitationCreateRequest

    api = invitation_api
    create = api.endpoint("POST", "/api/users/invitations")
    result = asyncio.run(create(
        body=InvitationCreateRequest(email="person@example.com", role="admin"),
        request=api.request("owner"), user_id=api.principal("owner"), csrf_valid=True,
    ))
    assert result["success"] is True
    assert set(result["invitation"]) == {"id", "email", "role", "created_at", "expires_at"}
    assert api.admin.execute("SELECT count(*) AS n FROM mail_outbox").fetchone()["n"] == 1


def test_company_admin_cannot_invite_another_admin(invitation_api):
    from backend.schemas.invitations import InvitationCreateRequest

    api = invitation_api
    create = api.endpoint("POST", "/api/users/invitations")
    with pytest.raises(HTTPException) as error:
        asyncio.run(create(
            body=InvitationCreateRequest(email="person@example.com", role="admin"),
            request=api.request("admin"), user_id=api.principal("admin"), csrf_valid=True,
        ))
    assert error.value.status_code == 403
    assert api.admin.execute("SELECT count(*) AS n FROM organization_invitations").fetchone()["n"] == 0


def test_manager_cannot_list_invitations(invitation_api):
    api = invitation_api
    listing = api.endpoint("GET", "/api/users/invitations")
    with pytest.raises(HTTPException) as error:
        asyncio.run(listing(request=api.request("manager"), user_id=api.principal("manager")))
    assert error.value.status_code == 403


def test_suspended_organization_cannot_accept_pending_invitation(invitation_api):
    from backend.schemas.invitations import InvitationAcceptRequest

    api = invitation_api
    api.admin.execute("UPDATE organizations SET is_active = FALSE WHERE id = %s", (api.org_id,))
    api.admin.commit()
    accept = api.endpoint("POST", "/api/invitations/accept")
    with pytest.raises(HTTPException) as error:
        asyncio.run(accept(
            body=InvitationAcceptRequest(
                organization_id=str(api.org_id), token="pending-token", name="Invitee",
                password="correct-password",
            ),
            request=SimpleNamespace(cookies={}), csrf_valid=True,
        ))
    assert error.value.status_code == 400
    assert api.admin.execute("SELECT count(*) AS n FROM organization_memberships").fetchone()["n"] == 3



def test_invitation_list_only_returns_active_unexpired_rows(invitation_api):
    from backend.temporal import serialize_instant, utc_now

    api = invitation_api
    invited_by = api.identities["owner"][0]
    now = utc_now()
    future = serialize_instant(now + __import__("datetime").timedelta(days=1))
    from datetime import timedelta\n    future = serialize_instant(now + timedelta(days=1))\n    past = serialize_instant(now - timedelta(days=1))
    current = serialize_instant(now)

    rows = (
        ("active@example.test", future, None, None),
        ("canceled@example.test", future, None, current),
        ("expired@example.test", past, None, None),
        ("accepted@example.test", future, current, None),
    )
    for email, expires_at, accepted_at, canceled_at in rows:
        api.admin.execute(
            """INSERT INTO organization_invitations
               (organization_id, email_normalized, company_role, token_hash, invited_by,
                expires_at, accepted_at, canceled_at)
               VALUES (%s, %s, 'engineer', %s, %s, %s, %s, %s)""",
            (api.org_id, email, uuid4().hex, invited_by, expires_at, accepted_at, canceled_at),
        )

    listing = api.endpoint("GET", "/api/users/invitations")
    result = asyncio.run(listing(request=api.request("owner"), user_id=api.principal("owner")))

    assert [row["email"] for row in result] == ["active@example.test"]
