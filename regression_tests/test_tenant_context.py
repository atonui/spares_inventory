"""Authenticated principal resolution and transaction-local tenant context."""

from datetime import timedelta
import os
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from fastapi import HTTPException
from psycopg.pq import TransactionStatus
from psycopg import sql

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture(autouse=True)
def migrated_tenant_schema(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    apply_postgres_migrations(postgres_schema[0])


def seed_user(conn, *, role="engineer", platform_admin=False, membership=True, active=True):
    from backend.temporal import serialize_instant, utc_now

    org_id = conn.execute(
        "INSERT INTO organizations(name, slug) VALUES (%s, %s) RETURNING id",
        ("Tenant", f"tenant-{role}-{platform_admin}-{membership}-{active}"),
    ).fetchone()["id"]
    user_id = conn.execute(
        """INSERT INTO users(email, name, password_hash)
           VALUES (%s, %s, %s) RETURNING id""",
        (f"{org_id}@example.test", "Test User", "not-a-real-hash"),
    ).fetchone()["id"]
    if membership:
        conn.execute(
            """INSERT INTO organization_memberships(organization_id, user_id, company_role, is_active)
               VALUES (%s, %s, %s, %s)""",
            (org_id, user_id, role, active),
        )
    if platform_admin:
        conn.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (user_id,))
    session_token = f"token-{org_id}"
    conn.execute(
        """INSERT INTO sessions(user_id, session_token, expires_at)
           VALUES (%s, %s, %s)""",
        (user_id, session_token, serialize_instant(utc_now() + timedelta(hours=1))),
    )
    return org_id, user_id, session_token


def test_resolve_principal_uses_active_server_side_membership(postgres_schema):
    from backend.services.principals import AuthenticatedPrincipal, resolve_principal

    connection, _ = postgres_schema
    org_id, user_id, token = seed_user(connection, role="manager")

    with connection.transaction():
        principal = resolve_principal(connection, token)

    assert principal == AuthenticatedPrincipal(user_id, UUID(str(org_id)), "manager", False)


def test_resolve_principal_rejects_missing_and_expired_sessions(postgres_schema):
    from backend.services.principals import resolve_principal
    from backend.temporal import serialize_instant, utc_now

    connection, _ = postgres_schema
    with connection.transaction(), pytest.raises(HTTPException) as missing:
        resolve_principal(connection, "missing")
    assert missing.value.status_code == 401

    org_id, user_id, token = seed_user(connection)
    connection.execute(
        "UPDATE sessions SET expires_at = %s WHERE user_id = %s",
        (serialize_instant(utc_now() - timedelta(seconds=1)), user_id),
    )
    with connection.transaction(), pytest.raises(HTTPException) as expired:
        resolve_principal(connection, token)
    assert expired.value.status_code == 401


def test_non_platform_user_without_active_membership_is_denied(postgres_schema):
    from backend.services.principals import resolve_principal

    connection, _ = postgres_schema
    _, _, token = seed_user(connection, membership=False)

    with connection.transaction(), pytest.raises(HTTPException) as error:
        resolve_principal(connection, token)

    assert error.value.status_code == 403


def test_non_platform_user_with_inactive_membership_is_denied(postgres_schema):
    from backend.services.principals import resolve_principal

    connection, _ = postgres_schema
    _, _, token = seed_user(connection, active=False)

    with connection.transaction(), pytest.raises(HTTPException) as error:
        resolve_principal(connection, token)

    assert error.value.status_code == 403


def test_platform_admin_without_membership_has_no_company_context(postgres_schema):
    from backend.services.principals import resolve_principal
    from backend.services.tenant_context import require_company_principal

    connection, _ = postgres_schema
    _, user_id, token = seed_user(connection, platform_admin=True, membership=False)

    with connection.transaction():
        principal = resolve_principal(connection, token)

    assert principal.user_id == user_id
    assert principal.is_platform_admin is True
    assert principal.organization_id is None
    with pytest.raises(HTTPException) as error:
        require_company_principal(principal)
    assert error.value.status_code == 403


def test_company_context_rejects_platform_only_principals():
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.tenant_context import require_company_principal

    principal = AuthenticatedPrincipal(9, None, None, True)

    with pytest.raises(HTTPException) as error:
        require_company_principal(principal)

    assert error.value.status_code == 403


def test_set_tenant_context_requires_active_transaction():
    from backend.services.tenant_context import set_tenant_context

    connection = SimpleNamespace(
        info=SimpleNamespace(transaction_status=TransactionStatus.IDLE),
        execute=lambda *args: pytest.fail("must not set context outside a transaction"),
    )

    with pytest.raises(ValueError, match="active PostgreSQL transaction"):
        set_tenant_context(connection, UUID("00000000-0000-0000-0000-000000000001"))


def test_authenticate_session_returns_principal_for_postgres(postgres_schema):
    from backend.services.principals import AuthenticatedPrincipal
    from backend.services.session_authentication import authenticate_session

    connection, schema = postgres_schema
    org_id, user_id, token = seed_user(connection, role="engineer")
    connection.commit()

    def new_connection():
        conn = psycopg.connect(
            os.environ["TEST_DATABASE_URL"],
            row_factory=psycopg.rows.dict_row,
            connect_timeout=5,
        )
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.commit()
        return conn

    principal = authenticate_session(token, new_connection)

    assert principal == AuthenticatedPrincipal(
        user_id, UUID(str(org_id)), "engineer", False
    )
