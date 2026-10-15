"""Transaction-local tenant context for PostgreSQL row-level security."""

from contextlib import contextmanager
from uuid import UUID

import psycopg
from fastapi import HTTPException
from psycopg.pq import TransactionStatus

from backend.postgres_database import postgres_transaction
from .principals import AuthenticatedPrincipal, resolve_principal


def require_company_principal(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    if principal.organization_id is None or principal.company_role is None:
        raise HTTPException(status_code=403, detail="Company membership required")
    return principal


def set_tenant_context(conn: psycopg.Connection, organization_id: UUID) -> None:
    """Set the RLS organization only inside the current transaction."""
    if conn.info.transaction_status == TransactionStatus.IDLE:
        raise ValueError("Tenant context requires an active PostgreSQL transaction")
    try:
        tenant_id = UUID(str(organization_id))
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Invalid organization identifier") from None
    conn.execute(
        "SELECT set_config('app.organization_id', %s, true)",
        (str(tenant_id),),
    )


@contextmanager
def authenticated_tenant_transaction(
    get_connection,
    *,
    session_token: str | None,
    expected_user_id: int | None = None,
    readonly: bool = False,
):
    """Validate the session and set its server-resolved company before tenant SQL."""
    conn = get_connection()
    try:
        with postgres_transaction(conn, readonly=readonly):
            principal = resolve_principal(conn, session_token)
            require_company_principal(principal)
            if expected_user_id is not None and principal.user_id != expected_user_id:
                raise HTTPException(status_code=401, detail="Invalid or expired session")
            set_tenant_context(conn, principal.organization_id)
            yield conn, principal
    finally:
        conn.close()
