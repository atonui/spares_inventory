"""Transactions for platform administration without implicit tenant context."""

from contextlib import contextmanager

from backend.postgres_database import postgres_transaction
from .authorization import require_platform_admin
from .principals import AuthenticatedPrincipal, resolve_principal


@contextmanager
def authenticated_platform_transaction(
    get_connection,
    *,
    session_token: str | None,
    expected_user_id: int | None = None,
    readonly: bool = False,
):
    """Validate a platform administrator session without setting organization RLS state."""
    conn = get_connection()
    try:
        with postgres_transaction(conn, readonly=readonly):
            # A platform transaction never inherits tenant scope from a reused connection.
            conn.execute("SELECT set_config('app.organization_id', '', true)")
            principal: AuthenticatedPrincipal = resolve_principal(conn, session_token)
            require_platform_admin(principal)
            if expected_user_id is not None and principal.user_id != expected_user_id:
                from fastapi import HTTPException

                raise HTTPException(status_code=401, detail="Invalid or expired session")
            yield conn, principal
    finally:
        conn.close()
