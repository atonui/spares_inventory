"""Authenticated transactions for global account data with no tenant scope."""

from contextlib import contextmanager

from backend.database_sql import is_postgres
from backend.postgres_database import postgres_transaction
from backend.services.principals import AuthenticatedPrincipal, resolve_principal
from backend.services.session_access import require_session
from backend.services.stock_transactions import write_stock_transaction


@contextmanager
def authenticated_account_transaction(
    get_connection,
    *,
    principal_or_user: int | AuthenticatedPrincipal,
    session_token: str | None,
):
    """Revalidate one account session without requiring a company membership."""
    conn = get_connection()
    if is_postgres(conn):
        expected_user_id = (
            principal_or_user.user_id
            if isinstance(principal_or_user, AuthenticatedPrincipal)
            else principal_or_user
        )
        try:
            with postgres_transaction(conn):
                # Account operations must not inherit tenant or prior account
                # scopes if a connection factory ever starts reusing sessions.
                conn.execute("SELECT set_config('app.organization_id', '', true)")
                conn.execute("SELECT set_config('app.email_change_user_id', '', true)")
                conn.execute("SELECT set_config('app.email_change_token_hash', '', true)")
                principal = resolve_principal(conn, session_token)
                if principal.user_id != expected_user_id:
                    from fastapi import HTTPException

                    raise HTTPException(status_code=401, detail="Invalid or expired session")
                # The caller needs the scoped connection; principal revalidation
                # above is an authorization check, not part of the context value.
                yield conn
        finally:
            conn.close()
        return

    with write_stock_transaction(lambda: conn) as transaction:
        require_session(
            transaction,
            session_token,
            expected_user_id=(
                principal_or_user.user_id
                if isinstance(principal_or_user, AuthenticatedPrincipal)
                else principal_or_user
            ),
        )
        yield transaction, principal_or_user
