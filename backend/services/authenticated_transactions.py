"""Own authenticated record writes, including validation under the writer lock."""
from contextlib import contextmanager
from .session_access import require_session
from .stock_transactions import write_stock_transaction
from .principals import AuthenticatedPrincipal

GENERIC_BUSY_DETAIL = 'Database is busy; no changes saved. Try again'


@contextmanager
def authenticated_write_transaction(get_connection, *, user_id: int | AuthenticatedPrincipal,
                                    session_token: str | None,
                                    busy_detail: str = GENERIC_BUSY_DETAIL):
    import psycopg

    from .tenant_context import authenticated_tenant_transaction

    connection = get_connection()
    if isinstance(connection, psycopg.Connection):
        expected_user_id = (
            user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
        )
        with authenticated_tenant_transaction(
            lambda: connection,
            session_token=session_token,
            expected_user_id=expected_user_id,
        ) as (conn, _principal):
            yield conn
        return
    with write_stock_transaction(lambda: connection, busy_detail=busy_detail) as conn:
        require_session(conn, session_token, expected_user_id=user_id)
        yield conn
