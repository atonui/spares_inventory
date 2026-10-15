"""Authenticate sessions and record request activity in one transaction."""

from .authenticated_transactions import GENERIC_BUSY_DETAIL
from .session_access import require_session
from .stock_transactions import write_stock_transaction


def authenticate_session(session_token, get_connection, *,
                         session_validator=require_session,
                         transaction_factory=write_stock_transaction,
                         busy_detail=GENERIC_BUSY_DETAIL):
    import psycopg

    from backend.postgres_database import postgres_transaction
    from backend.services.principals import resolve_principal
    from backend.temporal import serialize_instant, utc_now

    connection = get_connection()
    if isinstance(connection, psycopg.Connection):
        try:
            with postgres_transaction(connection):
                principal = resolve_principal(connection, session_token)
                connection.execute(
                    "UPDATE sessions SET last_activity = %s WHERE session_token = %s",
                    (serialize_instant(utc_now()), session_token),
                )
                return principal
        finally:
            connection.close()
    with transaction_factory(lambda: connection, busy_detail=busy_detail) as conn:
        session = session_validator(conn, session_token)
        conn.execute("UPDATE sessions SET last_activity=strftime('%Y-%m-%dT%H:%M:%f000Z','now') WHERE id=?",
                     (session['session_id'],))
        return session['user_id']
