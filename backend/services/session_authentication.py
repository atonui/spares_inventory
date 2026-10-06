"""Authenticate sessions and record request activity in one transaction."""

from .authenticated_transactions import GENERIC_BUSY_DETAIL
from .session_access import require_session
from .stock_transactions import write_stock_transaction


def authenticate_session(session_token, get_connection, *,
                         session_validator=require_session,
                         transaction_factory=write_stock_transaction,
                         busy_detail=GENERIC_BUSY_DETAIL):
    with transaction_factory(get_connection, busy_detail=busy_detail) as conn:
        session = session_validator(conn, session_token)
        conn.execute('UPDATE sessions SET last_activity=CURRENT_TIMESTAMP WHERE id=?',
                     (session['session_id'],))
        return session['user_id']
