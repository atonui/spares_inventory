"""Own authenticated record writes, including validation under the writer lock."""
from contextlib import contextmanager
from .session_access import require_session
from .stock_transactions import write_stock_transaction

GENERIC_BUSY_DETAIL = 'Database is busy; no changes saved. Try again'


@contextmanager
def authenticated_write_transaction(get_connection, *, user_id: int,
                                    session_token: str | None,
                                    busy_detail: str = GENERIC_BUSY_DETAIL):
    with write_stock_transaction(get_connection, busy_detail=busy_detail) as conn:
        require_session(conn, session_token, expected_user_id=user_id)
        yield conn
