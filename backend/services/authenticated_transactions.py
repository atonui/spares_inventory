"""Own authenticated record writes inside a tenant-scoped PostgreSQL transaction."""
from contextlib import contextmanager

from .principals import AuthenticatedPrincipal

GENERIC_BUSY_DETAIL = 'Database is busy; no changes saved. Try again'


@contextmanager
def authenticated_write_transaction(get_connection, *, user_id: int | AuthenticatedPrincipal,
                                    session_token: str | None,
                                    busy_detail: str = GENERIC_BUSY_DETAIL):
    """Yield a connection scoped to the session's company.

    ``busy_detail`` is accepted for existing callers; PostgreSQL waits on row
    locks instead of failing fast, so it is not used.
    """
    from .tenant_context import authenticated_tenant_transaction

    expected_user_id = user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
    with authenticated_tenant_transaction(
        get_connection,
        session_token=session_token,
        expected_user_id=expected_user_id,
    ) as (conn, _principal):
        yield conn
