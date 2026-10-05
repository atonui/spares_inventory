"""Own the connection and transaction for atomic stock writes."""
import sqlite3
from collections.abc import Callable
from contextlib import contextmanager
from fastapi import HTTPException


@contextmanager
def write_stock_transaction(get_connection: Callable[[], sqlite3.Connection]):
    conn = get_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        yield conn
        conn.commit()
    except Exception as exc:
        try:
            conn.rollback()
        except sqlite3.ProgrammingError:
            # Preserve the original error if a legacy caller already closed it.
            pass
        if isinstance(exc, sqlite3.OperationalError) and any(word in str(exc).lower() for word in ('locked', 'busy')):
            raise HTTPException(status_code=409, detail='Stock is busy; no changes saved. Try again') from exc
        raise
    finally:
        conn.close()
