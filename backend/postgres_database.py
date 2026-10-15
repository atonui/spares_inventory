"""Small Psycopg boundary for explicit PostgreSQL transactions."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row


CONNECT_TIMEOUT_SECONDS = 5


def connect_postgres(dsn: str, *, readonly: bool = False) -> psycopg.Connection:
    """Connect with mapping rows and safe public errors; never log connection details."""
    connection = None
    try:
        connection = psycopg.connect(
            dsn,
            row_factory=dict_row,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
        )
        if readonly:
            connection.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            connection.commit()
        return connection
    except psycopg.Error:
        if connection is not None:
            connection.close()
        raise RuntimeError("Unable to connect to PostgreSQL database") from None


@contextmanager
def postgres_transaction(
    connection: psycopg.Connection,
    *,
    readonly: bool = False,
) -> Iterator[psycopg.Connection]:
    """Commit on success and roll back on error; tenant context is set elsewhere."""
    try:
        if readonly:
            connection.execute("SET TRANSACTION READ ONLY")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
