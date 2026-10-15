"""Fixtures for isolated PostgreSQL integration tests."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row


def postgres_test_dsn() -> str:
    """Return the test DSN only when its target database is explicitly disposable."""
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        raise RuntimeError("TEST_DATABASE_URL must point to a disposable PostgreSQL test database")
    try:
        database = conninfo_to_dict(dsn).get("dbname")
    except psycopg.ProgrammingError:
        raise ValueError("TEST_DATABASE_URL must be a valid PostgreSQL connection string") from None
    if not database or not database.endswith("_test"):
        raise ValueError("TEST_DATABASE_URL database name must end in _test")
    return dsn


@pytest.fixture
def postgres_admin_connection():
    """Open an isolated test connection after checking its database name."""
    connection = psycopg.connect(
        postgres_test_dsn(), row_factory=dict_row, connect_timeout=5
    )
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def postgres_schema(postgres_admin_connection):
    """Give a test a private schema and remove it, including objects, afterward."""
    connection = postgres_admin_connection
    schema_name = f"test_{uuid4().hex}"
    connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name)))
    connection.execute("SELECT set_config('search_path', %s, false)", (schema_name,))
    connection.commit()
    try:
        yield connection, schema_name
    finally:
        connection.rollback()
        connection.execute("SELECT set_config('search_path', 'public', false)")
        connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name)))
        connection.commit()
