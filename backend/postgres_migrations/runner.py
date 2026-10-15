"""Checksummed PostgreSQL migration runner, separate from the SQLite chain."""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from . import registry
from backend.postgres_database import postgres_transaction


class PostgresMigrationError(RuntimeError):
    """The PostgreSQL schema is incomplete, modified, or cannot be upgraded safely."""


@dataclass(frozen=True)
class MigrationStatus:
    current_version: int
    applied_versions: tuple[int, ...]
    pending_versions: tuple[int, ...]


def _ledger_exists(conn: psycopg.Connection) -> bool:
    return conn.execute(
        "SELECT to_regclass('postgres_schema_migrations') AS table_name"
    ).fetchone()["table_name"] is not None


def _validate_history(conn: psycopg.Connection) -> tuple[int, ...]:
    migrations = tuple(registry.MIGRATIONS)
    try:
        registry.validate_registry(migrations)
    except ValueError as error:
        raise PostgresMigrationError(str(error)) from None
    if not _ledger_exists(conn):
        return ()
    rows = conn.execute(
        "SELECT version, name, checksum FROM postgres_schema_migrations ORDER BY version"
    ).fetchall()
    applied = tuple(row["version"] for row in rows)
    expected_prefix = tuple(m.version for m in migrations[: len(rows)])
    if applied != expected_prefix:
        raise PostgresMigrationError("PostgreSQL migration history is incomplete or unknown")
    for row, migration in zip(rows, migrations):
        if row["name"] != migration.name:
            raise PostgresMigrationError(f"PostgreSQL migration {migration.version} name changed")
        if row["checksum"] != migration.checksum:
            raise PostgresMigrationError(f"PostgreSQL migration {migration.version} checksum changed")
    return applied


def postgres_migration_status(conn: psycopg.Connection) -> MigrationStatus:
    applied = _validate_history(conn)
    pending = tuple(m.version for m in registry.MIGRATIONS[len(applied) :])
    return MigrationStatus(
        current_version=applied[-1] if applied else 0,
        applied_versions=applied,
        pending_versions=pending,
    )


def apply_postgres_migrations(conn: psycopg.Connection) -> MigrationStatus:
    with postgres_transaction(conn):
        conn.execute(
            """CREATE TABLE IF NOT EXISTS postgres_schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT to_char(timezone('UTC', now()), 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
            )"""
        )
    applied = _validate_history(conn)
    for migration in registry.MIGRATIONS[len(applied) :]:
        try:
            with postgres_transaction(conn):
                for statement in migration.statements:
                    conn.execute(statement)
                conn.execute(
                    """INSERT INTO postgres_schema_migrations(version, name, checksum)
                       VALUES (%s, %s, %s)""",
                    (migration.version, migration.name, migration.checksum),
                )
        except psycopg.Error as error:
            raise PostgresMigrationError(
                f"PostgreSQL migration {migration.version} ({migration.name}) failed"
            ) from error
        applied = (*applied, migration.version)
    return postgres_migration_status(conn)
