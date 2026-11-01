"""Explicit deployment-time privileges for the global security-event writer."""

from __future__ import annotations

import argparse
import os

import psycopg
from psycopg import sql
from psycopg.rows import tuple_row

WRITER_COLUMNS = (
    "actor_user_id",
    "event",
    "outcome",
    "request_id",
    "ip_address",
    "user_agent",
    "details",
)
ALL_COLUMNS = ("id", *WRITER_COLUMNS, "created_at")


def grant_security_event_writer(
    conn, *, runtime_role: str, schema: str = "public"
) -> None:
    """Replace broad direct/default grants atomically; reject inherited privileges.

    Run as the migration owner after v21. No commit is performed for the caller.
    A later platform-authorized reader requires its own explicit access design.
    """
    table = sql.Identifier(schema, "platform_security_events")
    sequence = sql.Identifier(schema, "platform_security_events_id_seq")
    role = sql.Identifier(runtime_role)
    with conn.transaction():
        for grantee in (role, sql.SQL("PUBLIC")):
            conn.execute(
                sql.SQL("REVOKE ALL PRIVILEGES ON TABLE {} FROM {}").format(
                    table, grantee
                )
            )
            # Table-level REVOKE does not remove separate column-level grants.
            conn.execute(
                sql.SQL("REVOKE ALL PRIVILEGES ({}) ON TABLE {} FROM {}").format(
                    sql.SQL(", ").join(map(sql.Identifier, ALL_COLUMNS)),
                    table,
                    grantee,
                )
            )
            conn.execute(
                sql.SQL("REVOKE ALL PRIVILEGES ON SEQUENCE {} FROM {}").format(
                    sequence, grantee
                )
            )
        conn.execute(
            sql.SQL("GRANT INSERT ({}) ON TABLE {} TO {}").format(
                sql.SQL(", ").join(map(sql.Identifier, WRITER_COLUMNS)),
                table,
                role,
            )
        )
        conn.execute(sql.SQL("GRANT USAGE ON SEQUENCE {} TO {}").format(sequence, role))
        qualified_table = table.as_string(conn)
        with conn.cursor(row_factory=tuple_row) as cursor:
            for privilege in (
                "SELECT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
            ):
                cursor.execute(
                    "SELECT has_table_privilege(%s, %s, %s)",
                    (runtime_role, qualified_table, privilege),
                )
                if cursor.fetchone()[0]:
                    raise ValueError(
                        "Runtime role retains excessive security-event privileges"
                    )
            for privilege in ("SELECT", "UPDATE", "REFERENCES"):
                cursor.execute(
                    "SELECT has_any_column_privilege(%s, %s, %s)",
                    (runtime_role, qualified_table, privilege),
                )
                if cursor.fetchone()[0]:
                    raise ValueError(
                        "Runtime role retains excessive security-event column privileges"
                    )
            for column in ("id", "created_at"):
                cursor.execute(
                    "SELECT has_column_privilege(%s, %s, %s, %s)",
                    (runtime_role, qualified_table, column, "INSERT"),
                )
                if cursor.fetchone()[0]:
                    raise ValueError(
                        "Runtime role can override server-generated event metadata"
                    )
            for privilege in ("SELECT", "UPDATE"):
                cursor.execute(
                    "SELECT has_sequence_privilege(%s, %s, %s)",
                    (runtime_role, sequence.as_string(conn), privilege),
                )
                if cursor.fetchone()[0]:
                    raise ValueError(
                        "Runtime role retains excessive event-sequence privileges"
                    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-role", required=True)
    parser.add_argument("--schema", default="public")
    args = parser.parse_args()
    dsn = os.environ.get("MIGRATION_DATABASE_URL")
    if not dsn:
        parser.error("MIGRATION_DATABASE_URL must be configured")
    with psycopg.connect(dsn) as conn:
        grant_security_event_writer(
            conn, runtime_role=args.runtime_role, schema=args.schema
        )
    print("Security-event writer grants applied")


if __name__ == "__main__":
    main()
