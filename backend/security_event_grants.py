"""Explicit deployment-time privileges for global security-event access."""

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
PLATFORM_READER_COLUMNS = ("id", "actor_user_id", "event", "outcome", "details", "created_at")


def grant_security_event_writer(
    conn, *, runtime_role: str, schema: str = "public", platform_reader: bool = False
) -> None:
    """Replace broad direct/default grants atomically; reject inherited privileges.

    Run as the migration owner after v21. An idle connection gets a committed
    transaction; an existing caller transaction gets a savepoint.
    Set platform_reader only for the web runtime after the platform-authorized
    reader has been deployed. That mode adds column-level SELECT for the fields
    required by the API while continuing to exclude IP, user-agent, and request ID.
    """
    table = sql.Identifier(schema, "platform_security_events")
    sequence = sql.Identifier(schema, "platform_security_events_id_seq")
    role = sql.Identifier(runtime_role)
    with conn.transaction():
        with conn.cursor(row_factory=tuple_row) as cursor:
            cursor.execute(
                """SELECT oid, rolname FROM pg_catalog.pg_roles
                   WHERE pg_has_role(%s, oid, 'USAGE') OR pg_has_role(%s, oid, 'SET')""",
                (runtime_role, runtime_role),
            )
            identities = cursor.fetchall()
            cursor.execute(
                """SELECT relowner FROM pg_catalog.pg_class
                   WHERE oid IN (%s::regclass, %s::regclass)
                   UNION SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname = %s""",
                (table.as_string(conn), sequence.as_string(conn), schema),
            )
            owners = {row[0] for row in cursor.fetchall()}
            if any(role_id in owners for role_id, _name in identities):
                raise ValueError(
                    "Runtime role has security-event object ownership privileges"
                )
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
        if platform_reader:
            conn.execute(
                sql.SQL("GRANT SELECT ({}) ON TABLE {} TO {}").format(
                    sql.SQL(", ").join(map(sql.Identifier, PLATFORM_READER_COLUMNS)),
                    table,
                    role,
                )
            )
        qualified_table = table.as_string(conn)
        with conn.cursor(row_factory=tuple_row) as cursor:
            for _role_id, identity in identities:
                _verify_writer_identity(
                    cursor, identity, qualified_table, sequence.as_string(conn),
                    allowed_reader_columns=PLATFORM_READER_COLUMNS if platform_reader else (),
                )


def _verify_writer_identity(
    cursor, identity, qualified_table, qualified_sequence, *, allowed_reader_columns=()
):
    """Check immediate and SET ROLE privileges after replacing direct ACLs."""
    for privilege in (
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    ):
        cursor.execute(
            "SELECT has_table_privilege(%s, %s, %s)",
            (identity, qualified_table, privilege),
        )
        if cursor.fetchone()[0]:
            raise ValueError("Runtime role retains excessive security-event privileges")
    for privilege in ("SELECT", "UPDATE", "REFERENCES"):
        for column in ALL_COLUMNS:
            cursor.execute(
                "SELECT has_column_privilege(%s, %s, %s, %s)",
                (identity, qualified_table, column, privilege),
            )
            if cursor.fetchone()[0] and not (
                privilege == "SELECT" and column in allowed_reader_columns
            ):
                raise ValueError(
                    "Runtime role retains excessive security-event column privileges"
                )
    for column in ("id", "created_at"):
        cursor.execute(
            "SELECT has_column_privilege(%s, %s, %s, %s)",
            (identity, qualified_table, column, "INSERT"),
        )
        if cursor.fetchone()[0]:
            raise ValueError(
                "Runtime role can override server-generated event metadata"
            )
    for privilege in ("SELECT", "UPDATE"):
        cursor.execute(
            "SELECT has_sequence_privilege(%s, %s, %s)",
            (identity, qualified_sequence, privilege),
        )
        if cursor.fetchone()[0]:
            raise ValueError("Runtime role retains excessive event-sequence privileges")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-role", required=True)
    parser.add_argument("--schema", default="public")
    parser.add_argument(
        "--platform-reader", action="store_true",
        help="also grant the API's safe, column-level security-event read access",
    )
    args = parser.parse_args()
    dsn = os.environ.get("MIGRATION_DATABASE_URL")
    if not dsn:
        parser.error("MIGRATION_DATABASE_URL must be configured")
    with psycopg.connect(dsn) as conn:
        grant_security_event_writer(
            conn, runtime_role=args.runtime_role, schema=args.schema,
            platform_reader=args.platform_reader,
        )
    print("Security-event writer and reader grants applied" if args.platform_reader else "Security-event writer grants applied")


if __name__ == "__main__":
    main()
