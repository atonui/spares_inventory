"""Runtime telemetry grants must permit inserts and deny reads or tampering."""

from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.errors import InsufficientPrivilege

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_runtime_security_event_grants_remove_defaults_and_allow_curated_inserts(
    postgres_schema,
):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.security_events import record_security_event
    from backend.security_event_grants import grant_security_event_writer

    conn, schema = postgres_schema
    apply_postgres_migrations(conn)
    role = "security_writer_" + uuid4().hex
    conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    conn.execute(
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(schema), sql.Identifier(role)
        )
    )
    # Simulate the broad default grants from the cutover runbook, plus column grants.
    conn.execute(
        sql.SQL("GRANT ALL ON platform_security_events TO {}").format(
            sql.Identifier(role)
        )
    )
    conn.execute(
        sql.SQL(
            "GRANT UPDATE (event), SELECT (details) ON platform_security_events TO {}"
        ).format(sql.Identifier(role))
    )
    conn.execute(
        sql.SQL("GRANT ALL ON SEQUENCE platform_security_events_id_seq TO {}").format(
            sql.Identifier(role)
        )
    )
    conn.commit()
    try:
        grant_security_event_writer(conn, runtime_role=role, schema=schema)
        conn.commit()
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        record_security_event(
            conn,
            event="login_failed",
            outcome="failure",
            details={"account_match": False, "email": "private@example.test"},
        )
        conn.commit()
        for query in [
            "SELECT * FROM platform_security_events",
            "SELECT details FROM platform_security_events",
            "UPDATE platform_security_events SET event='login_failed'",
            "DELETE FROM platform_security_events",
            "TRUNCATE platform_security_events",
            "INSERT INTO platform_security_events (id,event,outcome,request_id) VALUES (100,'login_failed','failure',gen_random_uuid())",
        ]:
            with pytest.raises(InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(query)
        conn.execute("RESET ROLE")
        row = conn.execute(
            "SELECT event,details FROM platform_security_events"
        ).fetchone()
        assert row == {"event": "login_failed", "details": {"account_match": False}}
        # Rollback must discard the writer's pending event.
        conn.commit()
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        record_security_event(conn, event="login_failed", outcome="failure")
        conn.rollback()
        conn.execute("RESET ROLE")
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM platform_security_events"
            ).fetchone()["n"]
            == 1
        )
    finally:
        conn.rollback()
        conn.execute("RESET ROLE")
        conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.commit()


@pytest.mark.parametrize("privileged_path", ["set_role", "table_owner", "schema_owner"])
def test_grant_command_refuses_privileged_runtime_and_preserves_existing_grants(
    postgres_schema, privileged_path
):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.security_event_grants import grant_security_event_writer

    conn, schema = postgres_schema
    apply_postgres_migrations(conn)
    runtime = "security_runtime_" + uuid4().hex
    elevated = "security_elevated_" + uuid4().hex
    conn.execute(
        sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT").format(sql.Identifier(runtime))
    )
    conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(elevated)))
    conn.execute(
        sql.SQL("GRANT USAGE, CREATE ON SCHEMA {} TO {}, {}").format(
            sql.Identifier(schema), sql.Identifier(runtime), sql.Identifier(elevated)
        )
    )
    conn.execute(
        sql.SQL("GRANT SELECT ON platform_security_events TO {}").format(
            sql.Identifier(runtime)
        )
    )
    if privileged_path == "set_role":
        conn.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(elevated), sql.Identifier(runtime)
            )
        )
        conn.execute(
            sql.SQL("GRANT SELECT, UPDATE ON platform_security_events TO {}").format(
                sql.Identifier(elevated)
            )
        )
    elif privileged_path == "table_owner":
        conn.execute(
            sql.SQL("ALTER TABLE platform_security_events OWNER TO {}").format(
                sql.Identifier(runtime)
            )
        )
    else:
        conn.execute(
            sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(
                sql.Identifier(schema), sql.Identifier(runtime)
            )
        )
    conn.commit()
    try:
        with pytest.raises(ValueError, match="privileg|owner"):
            grant_security_event_writer(conn, runtime_role=runtime, schema=schema)
        # A refusal must not partially revoke the role's original privileges.
        assert (
            conn.execute(
                "SELECT has_table_privilege(%s,%s,%s) AS allowed",
                (
                    runtime,
                    sql.Identifier(schema, "platform_security_events").as_string(conn),
                    "SELECT",
                ),
            ).fetchone()["allowed"]
            is True
        )
    finally:
        conn.rollback()
        conn.execute("RESET ROLE")
        # Return ownership before removing these disposable roles.
        owner = conn.execute("SELECT current_user AS name").fetchone()["name"]
        conn.execute(
            sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(
                sql.Identifier(schema), sql.Identifier(owner)
            )
        )
        conn.execute(
            sql.SQL("ALTER TABLE platform_security_events OWNER TO {}").format(
                sql.Identifier(owner)
            )
        )
        for role in (runtime, elevated):
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.commit()
