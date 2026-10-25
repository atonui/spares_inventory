"""Versioned PostgreSQL schema migration contracts."""

import pytest
import psycopg

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_password_reset_mail_migration_remains_registered_at_version_eight():
    from backend.postgres_migrations.registry import MIGRATIONS

    assert [(migration.version, migration.name) for migration in MIGRATIONS][-5] == (
        8,
        "password_reset_mail",
    )


def test_email_change_verification_migration_is_registered_with_account_schema():
    from backend.postgres_migrations.registry import MIGRATIONS

    migration = MIGRATIONS[-4]
    assert (migration.version, migration.name) == (9, "email_change_verification")
    sql = "\n".join(migration.statements)
    assert "CREATE TABLE email_change_requests" in sql
    assert "user_id BIGINT NOT NULL REFERENCES users(id)" in sql
    assert "proposed_email TEXT NOT NULL" in sql
    assert "token_hash TEXT NOT NULL" in sql
    assert "delivery_suppressed BOOLEAN NOT NULL DEFAULT FALSE" in sql
    assert "CREATE UNIQUE INDEX" in sql
    assert "lower(btrim(email))" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "email_change_request_account_scope" in sql
    assert "app.email_change_user_id" in sql
    assert "app.email_change_token_hash" in sql
    assert "organization_id" not in sql
    assert "UPDATE users SET email" not in sql


def test_mobile_pairing_migration_is_registered_with_token_scoped_rls():
    from backend.postgres_migrations.registry import MIGRATIONS

    migration = MIGRATIONS[-3]
    assert (migration.version, migration.name) == (10, "mobile_pairing")
    sql = "\n".join(migration.statements)
    assert "CREATE TABLE mobile_pairing_requests" in sql
    assert "qr_token_hash TEXT NOT NULL" in sql
    assert "claim_token_hash TEXT" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "app.mobile_pairing_user_id" in sql
    assert "app.mobile_pairing_qr_token_hash" in sql
    assert "app.mobile_pairing_claim_token_hash" in sql


def test_mobile_device_session_migration_tracks_revocable_paired_devices():
    from backend.postgres_migrations.registry import MIGRATIONS

    migration = MIGRATIONS[-2]
    assert (migration.version, migration.name) == (11, "mobile_device_sessions")
    sql = "\n".join(migration.statements)
    assert "CREATE TABLE mobile_device_sessions" in sql
    assert "session_id BIGINT NOT NULL UNIQUE REFERENCES sessions(id)" in sql
    assert "device_name TEXT NOT NULL" in sql
    assert "revoked_at TEXT" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "app.mobile_pairing_user_id" in sql


def test_mobile_stock_adjustment_migration_adds_a_unique_retry_key():
    from backend.postgres_migrations.registry import MIGRATIONS

    migration = MIGRATIONS[-1]
    assert (migration.version, migration.name) == (12, "mobile_stock_adjustments")
    sql = "\n".join(migration.statements)
    assert "ALTER TABLE movements ADD COLUMN client_operation_id TEXT" in sql
    assert "CREATE UNIQUE INDEX uq_movements_created_operation" in sql


def test_email_change_request_constraints_are_append_only_and_single_active(postgres_schema):
    from psycopg.errors import UniqueViolation

    from backend.postgres_migrations.runner import apply_postgres_migrations
    from datetime import timedelta
    from backend.temporal import serialize_instant, utc_now

    connection, _ = postgres_schema
    status = apply_postgres_migrations(connection)
    assert status.applied_versions == tuple(range(1, 13))
    assert status.pending_versions == ()

    user_id = connection.execute(
        "INSERT INTO users(email, name, password_hash) VALUES (%s, %s, %s) RETURNING id",
        ("CaseSensitive@example.test", "Case test", "unused"),
    ).fetchone()["id"]
    expiration = serialize_instant(utc_now() + timedelta(hours=1))
    connection.execute(
        "INSERT INTO email_change_requests(user_id, proposed_email, token_hash, expires_at) "
        "VALUES (%s, %s, %s, %s)",
        (user_id, "next@example.test", "token-hash-1", expiration),
    )
    with pytest.raises(UniqueViolation), connection.transaction():
        connection.execute(
            "INSERT INTO email_change_requests(user_id, proposed_email, token_hash, expires_at) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, "other@example.test", "token-hash-2", expiration),
        )
    with pytest.raises(UniqueViolation), connection.transaction():
        connection.execute(
            "INSERT INTO users(email, name, password_hash) VALUES (%s, %s, %s)",
            ("casesensitive@example.test", "Case collision", "unused"),
        )


def test_password_reset_outbox_message_type_is_supported(postgres_schema):
    from psycopg.errors import CheckViolation
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    status = apply_postgres_migrations(connection)
    assert status.applied_versions == tuple(range(1, 13))
    connection.execute(
        "INSERT INTO mail_outbox (message_type, recipient_email, encrypted_payload, idempotency_key) "
        "VALUES ('password_reset', 'person@example.test', 'ciphertext', 'password-reset-test')"
    )
    assert connection.execute(
        "SELECT organization_id, message_type FROM mail_outbox WHERE idempotency_key = 'password-reset-test'"
    ).fetchone() == {"organization_id": None, "message_type": "password_reset"}
    with pytest.raises(CheckViolation):
        connection.execute(
            "INSERT INTO mail_outbox (message_type, recipient_email, encrypted_payload, idempotency_key) "
            "VALUES ('unsupported', 'person@example.test', 'ciphertext', 'unsupported-test')"
        )


def test_mail_outbox_counts_view_is_one_row_with_only_integer_counts(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    empty = connection.execute(
        "SELECT pending, failed FROM platform_mail_outbox_counts"
    ).fetchall()
    assert empty == [{"pending": 0, "failed": 0}]

    connection.execute(
        """INSERT INTO mail_outbox
           (message_type, recipient_email, encrypted_payload, idempotency_key, status, sent_at)
           VALUES ('organization_invitation', 'a@example.test', 'cipher-a', 'a', 'pending', NULL),
                  ('organization_invitation', 'b@example.test', 'cipher-b', 'b', 'failed', NULL),
                  ('organization_invitation', 'c@example.test', 'cipher-c', 'c', 'sent', '2026-10-17T00:00:00Z')"""
    )
    counts = connection.execute(
        "SELECT pending, failed FROM platform_mail_outbox_counts"
    ).fetchall()
    columns = connection.execute(
        """SELECT column_name, data_type FROM information_schema.columns
           WHERE table_schema = current_schema()
             AND table_name = 'platform_mail_outbox_counts'
           ORDER BY ordinal_position"""
    ).fetchall()
    assert counts == [{"pending": 1, "failed": 1}]
    assert columns == [
        {"column_name": "pending", "data_type": "integer"},
        {"column_name": "failed", "data_type": "integer"},
    ]


def test_fresh_schema_applies_core_and_tenancy_migrations(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    status = apply_postgres_migrations(connection)

    assert status.applied_versions == tuple(range(1, 13))
    assert status.pending_versions == ()
    tenant_tables = {
        row["tablename"]
        for row in connection.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
        ).fetchall()
    }
    expected = {
        "stores",
        "store_types",
        "parts",
        "inventory",
        "work_orders",
        "movements",
        "stock_transfers",
        "equipment",
        "equipment_history",
        "activity_logs",
        "organization_settings",
        "company_announcements",
        "announcement_dismissals",
        "organization_invitations",
        "mobile_pairing_requests",
        "mobile_device_sessions",
    }
    assert expected <= tenant_tables
    columns = {
        (row["table_name"], row["column_name"])
        for row in connection.execute(
            """SELECT table_name, column_name FROM information_schema.columns
               WHERE table_schema = current_schema()"""
        ).fetchall()
    }
    assert all((table, "organization_id") in columns for table in expected)
    rls = {
        row["relname"]: (row["relrowsecurity"], row["relforcerowsecurity"])
        for row in connection.execute(
            """SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = current_schema() AND c.relkind = 'r'"""
        ).fetchall()
    }
    assert all(rls[table] == (True, False) for table in expected)
    policies = connection.execute(
        """SELECT tablename FROM pg_policies WHERE schemaname = current_schema()"""
    ).fetchall()
    assert {row["tablename"] for row in policies} == expected | {"email_change_requests"}
    assert rls["email_change_requests"] == (True, False)
    constraints = {
        row["conname"]
        for row in connection.execute(
            """SELECT conname FROM pg_constraint
               WHERE connamespace = current_schema()::regnamespace"""
        ).fetchall()
    }
    assert {
        "uq_parts_org_part_number",
        "uq_work_orders_org_number",
        "uq_equipment_org_serial",
        "fk_inventory_store",
        "fk_inventory_part",
    } <= constraints


def test_native_refresh_migration_preserves_sessions_and_tracks_hashed_rotation(
    postgres_schema, monkeypatch
):
    from datetime import timedelta
    from uuid import uuid4

    from backend.postgres_migrations import registry
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.temporal import serialize_instant, utc_now

    connection, _ = postgres_schema
    all_migrations = registry.MIGRATIONS
    monkeypatch.setattr(registry, "MIGRATIONS", all_migrations[:5])
    apply_postgres_migrations(connection)
    user_id = connection.execute(
        "INSERT INTO users(email, name, password_hash) VALUES (%s, %s, %s) RETURNING id",
        (f"renewal-{uuid4().hex}@example.test", "Renewal test", "unused"),
    ).fetchone()["id"]
    session_expiry = serialize_instant(utc_now() + timedelta(hours=1))
    connection.execute(
        "INSERT INTO sessions(user_id, session_token_hash, expires_at) VALUES (%s, %s, %s)",
        (user_id, f"access-hash-{uuid4().hex}", session_expiry),
    )
    connection.commit()

    monkeypatch.setattr(registry, "MIGRATIONS", all_migrations)
    status = apply_postgres_migrations(connection)

    session_columns = {
        row["column_name"]
        for row in connection.execute(
            """SELECT column_name FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = 'sessions'"""
        ).fetchall()
    }
    refresh_columns = {
        row["column_name"]
        for row in connection.execute(
            """SELECT column_name FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'session_refresh_credentials'"""
        ).fetchall()
    }
    session_id = connection.execute(
        "SELECT id FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()["id"]
    migrated_expiry = connection.execute(
        "SELECT absolute_expires_at FROM sessions WHERE id = %s", (session_id,)
    ).fetchone()["absolute_expires_at"]
    connection.execute(
        """INSERT INTO session_refresh_credentials
           (session_id, token_hash, issued_at, expires_at)
           VALUES (%s, %s, %s, %s)""",
        (
            session_id,
            f"{uuid4().hex}{uuid4().hex}",
            serialize_instant(utc_now()),
            serialize_instant(utc_now() + timedelta(hours=24)),
        ),
    )

    assert status.applied_versions == tuple(range(1, 13))
    assert "absolute_expires_at" in session_columns
    assert migrated_expiry == session_expiry
    assert {
        "session_id",
        "token_hash",
        "issued_at",
        "expires_at",
        "consumed_at",
        "retry_request_id",
        "retry_response_ciphertext",
        "retry_response_expires_at",
    } <= refresh_columns


def test_native_refresh_migration_allows_only_one_active_credential_per_session(postgres_schema):
    from datetime import timedelta
    from uuid import uuid4

    from psycopg.errors import UniqueViolation

    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.temporal import serialize_instant, utc_now

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    user_id = connection.execute(
        "INSERT INTO users(email, name, password_hash) VALUES (%s, %s, %s) RETURNING id",
        (f"rotation-{uuid4().hex}@example.test", "Rotation test", "unused"),
    ).fetchone()["id"]
    session_id = connection.execute(
        """INSERT INTO sessions(user_id, session_token_hash, expires_at)
           VALUES (%s, %s, %s) RETURNING id""",
        (
            user_id,
            f"access-hash-{uuid4().hex}",
            serialize_instant(utc_now() + timedelta(minutes=15)),
        ),
    ).fetchone()["id"]
    values = (
        session_id,
        serialize_instant(utc_now()),
        serialize_instant(utc_now() + timedelta(hours=24)),
    )
    connection.execute(
        """INSERT INTO session_refresh_credentials
           (session_id, token_hash, issued_at, expires_at) VALUES (%s, %s, %s, %s)""",
        (values[0], f"{uuid4().hex}{uuid4().hex}", values[1], values[2]),
    )

    with pytest.raises(UniqueViolation):
        connection.execute(
            """INSERT INTO session_refresh_credentials
               (session_id, token_hash, issued_at, expires_at) VALUES (%s, %s, %s, %s)""",
            (values[0], f"{uuid4().hex}{uuid4().hex}", values[1], values[2]),
        )


def test_reapplying_postgres_migrations_is_idempotent(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    first = apply_postgres_migrations(connection)
    second = apply_postgres_migrations(connection)

    assert second == first


def test_altered_migration_checksum_is_rejected(postgres_schema):
    from backend.postgres_migrations.runner import (
        PostgresMigrationError,
        apply_postgres_migrations,
    )

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    connection.execute(
        "UPDATE postgres_schema_migrations SET checksum = 'altered' WHERE version = 1"
    )

    with pytest.raises(PostgresMigrationError, match="checksum"):
        apply_postgres_migrations(connection)


def test_incomplete_postgres_migration_history_is_rejected(postgres_schema):
    from backend.postgres_migrations.runner import (
        PostgresMigrationError,
        apply_postgres_migrations,
    )

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    connection.execute("DELETE FROM postgres_schema_migrations WHERE version = 1")

    with pytest.raises(PostgresMigrationError, match="incomplete"):
        apply_postgres_migrations(connection)


def test_failed_migration_rolls_back_ddl_and_ledger_row(postgres_schema, monkeypatch):
    from backend.postgres_migrations import registry
    from backend.postgres_migrations.runner import (
        PostgresMigrationError,
        apply_postgres_migrations,
    )

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)

    failing = registry.Migration(
        version=13,
        name="injected_failure",
        statements=(
            "CREATE TABLE failed_migration_probe (id integer PRIMARY KEY)",
            "CREATE TABLE failed_migration_probe (id integer PRIMARY KEY)",
        ),
    )

    monkeypatch.setattr(registry, "MIGRATIONS", (*registry.MIGRATIONS, failing))

    with pytest.raises(PostgresMigrationError, match="failed"):
        apply_postgres_migrations(connection)

    assert connection.execute("SELECT to_regclass('failed_migration_probe') AS name").fetchone()["name"] is None
    assert connection.execute(
        "SELECT count(*) AS count FROM postgres_schema_migrations WHERE version = 8"
    ).fetchone()["count"] == 0


def test_v0004_pending_invitation_email_is_unique_per_organization(postgres_schema):
    from psycopg.errors import UniqueViolation

    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    status = apply_postgres_migrations(connection)
    assert status.applied_versions == tuple(range(1, 13))
    connection.execute("SET LOCAL row_security = off")
    org_a = connection.execute(
        "INSERT INTO organizations (name, slug) VALUES ('A', 'a') RETURNING id"
    ).fetchone()["id"]
    org_b = connection.execute(
        "INSERT INTO organizations (name, slug) VALUES ('B', 'b') RETURNING id"
    ).fetchone()["id"]
    user = connection.execute(
        "INSERT INTO users (email, name, password_hash) VALUES ('owner@example.test', 'Owner', 'x') RETURNING id"
    ).fetchone()["id"]
    for org_id in (org_a, org_b):
        connection.execute(
            "INSERT INTO organization_invitations "
            "(organization_id, email_normalized, company_role, token_hash, invited_by, expires_at) "
            "VALUES (%s, 'invite@example.test', 'engineer', 'hash-' || %s, %s, '2099-01-01T00:00:00Z')",
            (org_id, org_id, user),
        )
    with pytest.raises(UniqueViolation):
        connection.execute(
            "INSERT INTO organization_invitations "
            "(organization_id, email_normalized, company_role, token_hash, invited_by, expires_at) "
            "VALUES (%s, 'invite@example.test', 'manager', 'another-hash', %s, '2099-01-01T00:00:00Z')",
            (org_a, user),
        )


def test_v0005_hashes_existing_sessions_and_drops_raw_session_values(postgres_schema, monkeypatch):
    from hashlib import sha256

    from backend.postgres_migrations import registry
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    all_migrations = registry.MIGRATIONS
    monkeypatch.setattr(registry, "MIGRATIONS", all_migrations[:4])
    apply_postgres_migrations(connection)

    user = connection.execute(
        "INSERT INTO users (email, name, password_hash, session_token) "
        "VALUES ('legacy@example.test', 'Legacy', 'x', 'legacy-user-token') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO sessions (user_id, session_token, expires_at) "
        "VALUES (%s, 'still-valid-session-token', '2099-01-01T00:00:00Z')",
        (user,),
    )

    monkeypatch.setattr(registry, "MIGRATIONS", all_migrations)
    status = apply_postgres_migrations(connection)

    assert status.applied_versions == tuple(range(1, 13))
    session_columns = {
        row["column_name"]
        for row in connection.execute(
            """SELECT column_name FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = 'sessions'"""
        ).fetchall()
    }
    assert "session_token" not in session_columns
    assert "session_token_hash" in session_columns
    stored_hash = connection.execute(
        "SELECT session_token_hash FROM sessions WHERE user_id = %s", (user,)
    ).fetchone()["session_token_hash"]
    assert stored_hash == sha256(b"still-valid-session-token").hexdigest()
    assert connection.execute(
        "SELECT session_token FROM users WHERE id = %s", (user,)
    ).fetchone()["session_token"] is None


def test_invitation_rls_denies_reads_without_matching_context(postgres_schema):
    from uuid import uuid4

    from psycopg import sql

    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    apply_postgres_migrations(connection)
    org = connection.execute(
        "INSERT INTO organizations (name, slug) VALUES ('A', 'a') RETURNING id"
    ).fetchone()["id"]
    user = connection.execute(
        "INSERT INTO users (email, name, password_hash) VALUES ('owner@example.test', 'Owner', 'x') RETURNING id"
    ).fetchone()["id"]
    connection.execute(
        "INSERT INTO organization_invitations "
        "(organization_id, email_normalized, company_role, token_hash, invited_by, expires_at) "
        "VALUES (%s, 'invite@example.test', 'engineer', 'hash', %s, '2099-01-01T00:00:00Z')",
        (org, user),
    )
    role = "invitation_reader_" + uuid4().hex
    connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    schema = connection.execute("SELECT current_schema() AS name").fetchone()["name"]
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
        sql.Identifier(schema), sql.Identifier(role)
    ))
    connection.execute(sql.SQL("GRANT SELECT ON organization_invitations TO {}").format(
        sql.Identifier(role)
    ))
    connection.commit()
    from regression_tests.postgres_fixtures import postgres_test_dsn
    with psycopg.connect(postgres_test_dsn(), row_factory=connection.row_factory) as reader:
        reader.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        reader.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        reader.commit()
        reader.execute("SELECT set_config('app.organization_id', '', true)")
        assert reader.execute(
            "SELECT count(*) AS count FROM organization_invitations"
        ).fetchone()["count"] == 0
    connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
    connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
    connection.commit()
