"""Versioned PostgreSQL schema migration contracts."""

import pytest

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_fresh_schema_applies_core_and_tenancy_migrations(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection, _ = postgres_schema
    status = apply_postgres_migrations(connection)

    assert status.applied_versions == (1, 2, 3)
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
    assert {row["tablename"] for row in policies} == expected
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
        version=4,
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
        "SELECT count(*) AS count FROM postgres_schema_migrations WHERE version = 4"
    ).fetchone()["count"] == 0
