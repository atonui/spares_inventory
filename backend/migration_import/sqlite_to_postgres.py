"""Copy a legacy SQLite snapshot into a migrated, empty PostgreSQL database."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import tempfile
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from backend.migration_import.verify import verify_import
from backend.postgres_migrations import registry
from backend.postgres_migrations.runner import postgres_migration_status
from backend.temporal import parse_api_instant


@dataclass(frozen=True)
class ImportReport:
    organization_id: str
    organization_slug: str
    dry_run: bool
    applied: bool
    source_counts: dict[str, int]
    target_counts: dict[str, int]
    balances_checked: int
    transfer_states: dict[str, int]
    memberships_checked: int
    revoked_sessions: int


TENANT_TABLES = (
    "stores", "store_types", "parts", "work_orders", "inventory", "movements",
    "stock_transfers", "equipment", "equipment_history", "activity_logs",
)
CORE_TABLES = (
    "users", "stores", "store_types", "parts", "work_orders", "inventory",
    "movements", "equipment", "equipment_history", "activity_logs",
    "system_logs", "system_settings",
)
OPTIONAL_TABLES = ("sessions", "stock_transfers", "organisation_settings", "announcement_dismissals")
USER_COLUMNS = (
    "id", "email", "name", "password_hash", "territory", "session_token", "created_at",
    "session_expires", "failed_login_attempts", "account_locked_until", "last_login",
    "reset_token", "reset_token_expires", "archived_at", "display_timezone",
)
TENANT_COLUMNS = {
    "stores": ("id", "name", "type", "location", "assigned_user_id", "created_at", "archived_at"),
    "store_types": ("id", "type_code", "type_name", "description", "is_active", "display_order", "created_at", "updated_at"),
    "parts": ("id", "part_number", "description", "category", "unit_cost", "created_at", "archived_at"),
    "work_orders": ("id", "work_order_number", "customer_name", "description", "status", "assigned_engineer_id", "created_at"),
    "inventory": ("id", "store_id", "part_id", "quantity", "min_threshold", "work_order_id", "updated_at"),
    "movements": ("id", "from_store_id", "to_store_id", "part_id", "quantity", "movement_type", "work_order_id", "created_by", "notes", "created_at"),
    "stock_transfers": ("movement_id", "status", "source_min_threshold", "completed_by", "completed_at", "completion_note"),
    "equipment": ("id", "equipment_name", "make", "model", "serial_number", "assigned_user_id", "calibration_cert_number", "calibration_authority", "calibration_date", "next_calibration_date", "status", "notes", "created_at", "updated_at"),
    "equipment_history": ("id", "equipment_id", "action", "from_user_id", "to_user_id", "calibration_date", "notes", "created_by", "created_at"),
    "activity_logs": ("id", "user_id", "username", "action", "resource_type", "resource_id", "details", "ip_address", "user_agent", "status", "error_message", "created_at"),
}
GLOBAL_COLUMNS = {
    "system_logs": ("id", "level", "component", "message", "details", "created_at"),
    "system_settings": ("id", "setting_key", "setting_value", "description", "updated_by", "updated_at"),
}
TEMPORAL_COLUMNS = {
    "users": ("created_at", "session_expires", "account_locked_until", "last_login"),
    "sessions": ("expires_at", "created_at", "last_activity"),
    "stores": ("created_at",), "store_types": ("created_at", "updated_at"),
    "parts": ("created_at",), "work_orders": ("created_at",),
    "inventory": ("updated_at",), "movements": ("created_at",),
    "stock_transfers": ("completed_at",), "equipment": ("created_at", "updated_at"),
    "equipment_history": ("created_at",), "activity_logs": ("created_at",),
    "system_logs": ("created_at",), "system_settings": ("updated_at",),
    "organisation_settings": ("updated_at",), "announcement_dismissals": ("dismissed_at",),
}


def _slug(name: str) -> str:
    value = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")[:55].strip("-")
    if not value:
        raise ValueError("Organization name cannot produce a valid slug")
    return value


def _source_connection(path: Path):
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise ValueError("SQLite source file does not exist")
    connection = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _table_names(source) -> set[str]:
    return {row[0] for row in source.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )}


def _rows(source, table: str) -> list[sqlite3.Row]:
    return source.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()


def _validate_source(source, tables: set[str]) -> None:
    from backend.migrations.validation import validate_current, validate_legacy

    missing = set(CORE_TABLES) - tables
    if missing:
        raise ValueError("SQLite source is missing required application tables")
    try:
        if "schema_migrations" in tables:
            validate_current(source)
        else:
            validate_legacy(source)
        violations = source.execute("PRAGMA foreign_key_check").fetchall()
        sentinel_only = all(
            row[0] == "activity_logs" and row[2] == "users"
            and source.execute("SELECT user_id FROM activity_logs WHERE rowid=?", (row[1],)).fetchone()[0] == 0
            for row in violations
        )
        if violations and not sentinel_only:
            raise ValueError("SQLite source contains invalid foreign references")
        for table, columns in TEMPORAL_COLUMNS.items():
            if table not in tables:
                continue
            available = {row[1] for row in source.execute(f'PRAGMA table_info("{table}")')}
            for column in set(columns) & available:
                for (value,) in source.execute(f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL'):
                    parse_api_instant(value)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("SQLite source schema or data failed validation") from exc


def _target_table_counts(target) -> dict[str, int]:
    names = [row["tablename"] for row in target.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname=current_schema()"
    ).fetchall()]
    counts = {}
    for name in names:
        if name == "postgres_schema_migrations":
            continue
        counts[name] = target.execute(
            sql.SQL("SELECT count(*) AS n FROM {} ").format(sql.Identifier(name))
        ).fetchone()["n"]
    if any(counts.values()):
        raise ValueError("PostgreSQL target is not empty")
    return counts


def _target_columns(target, table: str) -> set[str]:
    return {row["column_name"] for row in target.execute(
        """SELECT column_name FROM information_schema.columns
           WHERE table_schema=current_schema() AND table_name=%s""", (table,),
    ).fetchall()}


def _insert_rows(target, table: str, columns: tuple[str, ...], rows, *, organization_id=None, transforms=None):
    if table == "stock_transfers" and not rows:
        return
    target_columns = _target_columns(target, table)
    picked = [column for column in columns if column in target_columns]
    if organization_id is not None:
        picked.append("organization_id")
    if set(columns) - target_columns:
        missing = set(columns) - target_columns
        if missing:
            raise ValueError("PostgreSQL target schema is incompatible with the importer")
    if not rows:
        return
    placeholders = sql.SQL(",").join(sql.Placeholder() for _ in picked)
    statement = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
        sql.Identifier(table), sql.SQL(",").join(map(sql.Identifier, picked)), placeholders
    )
    transform = transforms or {}
    values = []
    for row in rows:
        data = dict(row)
        shaped = []
        for column in picked:
            if column == "organization_id":
                shaped.append(organization_id)
            elif column in transform:
                shaped.append(transform[column](data.get(column)))
            else:
                shaped.append(data.get(column))
        values.append(tuple(shaped))
    with target.cursor() as cursor:
        cursor.executemany(statement, values)


def _advance_identity_sequences(target) -> None:
    for table in ("users", *TENANT_TABLES, "system_logs", "system_settings"):
        if "id" not in _target_columns(target, table):
            continue
        target.execute(
            sql.SQL(
                "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
                "GREATEST(COALESCE(max(id), 1), 1), count(*) > 0) FROM {}"
            ).format(sql.Identifier(table)),
            (table,),
        )


def import_sqlite_snapshot(
    source_path: Path, target_dsn: str, *, organization_name: str,
    platform_admin_email: str, tenant_owner_email: str, dry_run: bool = True,
) -> ImportReport:
    """Import a validated SQLite snapshot; default mode always rolls back."""
    if not organization_name.strip():
        raise ValueError("Organization name is required")
    admin_email = platform_admin_email.strip().lower()
    if not admin_email or "@" not in admin_email:
        raise ValueError("Platform administrator email is invalid")
    owner_email = tenant_owner_email.strip().lower()
    if not owner_email or "@" not in owner_email:
        raise ValueError("Tenant owner email is invalid")
    if owner_email == admin_email:
        raise ValueError("Platform administrator and tenant owner must be different accounts")
    slug = _slug(organization_name)
    original = _source_connection(Path(source_path))
    staging = None
    staging_directory = tempfile.TemporaryDirectory(prefix="inventory-import-")
    staging_path = Path(staging_directory.name) / "snapshot.sqlite3"
    target = None
    try:
        from backend.migrations.runner import apply_migrations

        staging = sqlite3.connect(staging_path)
        staging.row_factory = sqlite3.Row
        original.backup(staging)
        apply_migrations(staging)
        source = staging
        tables = _table_names(source)
        _validate_source(source, tables)
        source_rows = {table: _rows(source, table) for table in tables if table != "schema_migrations"}
        source_counts = {table: len(rows) for table, rows in source_rows.items()}
        users = source_rows["users"]
        columns = {row[1] for row in source.execute('PRAGMA table_info("users")')}
        if "role" not in columns:
            raise ValueError("SQLite users table has no company role column")
        platform_user = next((row for row in users if str(row["email"]).strip().lower() == admin_email), None)
        if not platform_user or platform_user["role"] != "superadmin":
            raise ValueError("Platform administrator email must identify an existing legacy superadmin")
        tenant_owner = next((row for row in users if str(row["email"]).strip().lower() == owner_email), None)
        if not tenant_owner or tenant_owner["role"] not in {"superadmin", "admin"}:
            raise ValueError("Tenant owner email must identify a different existing legacy admin or superadmin")
        normalized_emails = [str(row["email"]).strip().lower() for row in users]
        if len(set(normalized_emails)) != len(normalized_emails):
            raise ValueError("SQLite source contains duplicate normalized email addresses")
        if any(row["role"] not in {"superadmin", "admin", "manager", "engineer"} for row in users):
            raise ValueError("SQLite source contains an unsupported user role")

        target = psycopg.connect(target_dsn, row_factory=dict_row, connect_timeout=5)
        status = postgres_migration_status(target)
        if status.applied_versions != tuple(m.version for m in registry.MIGRATIONS) or status.pending_versions:
            raise ValueError("PostgreSQL target migrations are not current")
        _target_table_counts(target)
        organization = target.execute(
            "INSERT INTO organizations(name,slug) VALUES (%s,%s) RETURNING id",
            (organization_name.strip(), slug),
        ).fetchone()
        organization_id = organization["id"]
        target.execute("INSERT INTO organization_settings(organization_id) VALUES (%s)", (organization_id,))

        _insert_rows(target, "users", USER_COLUMNS, users, transforms={
            "session_token": lambda _v: None,
            "session_expires": lambda _v: None,
            "reset_token": lambda _v: None,
            "reset_token_expires": lambda _v: None,
        })
        with target.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO organization_memberships(organization_id,user_id,company_role) VALUES (%s,%s,%s)",
                [(organization_id, row["id"],
                  "owner" if row["id"] == tenant_owner["id"]
                  else ("admin" if row["role"] in {"superadmin", "admin"} else row["role"]))
                 for row in users if row["id"] != platform_user["id"]],
            )
        target.execute("INSERT INTO platform_admins(user_id) VALUES (%s)", (platform_user["id"],))

        imported_counts = {"users": len(users), "memberships": len(users) - 1, "platform_admins": 1}
        for table, columns_for_table in TENANT_COLUMNS.items():
            rows = source_rows.get(table, [])
            if rows and table not in tables:
                raise ValueError("SQLite source is missing an operational table")
            if table == "activity_logs":
                _insert_rows(target, table, columns_for_table, rows, organization_id=organization_id,
                             transforms={"user_id": lambda value: None if value == 0 else value})
            elif table == "store_types":
                # SQLite represents BOOLEAN columns as integer 0/1; psycopg adapts
                # those integers as smallint, which PostgreSQL will not implicitly
                # cast to BOOLEAN.
                _insert_rows(target, table, columns_for_table, rows, organization_id=organization_id,
                             transforms={"is_active": lambda value: None if value is None else bool(value)})
            else:
                _insert_rows(target, table, columns_for_table, rows, organization_id=organization_id)
            if table in tables:
                imported_counts[table] = len(rows)

        for table, table_columns in GLOBAL_COLUMNS.items():
            rows = source_rows.get(table, [])
            if table == "system_settings":
                notice = next((row for row in rows if row["setting_key"] == "system_announcement"), None)
                normal_rows = [row for row in rows if row["setting_key"] != "system_announcement"]
                _insert_rows(target, table, table_columns, normal_rows)
                imported_counts[table] = len(normal_rows)
                if notice is not None:
                    payload = json.loads(notice["setting_value"])
                    if not isinstance(payload, dict) or not isinstance(payload.get("message"), str):
                        raise ValueError("SQLite announcement data is invalid")
                    if not payload.get("revision"):
                        payload["revision"] = "legacy-import-" + str(notice["id"])
                    target.execute(
                        "INSERT INTO company_announcements(organization_id,revision,payload,updated_by,updated_at) VALUES (%s,%s,%s,%s,%s)",
                        (organization_id, payload["revision"], json.dumps(payload), notice["updated_by"], notice["updated_at"]),
                    )
                    imported_counts["system_announcement"] = 1
            else:
                _insert_rows(target, table, table_columns, rows)
                if table in tables:
                    imported_counts[table] = len(rows)

        if "organisation_settings" in source_rows and source_rows["organisation_settings"]:
            settings = source_rows["organisation_settings"]
            if len(settings) != 1 or settings[0]["id"] != 1:
                raise ValueError("SQLite organization settings are invalid")
            target.execute(
                "UPDATE organization_settings SET business_timezone=%s,revision=%s,updated_at=%s,updated_by=%s WHERE organization_id=%s",
                (settings[0]["business_timezone"], settings[0]["revision"], settings[0]["updated_at"], settings[0]["updated_by"], organization_id),
            )
            imported_counts["organisation_settings"] = 1
        else:
            imported_counts["organisation_settings"] = 1

        notice = target.execute(
            "SELECT revision FROM company_announcements WHERE organization_id=%s", (organization_id,),
        ).fetchone()
        if "announcement_dismissals" in source_rows:
            rows = source_rows["announcement_dismissals"]
            if notice:
                _insert_rows(target, "announcement_dismissals", ("user_id", "revision", "dismissed_at"), rows,
                             organization_id=organization_id)
                imported_counts["announcement_dismissals"] = len(rows)
            else:
                if rows:
                    raise ValueError("SQLite announcement dismissals have no matching announcement")
                imported_counts["announcement_dismissals"] = 0
        else:
            imported_counts["announcement_dismissals"] = 0
        _advance_identity_sequences(target)
        revoked = source_counts.get("sessions", 0)
        summary = verify_import(source, target, organization_id,
                                imported_counts=imported_counts,
                                source_counts=source_counts, revoked_sessions=revoked,
                                platform_admin_user_id=platform_user["id"])
        if dry_run:
            target.rollback()
        else:
            target.commit()
        return ImportReport(
            organization_id=str(organization_id), organization_slug=slug,
            dry_run=dry_run, applied=not dry_run,
            source_counts=summary["source_counts"], target_counts=summary["target_counts"],
            balances_checked=summary["balances_checked"],
            transfer_states=summary["transfer_states"],
            memberships_checked=summary["memberships_checked"], revoked_sessions=revoked,
        )
    except Exception:
        if target is not None:
            target.rollback()
        raise
    finally:
        original.close()
        if staging is not None:
            staging.close()
        staging_directory.cleanup()
        if target is not None:
            target.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Rehearse or apply a SQLite-to-PostgreSQL import")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("import-sqlite")
    command.add_argument("--source", type=Path, required=True)
    command.add_argument("--target-dsn-env", default="DATABASE_URL")
    command.add_argument("--organization-name", required=True)
    command.add_argument("--platform-admin-email", required=True)
    command.add_argument("--tenant-owner-email", required=True)
    command.add_argument("--apply", action="store_true", help="commit the import; default is rollback-only rehearsal")
    args = parser.parse_args(argv)
    import os
    dsn = os.environ.get(args.target_dsn_env)
    if not dsn:
        parser.error("target DSN environment variable is not set")
    try:
        report = import_sqlite_snapshot(
            args.source, dsn, organization_name=args.organization_name,
            platform_admin_email=args.platform_admin_email, dry_run=not args.apply,
            tenant_owner_email=args.tenant_owner_email,
        )
    except Exception as error:
        # Driver exception messages can contain SQL values or connection details.
        # Emit only the class to help diagnose failures without exposing payloads.
        print(
            "Import stopped: validation or database operation failed "
            f"(failure_type={type(error).__name__}); "
            "details withheld to protect row values and credentials.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(asdict(report), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
