"""Migration import contracts run against the disposable PostgreSQL CI database."""

from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture(params=[False, True], ids=["legacy", "current"])
def sqlite_snapshot(tmp_path, request):
    from backend.migrations.runner import apply_migrations
    from backend.temporal import serialize_instant, utc_now
    from regression_tests.migration_fixtures import legacy_connection, snapshot

    path = tmp_path / ("legacy.sqlite3" if not request.param else "current.sqlite3")
    source = legacy_connection(path, current=request.param)
    source.execute("INSERT INTO users(id,email,name,password_hash,role) VALUES (8,'staff@example.com','Staff','staff-hash','engineer')")
    source.execute("INSERT INTO sessions(user_id,session_token,expires_at) VALUES (7,'must-not-survive',?)",
                   (serialize_instant(utc_now() + timedelta(hours=1)),))
    source.execute("INSERT INTO activity_logs(user_id,action,created_at) VALUES (0,'legacy-anonymous',?)",
                   (serialize_instant(utc_now()),))
    source.commit()
    if request.param:
        apply_migrations(source)
        created = serialize_instant(utc_now())
        source.execute("UPDATE organisation_settings SET business_timezone='Europe/London',revision=9")
        source.execute("INSERT INTO system_settings(setting_key,setting_value,updated_by,updated_at) VALUES ('system_announcement',?,?,?)",
                       ('{"message":"Maintenance notice","level":"warning","revision":"notice-1","audience":"everyone","roles":[],"starts_at":null,"expires_at":null,"dismissible":false,"set_at":"' + created + '"}', 7, created))
        source.execute("INSERT INTO announcement_dismissals(user_id,revision,dismissed_at) VALUES (8,'notice-1',?)",
                       (created,))
        if source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='stock_transfers'").fetchone():
            source.execute("INSERT INTO stock_transfers(movement_id,status,source_min_threshold,completed_by,completed_at) VALUES (1,'received',2,7,?)",
                           (created,))
        source.commit()
    before = snapshot(source)
    source.close()
    return path, before


@pytest.fixture
def migrated_target(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from regression_tests.postgres_fixtures import postgres_test_dsn

    connection, schema = postgres_schema
    apply_postgres_migrations(connection)
    dsn = make_conninfo(postgres_test_dsn(), options=f"-csearch_path={schema}")
    return connection, dsn


def test_import_preserves_tenant_data_maps_roles_and_rehearsal_rolls_back(sqlite_snapshot, migrated_target):
    from regression_tests.migration_fixtures import snapshot
    from backend.migration_import.sqlite_to_postgres import import_sqlite_snapshot

    path, before = sqlite_snapshot
    admin, dsn = migrated_target
    report = import_sqlite_snapshot(
        path, dsn, organization_name="First Company",
        platform_admin_email="test@example.com", dry_run=True,
    )
    assert report.dry_run and not report.applied
    assert report.source_counts["users"] == 2
    assert report.revoked_sessions == 1
    assert report.memberships_checked == 2
    assert report.balances_checked == 1
    assert report.transfer_states == ({"received": 1} if before.get("stock_transfers") else {})
    assert report.target_counts["users"] == 2
    assert admin.execute("SELECT count(*) FROM users").fetchone()["count"] == 0

    with sqlite3_readwrite(path) as source:
        assert snapshot(source) == before


def test_import_apply_maps_first_superadmin_to_platform_and_company_owner(sqlite_snapshot, migrated_target):
    from backend.migration_import.sqlite_to_postgres import import_sqlite_snapshot

    path, _before = sqlite_snapshot
    admin, dsn = migrated_target
    report = import_sqlite_snapshot(
        path, dsn, organization_name="First Company",
        platform_admin_email="test@example.com", dry_run=False,
    )
    assert report.applied and not report.dry_run
    assert admin.execute("SELECT company_role FROM organization_memberships WHERE user_id=7").fetchone()["company_role"] == "owner"
    assert admin.execute("SELECT count(*) FROM platform_admins WHERE user_id=7").fetchone()["count"] == 1
    assert admin.execute("SELECT count(*) FROM organization_memberships WHERE user_id=8 AND company_role='engineer'").fetchone()["count"] == 1
    assert admin.execute("SELECT count(*) FROM sessions WHERE is_active").fetchone()["count"] == 0
    identity = admin.execute("SELECT session_token,reset_token FROM users WHERE id=7").fetchone()
    assert identity["session_token"] is None and identity["reset_token"] is None
    assert admin.execute("SELECT user_id FROM activity_logs WHERE action='legacy-anonymous'").fetchone()["user_id"] is None
    assert admin.execute("SELECT quantity FROM inventory WHERE id=1").fetchone()["quantity"] == 19
    if _before.get("organisation_settings"):
        assert admin.execute("SELECT business_timezone,revision FROM organization_settings").fetchone() == {
            "business_timezone": "Europe/London", "revision": 9,
        }
        assert admin.execute("SELECT payload->>'message' AS message FROM company_announcements").fetchone()["message"] == "Maintenance notice"
        assert admin.execute("SELECT count(*) FROM announcement_dismissals").fetchone()["count"] == 1


def test_import_rejects_invalid_foreign_reference_without_mutating_source(sqlite_snapshot, migrated_target):
    from backend.migration_import.sqlite_to_postgres import import_sqlite_snapshot
    from regression_tests.migration_fixtures import snapshot

    path, _before = sqlite_snapshot
    admin, dsn = migrated_target
    with sqlite3_readwrite(path) as source:
        source.execute("PRAGMA foreign_keys=OFF")
        source.execute("INSERT INTO inventory(store_id,part_id,quantity,min_threshold) VALUES (999,1,1,0)")
        source.commit()
        invalid = snapshot(source)
    with pytest.raises(ValueError):
        import_sqlite_snapshot(path, dsn, organization_name="First Company",
                               platform_admin_email="test@example.com")
    with sqlite3_readwrite(path) as source:
        assert snapshot(source) == invalid
    assert admin.execute("SELECT count(*) FROM organizations").fetchone()["count"] == 0


def test_import_refuses_a_nonempty_target(sqlite_snapshot, migrated_target):
    from backend.migration_import.sqlite_to_postgres import import_sqlite_snapshot

    path, _before = sqlite_snapshot
    admin, dsn = migrated_target
    admin.execute("INSERT INTO organizations(name,slug) VALUES ('Bootstrap','bootstrap')")
    admin.commit()
    with pytest.raises(ValueError, match="target is not empty"):
        import_sqlite_snapshot(path, dsn, organization_name="First Company",
                               platform_admin_email="test@example.com")


def sqlite3_readwrite(path: Path):
    import sqlite3
    return sqlite3.connect(path)
