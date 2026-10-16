"""PostgreSQL startup refuses incomplete or altered tenant schemas."""

import pytest
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

pytest_plugins = ("regression_tests.postgres_fixtures",)


def _schema_dsn(schema):
    parts = urlsplit(os.environ["TEST_DATABASE_URL"])
    query = dict(parse_qsl(parts.query))
    query["options"] = f"-csearch_path={schema}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def test_startup_applies_empty_schema_then_is_idempotent(postgres_schema):
    from backend.app_database import initialize_application_database
    _admin, schema = postgres_schema
    dsn = _schema_dsn(schema)
    first = initialize_application_database(dsn, defaults={})
    second = initialize_application_database(dsn, defaults={})
    assert first.applied_versions == (1, 2, 3, 4, 5, 6)
    assert first.pending_versions == ()
    assert second == first


def test_startup_rejects_modified_migration_ledger(postgres_schema):
    from backend.app_database import initialize_application_database
    from backend.postgres_migrations.runner import apply_postgres_migrations
    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    admin.execute("UPDATE postgres_schema_migrations SET checksum='altered' WHERE version=4")
    admin.commit()
    dsn = _schema_dsn(schema)
    with pytest.raises(RuntimeError, match="checksum"):
        initialize_application_database(dsn, defaults={})


def test_startup_rejects_unknown_newer_migration_history(postgres_schema):
    from backend.app_database import initialize_application_database
    from backend.postgres_migrations.runner import apply_postgres_migrations
    admin, schema = postgres_schema
    apply_postgres_migrations(admin)
    admin.execute(
        "INSERT INTO postgres_schema_migrations(version,name,checksum) VALUES (7,'future','future')"
    )
    admin.commit()
    dsn = _schema_dsn(schema)
    with pytest.raises(RuntimeError, match="history"):
        initialize_application_database(dsn, defaults={})
