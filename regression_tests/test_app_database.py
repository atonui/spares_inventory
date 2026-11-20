from contextlib import closing

import pytest


def test_app_database_defaults_preserve_core_defaults_and_stringify_overrides():
    from backend.app_database import make_database_defaults

    defaults = make_database_defaults(
        max_login_attempts=9,
        lockout_duration_minutes=33,
        session_duration_hours=44,
        remember_me_duration_days=55,
    )

    assert defaults["calibration_reminder_days"] == "30"
    assert defaults["max_login_attempts"] == "9"
    assert defaults["lockout_duration_minutes"] == "33"
    assert defaults["session_duration_hours"] == "44"
    assert defaults["remember_me_duration_days"] == "55"


@pytest.mark.parametrize("url", ["inventory.db", "/data/inventory.db", "sqlite:///inventory.db", "mysql://db/app"])
def test_non_postgresql_database_urls_are_refused(url):
    import main
    from pydantic import ValidationError
    from backend.app_database import initialize_application_database, open_application_database

    config = main.settings.model_dump()
    config["DATABASE_URL"] = url
    with pytest.raises(ValidationError, match="PostgreSQL"):
        main.Settings(**config)
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        open_application_database(url)
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        initialize_application_database(url, defaults={})

def test_application_database_initializes_postgres_migrations(monkeypatch):
    import backend.app_database as app_database

    calls = []
    connection = type("Connection", (), {"close": lambda self: calls.append("closed")})()
    monkeypatch.setattr(app_database, "connect_postgres", lambda dsn: calls.append(dsn) or connection)
    monkeypatch.setattr(
        "backend.postgres_migrations.runner.apply_postgres_migrations",
        lambda conn: calls.append(conn) or "migration-status",
        raising=False,
    )

    result = app_database.initialize_application_database(
        "postgresql://user@db/inventory_test", defaults={}
    )

    assert result == "migration-status"
    assert calls[0] == "postgresql://user@db/inventory_test"
    assert calls[1] is connection
    assert calls[2] == "closed"


def test_application_database_uses_separate_migration_connection(monkeypatch):
    import backend.app_database as app_database

    calls = []
    connection = type("Connection", (), {"close": lambda self: None})()
    monkeypatch.setattr(app_database, "connect_postgres", lambda dsn: calls.append(dsn) or connection)
    monkeypatch.setattr(
        "backend.postgres_migrations.runner.apply_postgres_migrations",
        lambda conn: "migration-status",
        raising=False,
    )
    app_database.initialize_application_database(
        "postgresql://runtime@db/inventory",
        defaults={},
        migration_database_url="postgresql://migrator@db/inventory",
    )
    assert calls == ["postgresql://migrator@db/inventory"]
