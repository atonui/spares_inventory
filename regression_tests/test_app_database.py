from contextlib import closing


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


def test_main_database_wrappers_use_current_database_path(tmp_path, monkeypatch):
    import main

    database_path = tmp_path / "current.db"
    monkeypatch.setattr(main, "DATABASE", str(database_path))

    main.init_db()

    with closing(main.get_db_connection()) as conn:
        setting = conn.execute(
            "SELECT setting_value FROM system_settings WHERE setting_key=?",
            ("session_duration_hours",),
        ).fetchone()
        user_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()

    assert database_path.exists()
    assert setting["setting_value"] == str(main.SESSION_DURATION_HOURS)
    assert user_table["name"] == "users"


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
