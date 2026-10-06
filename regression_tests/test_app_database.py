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