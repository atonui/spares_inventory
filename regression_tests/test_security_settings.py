"""Global security settings are read from PostgreSQL system_settings with code defaults."""
import pytest


DEFAULTS = dict(max_login_attempts=5, lockout_duration_minutes=15,
                session_duration_hours=24, remember_me_duration_days=30)


def save(stock_database, rows):
    owner = stock_database.db
    owner.execute('DELETE FROM system_settings')
    for key, value in rows:
        owner.execute('INSERT INTO system_settings(setting_key,setting_value) VALUES(%s,%s)', (key, value))
    owner.commit()


def test_security_settings_overlay_only_saved_security_values(stock_database):
    from backend.services.security_settings import load_security_settings

    save(stock_database, [('max_login_attempts', '7'), ('unrelated', 'not-an-integer')])
    assert load_security_settings(stock_database.connect, defaults=DEFAULTS) == {**DEFAULTS, 'max_login_attempts': 7}
    assert DEFAULTS['max_login_attempts'] == 5


def test_security_settings_close_connection_on_bad_saved_value(stock_database):
    from backend.services.security_settings import load_security_settings

    save(stock_database, [('max_login_attempts', 'bad')])
    conn = stock_database.connect()
    with pytest.raises(ValueError):
        load_security_settings(lambda: conn, defaults=DEFAULTS)
    assert conn.closed


def test_main_security_settings_use_current_database_and_defaults(stock_database, monkeypatch):
    import main

    save(stock_database, [])
    monkeypatch.setattr(main, 'get_db_connection', stock_database.connect)
    monkeypatch.setattr(main, 'MAX_LOGIN_ATTEMPTS', 9)
    assert main.get_security_config()['max_login_attempts'] == 9
