from contextlib import closing
import sqlite3

import pytest

from backend.database import connect_database
from regression_tests.session_fixtures import session_database


DEFAULTS = dict(max_login_attempts=5, lockout_duration_minutes=15,
                session_duration_hours=24, remember_me_duration_days=30)


def test_security_settings_overlay_only_saved_security_values(tmp_path):
    from backend.services.security_settings import load_security_settings

    path = session_database(tmp_path / 'settings.db')
    with closing(connect_database(path)) as conn:
        conn.execute('DELETE FROM system_settings')
        conn.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('max_login_attempts','7')")
        conn.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('unrelated','not-an-integer')")
        conn.commit()
    assert load_security_settings(lambda: connect_database(path), defaults=DEFAULTS) == {**DEFAULTS, 'max_login_attempts': 7}
    assert DEFAULTS['max_login_attempts'] == 5


def test_security_settings_close_connection_on_bad_saved_value(tmp_path):
    from backend.services.security_settings import load_security_settings

    path = session_database(tmp_path / 'settings.db')
    conn = connect_database(path)
    conn.execute("UPDATE system_settings SET setting_value='bad' WHERE setting_key='max_login_attempts'")
    conn.commit()
    with pytest.raises(ValueError):
        load_security_settings(lambda: conn, defaults=DEFAULTS)
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        conn.execute('SELECT 1')


def test_main_security_settings_use_current_database_and_defaults(tmp_path, monkeypatch):
    import main

    path = session_database(tmp_path / 'settings.db')
    with closing(connect_database(path)) as conn:
        conn.execute('DELETE FROM system_settings')
        conn.commit()
    monkeypatch.setattr(main, 'get_db_connection', lambda: connect_database(path))
    monkeypatch.setattr(main, 'MAX_LOGIN_ATTEMPTS', 9)
    assert main.get_security_config()['max_login_attempts'] == 9
