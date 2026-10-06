"""Load database-backed authentication policy settings."""

from contextlib import closing


def load_security_settings(get_connection, *, defaults: dict) -> dict:
    with closing(get_connection()) as conn:
        rows = conn.execute("""
            SELECT setting_key, setting_value FROM system_settings
            WHERE setting_key IN (
                'max_login_attempts', 'lockout_duration_minutes',
                'session_duration_hours', 'remember_me_duration_days'
            )
        """).fetchall()
        saved = {row['setting_key']: int(row['setting_value']) for row in rows}
    return {key: saved.get(key, value) for key, value in defaults.items()}
