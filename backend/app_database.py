"""Application database helpers that bind settings to path-based database APIs."""

from backend.database import DEFAULT_SETTINGS, connect_database, initialize_database


def make_database_defaults(
    *,
    max_login_attempts: int,
    lockout_duration_minutes: int,
    session_duration_hours: int,
    remember_me_duration_days: int,
):
    return {
        **DEFAULT_SETTINGS,
        "max_login_attempts": str(max_login_attempts),
        "lockout_duration_minutes": str(lockout_duration_minutes),
        "session_duration_hours": str(session_duration_hours),
        "remember_me_duration_days": str(remember_me_duration_days),
    }


def initialize_application_database(database_path, *, defaults):
    return initialize_database(database_path, defaults=defaults)


def open_application_database(database_path):
    return connect_database(database_path)