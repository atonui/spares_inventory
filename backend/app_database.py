"""Application database helpers that bind settings to path-based database APIs."""

from backend.database import DEFAULT_SETTINGS, connect_database, initialize_database
from backend.postgres_database import connect_postgres


def is_postgresql_dsn(database_url):
    return isinstance(database_url, str) and database_url.startswith(
        ("postgresql://", "postgres://")
    )


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
    if is_postgresql_dsn(database_path):
        from backend.postgres_migrations.runner import apply_postgres_migrations

        connection = connect_postgres(database_path)
        try:
            return apply_postgres_migrations(connection)
        finally:
            connection.close()
    return initialize_database(database_path, defaults=defaults)


def open_application_database(database_path):
    if is_postgresql_dsn(database_path):
        return connect_postgres(database_path)
    return connect_database(database_path)
