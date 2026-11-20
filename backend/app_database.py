"""Application database helpers bound to the configured PostgreSQL database."""

from backend.postgres_database import connect_postgres

# Bootstrap security defaults; saved system_settings values override them.
DEFAULT_SETTINGS = {
    "calibration_reminder_days": "30",
    "max_login_attempts": "5",
    "lockout_duration_minutes": "15",
    "session_duration_hours": "24",
    "remember_me_duration_days": "30",
}


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


def _require_postgresql(database_url):
    if not is_postgresql_dsn(database_url):
        raise RuntimeError("DATABASE_URL must be a PostgreSQL connection URL")


def initialize_application_database(database_path, *, defaults, migration_database_url=None):
    """Apply the PostgreSQL migration chain (as the migration role when configured)."""
    _require_postgresql(database_path)
    from backend.postgres_migrations.runner import apply_postgres_migrations

    connection = connect_postgres(migration_database_url or database_path)
    try:
        return apply_postgres_migrations(connection)
    finally:
        connection.close()


def open_application_database(database_path):
    _require_postgresql(database_path)
    return connect_postgres(database_path)
