"""Version 8: map desktop-approved native sessions to revocable devices."""

VERSION = 8
NAME = "mobile_device_sessions"

SQL = '''CREATE TABLE mobile_device_sessions (
    request_id TEXT PRIMARY KEY REFERENCES mobile_pairing_requests(request_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id INTEGER NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    paired_at TEXT NOT NULL,
    revoked_at TEXT
)'''


def upgrade(conn):
    conn.execute(SQL)
    conn.execute("CREATE INDEX idx_mobile_device_user_paired ON mobile_device_sessions(user_id, paired_at DESC)")


def validate(conn):
    from .validation import validate_current
    validate_current(conn, require_mobile_pairing=True, require_mobile_devices=True)
