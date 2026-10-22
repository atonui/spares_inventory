"""Version 7: short-lived desktop approvals for native mobile sessions."""

VERSION = 7
NAME = "mobile_pairing"

SQL = '''CREATE TABLE mobile_pairing_requests (
    request_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    qr_token_hash TEXT NOT NULL UNIQUE,
    claim_token_hash TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('created', 'pending', 'approved', 'consumed', 'cancelled')),
    device_name TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    claimed_at TEXT,
    approved_at TEXT,
    consumed_at TEXT
)'''


def upgrade(conn):
    conn.execute(SQL)
    conn.execute("CREATE INDEX idx_mobile_pairing_user_created ON mobile_pairing_requests(user_id, created_at DESC)")


def validate(conn):
    from .validation import validate_current
    validate_current(conn, require_mobile_pairing=True)
