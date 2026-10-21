"""Version 11: track revocable sessions created through mobile pairing."""

VERSION = 11
NAME = "mobile_device_sessions"

SQL = (
    """CREATE TABLE mobile_device_sessions (
        request_id TEXT PRIMARY KEY REFERENCES mobile_pairing_requests(request_id) ON DELETE CASCADE,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_id BIGINT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
        device_name TEXT NOT NULL,
        paired_at TEXT NOT NULL,
        revoked_at TEXT
    )""",
    "CREATE INDEX idx_mobile_device_user_paired ON mobile_device_sessions(user_id, paired_at DESC)",
    "ALTER TABLE mobile_device_sessions ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY mobile_device_account_scope ON mobile_device_sessions
        USING (user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), ''))
        WITH CHECK (user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), ''))""",
)
