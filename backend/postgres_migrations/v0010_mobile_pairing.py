"""Version 10: one-time desktop approvals for native mobile sessions."""

VERSION = 10
NAME = "mobile_pairing"

SQL = (
    """CREATE TABLE mobile_pairing_requests (
        request_id TEXT PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        qr_token_hash TEXT NOT NULL UNIQUE CHECK (qr_token_hash ~ '^[0-9a-f]{64}$'),
        claim_token_hash TEXT UNIQUE CHECK (claim_token_hash IS NULL OR claim_token_hash ~ '^[0-9a-f]{64}$'),
        status TEXT NOT NULL CHECK (status IN ('created', 'pending', 'approved', 'consumed', 'cancelled')),
        device_name TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        claimed_at TEXT,
        approved_at TEXT,
        consumed_at TEXT
    )""",
    "CREATE INDEX idx_mobile_pairing_user_created ON mobile_pairing_requests(user_id, created_at DESC)",
    "ALTER TABLE mobile_pairing_requests ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY mobile_pairing_token_scope ON mobile_pairing_requests
        USING (
            user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), '')
            OR qr_token_hash = NULLIF(current_setting('app.mobile_pairing_qr_token_hash', true), '')
            OR claim_token_hash = NULLIF(current_setting('app.mobile_pairing_claim_token_hash', true), '')
        )
        WITH CHECK (
            user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), '')
            OR qr_token_hash = NULLIF(current_setting('app.mobile_pairing_qr_token_hash', true), '')
            OR claim_token_hash = NULLIF(current_setting('app.mobile_pairing_claim_token_hash', true), '')
        )""",
)
