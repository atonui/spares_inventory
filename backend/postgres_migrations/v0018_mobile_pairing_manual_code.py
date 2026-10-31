"""Version 18: add a hashed one-time manual pairing code."""

VERSION = 18
NAME = "mobile_pairing_manual_code"

SQL = (
    "ALTER TABLE mobile_pairing_requests ADD COLUMN pairing_code_hash TEXT UNIQUE CHECK (pairing_code_hash IS NULL OR pairing_code_hash ~ '^[0-9a-f]{64}$')",
    "DROP POLICY mobile_pairing_token_scope ON mobile_pairing_requests",
    """CREATE POLICY mobile_pairing_token_scope ON mobile_pairing_requests
        USING (
            user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), '')
            OR qr_token_hash = NULLIF(current_setting('app.mobile_pairing_qr_token_hash', true), '')
            OR pairing_code_hash = NULLIF(current_setting('app.mobile_pairing_code_hash', true), '')
            OR claim_token_hash = NULLIF(current_setting('app.mobile_pairing_claim_token_hash', true), '')
        )
        WITH CHECK (
            user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), '')
            OR qr_token_hash = NULLIF(current_setting('app.mobile_pairing_qr_token_hash', true), '')
            OR pairing_code_hash = NULLIF(current_setting('app.mobile_pairing_code_hash', true), '')
            OR claim_token_hash = NULLIF(current_setting('app.mobile_pairing_claim_token_hash', true), '')
        )""",
)
