"""Version 5: store PostgreSQL session credentials as SHA-256 hashes."""

VERSION = 5
NAME = "hashed_session_credentials"
SQL = (
    "ALTER TABLE sessions ADD COLUMN session_token_hash TEXT",
    """UPDATE sessions
       SET session_token_hash = encode(sha256(convert_to(session_token, 'UTF8')), 'hex')""",
    "ALTER TABLE sessions ALTER COLUMN session_token_hash SET NOT NULL",
    "CREATE UNIQUE INDEX uq_sessions_session_token_hash ON sessions(session_token_hash)",
    "UPDATE users SET session_token = NULL",
    "ALTER TABLE sessions DROP COLUMN session_token",
)
