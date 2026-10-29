"""Version 15: login-bound, expiring platform support sessions."""

VERSION = 15
NAME = "platform_support_sessions"

SQL = (
    """CREATE TABLE platform_support_sessions (
       id UUID PRIMARY KEY,
       actor_user_id BIGINT NOT NULL REFERENCES users(id),
       auth_session_id BIGINT NOT NULL REFERENCES sessions(id),
       organization_id UUID NOT NULL REFERENCES organizations(id),
       reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 500),
       created_at TEXT NOT NULL,
       expires_at TEXT NOT NULL,
       ended_at TEXT,
       CHECK (expires_at::timestamptz = created_at::timestamptz + interval '15 minutes')
    )""",
    "CREATE INDEX idx_platform_support_live ON platform_support_sessions(actor_user_id, auth_session_id, expires_at) WHERE ended_at IS NULL",
    "CREATE INDEX idx_platform_support_organization ON platform_support_sessions(organization_id, created_at DESC)",
    "REVOKE ALL ON platform_support_sessions FROM PUBLIC",
)
