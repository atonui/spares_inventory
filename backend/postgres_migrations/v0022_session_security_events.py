"""Version 22: extend global security taxonomy for credential lifecycle events."""
VERSION = 22
NAME = "session_security_events"
SQL = (
    "ALTER TABLE platform_security_events DROP CONSTRAINT platform_security_events_event_check",
    """ALTER TABLE platform_security_events ADD CONSTRAINT platform_security_events_event_check
       CHECK (event IN (
           'login_succeeded','login_failed','login_blocked','account_locked',
           'password_reset_requested','password_reset_failed','password_reset_completed',
           'password_changed','session_revoked','session_issued','session_rotated'
       ))""",
)
