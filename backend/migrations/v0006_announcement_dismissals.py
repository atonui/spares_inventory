"""Version 6: account-scoped notice dismissal; existing notices remain unchanged."""
VERSION=6
NAME='announcement_dismissals'
SQL='''CREATE TABLE announcement_dismissals (
    user_id INTEGER NOT NULL REFERENCES users(id),
    revision TEXT NOT NULL,
    dismissed_at TEXT NOT NULL,
    PRIMARY KEY(user_id, revision)
)'''
def upgrade(conn):
    conn.execute(SQL)
def validate(conn):
    from .validation import validate_current
    validate_current(conn,require_announcements=True)
