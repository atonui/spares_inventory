"""Version 10: store hashes instead of live SQLite session credentials."""

from hashlib import sha256
import re


VERSION = 10
NAME = "hashed_sqlite_sessions"
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def upgrade(conn):
    rows = conn.execute("SELECT id, session_token FROM sessions").fetchall()
    for row in rows:
        token = row["session_token"] if hasattr(row, "keys") else row[1]
        identifier = row["id"] if hasattr(row, "keys") else row[0]
        if not _HASH.fullmatch(token):
            conn.execute(
                "UPDATE sessions SET session_token = ? WHERE id = ?",
                (_hash(token), identifier),
            )
    conn.execute("UPDATE users SET session_token = NULL, session_expires = NULL")


def validate(conn):
    for row in conn.execute("SELECT session_token FROM sessions"):
        token = row["session_token"] if hasattr(row, "keys") else row[0]
        if not _HASH.fullmatch(token):
            raise RuntimeError("SQLite session credential hashes are missing or malformed")
