"""Validate a request's original session on a borrowed transaction connection."""
import sqlite3
from datetime import datetime, timezone
from fastapi import HTTPException


def require_session(conn: sqlite3.Connection, session_token: str | None,
                    *, expected_user_id: int | None = None) -> sqlite3.Row:
    if not conn.in_transaction:
        raise ValueError('Session validation requires an active transaction')
    if not session_token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    try:
        row = cursor.execute('''SELECT s.id AS session_id, s.user_id, s.expires_at, u.role, u.name
            FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.session_token=? AND s.is_active=1 AND u.archived_at IS NULL''',
            (session_token,)).fetchone()
    finally:
        cursor.close()
    if not row or (expected_user_id is not None and row['user_id'] != expected_user_id):
        raise HTTPException(status_code=401, detail='Invalid or expired session')
    try:
        expires = datetime.fromisoformat(row['expires_at'])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail='Invalid or expired session') from None
    if datetime.now(timezone.utc) >= expires:
        raise HTTPException(status_code=401, detail='Session expired')
    return row
