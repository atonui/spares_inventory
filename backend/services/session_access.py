"""Validate a request's original session on a borrowed transaction connection."""
import sqlite3
from backend.temporal import utc_now
from backend.temporal_contract import stored_instant
from backend.services.session_credentials import hash_session_credential
from fastapi import HTTPException


def require_session(conn: sqlite3.Connection, session_token: str | None,
                    *, expected_user_id: int | None = None) -> sqlite3.Row:
    if not conn.in_transaction:
        raise ValueError('Session validation requires an active transaction')
    if not session_token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    token_hash = hash_session_credential(session_token)
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    try:
        row = cursor.execute('''SELECT s.id AS session_id, s.user_id, s.expires_at, u.role, u.name
            FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.session_token=? AND s.is_active=1 AND u.archived_at IS NULL''',
            (token_hash,)).fetchone()
        if row is None:
            # Upgrade an un-migrated database lazily while preserving existing sessions.
            row = cursor.execute('''SELECT s.id AS session_id, s.user_id, s.expires_at, u.role, u.name
                FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.session_token=? AND s.is_active=1 AND u.archived_at IS NULL''',
                (session_token,)).fetchone()
            if row is not None:
                cursor.execute(
                    "UPDATE sessions SET session_token=? WHERE id=? AND session_token=?",
                    (token_hash, row["session_id"], session_token),
                )
    finally:
        cursor.close()
    if not row or (expected_user_id is not None and row['user_id'] != expected_user_id):
        raise HTTPException(status_code=401, detail='Invalid or expired session')
    try:
        expires = stored_instant(row['expires_at'], 'expires_at')
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail='Invalid or expired session') from None
    if utc_now() >= expires:
        raise HTTPException(status_code=401, detail='Session expired')
    return row
