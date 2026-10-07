"""Administrative authorization guards with explicit connection ownership."""

import sqlite3
from fastapi import HTTPException


def check_admin(user_id: int, conn=None, get_connection=None) -> bool:
    """Check current authority, borrowing an owning mutation connection."""
    close = conn is None
    if close:
        conn = get_connection()
    try:
        user = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
        return bool(user and user['role'] in {'admin', 'superadmin'})
    finally:
        if close:
            conn.close()


def require_archive_admin(conn,user_id):
    actor=conn.execute('SELECT role FROM users WHERE id=? AND archived_at IS NULL',(user_id,)).fetchone()
    if not actor or actor['role'] not in ('admin','superadmin'):
        raise HTTPException(status_code=403,detail='Admin access required')


def require_user_management(user_id: int, requested_role=None, target_user_id=None, *, conn=None, get_connection=None):
    """Protect privileged role assignment and existing superadmin accounts."""
    close = conn is None
    if close:
        conn = get_connection()
    try:
        actor = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        target = (conn.execute("SELECT role FROM users WHERE id = ?", (target_user_id,)).fetchone()
                  if target_user_id is not None else None)
    finally:
        if close:
            conn.close()
    if not actor or actor["role"] not in {"admin", "superadmin"}:
        raise HTTPException(status_code=403, detail="Admin access required")
    if actor["role"] != "superadmin" and (
        requested_role == "superadmin" or (target and target["role"] == "superadmin")
    ):
        raise HTTPException(status_code=403, detail="Superadmin access required")


def require_superadmin(user_id: int, conn=None, get_connection=None):
    """Raise 403 unless the caller has role == 'superadmin'."""
    close = conn is None
    if close:
        conn = get_connection()
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        row = cur.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
    finally:
        cur.close()
        if close:
            conn.close()
    if not row or row["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")

