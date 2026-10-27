"""Administrative authorization guards with explicit connection ownership."""

import sqlite3
from fastapi import HTTPException
from .principals import AuthenticatedPrincipal


def check_admin(user_id: int, conn=None, get_connection=None) -> bool:
    """Check current authority, borrowing an owning mutation connection."""
    if isinstance(user_id, AuthenticatedPrincipal):
        return (user_id.organization_id is not None and user_id.organization_is_active
                and user_id.company_role in {"owner", "admin"})
    close = conn is None
    if close:
        conn = get_connection()
    try:
        user = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
        return bool(user and user['role'] in {'admin', 'superadmin'})
    finally:
        if close:
            conn.close()


def require_company_admin(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    """Require an active, server-resolved owner or admin company membership."""
    if (principal.organization_id is None or not principal.organization_is_active
            or principal.company_role not in {"owner", "admin"}):
        raise HTTPException(status_code=403, detail="Company administrator access required")
    return principal


def require_platform_admin(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    """Require platform authority independently of any company role."""
    if not principal.is_platform_admin:
        raise HTTPException(status_code=403, detail="Platform administrator access required")
    return principal


def require_archive_admin(conn,user_id):
    if isinstance(user_id, AuthenticatedPrincipal):
        if (user_id.organization_id is None or not user_id.organization_is_active
                or user_id.company_role not in {"owner", "admin"}):
            raise HTTPException(status_code=403,detail='Admin access required')
        return
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
    """Require platform authority on PostgreSQL and preserve SQLite compatibility."""
    if isinstance(user_id, AuthenticatedPrincipal):
        if not user_id.is_platform_admin:
            raise HTTPException(status_code=403, detail="Platform administrator access required")
        return
    close = conn is None
    if close:
        conn = get_connection()
    try:
        import psycopg
        if isinstance(conn, psycopg.Connection):
            row = conn.execute(
                "SELECT 1 FROM platform_admins WHERE user_id = %s", (user_id,)
            ).fetchone()
            allowed = row is not None
        else:
            cur = conn.cursor()
            cur.row_factory = sqlite3.Row
            try:
                row = cur.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
            finally:
                cur.close()
            allowed = bool(row and row["role"] == "superadmin")
    finally:
        if close:
            conn.close()
    if not allowed:
        raise HTTPException(status_code=403, detail="Superadmin access required")

