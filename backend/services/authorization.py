"""Administrative authorization guards with explicit connection ownership."""

import sqlite3
from dataclasses import replace
from fastapi import HTTPException
from backend.database_sql import is_postgres
from .principals import AuthenticatedPrincipal


def check_admin(user_id: int | AuthenticatedPrincipal, conn=None, get_connection=None) -> bool:
    """Check tenant-admin authority for a PostgreSQL principal or legacy SQLite user.

    PostgreSQL callers must provide a server-resolved principal. An integer user
    ID is supported only by the legacy single-tenant SQLite authorization model.
    """
    if isinstance(user_id, AuthenticatedPrincipal):
        try:
            require_company_admin(user_id, conn=conn)
            return True
        except HTTPException:
            return False
    close = conn is None
    if close:
        conn = get_connection()
    try:
        if is_postgres(conn):
            return False
        user = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
        return bool(user and user['role'] in {'admin', 'superadmin'})
    finally:
        if close:
            conn.close()


def current_company_principal(
    principal: AuthenticatedPrincipal, conn
) -> AuthenticatedPrincipal:
    """Refresh tenant authority from the membership inside the scoped transaction."""
    if not isinstance(principal, AuthenticatedPrincipal) or principal.organization_id is None:
        raise HTTPException(status_code=403, detail="Company administrator access required")
    scope = conn.execute(
        "SELECT current_setting('app.organization_id', TRUE) AS organization_id"
    ).fetchone()
    if scope is None or scope["organization_id"] != str(principal.organization_id):
        raise HTTPException(status_code=403, detail="Company tenant context is missing or mismatched")
    row = conn.execute(
        """SELECT om.company_role
           FROM organization_memberships AS om
           JOIN organizations AS o ON o.id = om.organization_id
           WHERE om.organization_id = %s AND om.user_id = %s
             AND om.is_active = TRUE AND o.is_active = TRUE""",
        (principal.organization_id, principal.user_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="Active company membership required")
    return replace(principal, company_role=row["company_role"], organization_is_active=True)


def require_company_admin(
    principal: AuthenticatedPrincipal, conn=None
) -> AuthenticatedPrincipal:
    """Require current owner/admin membership when a scoped connection is available."""
    current = current_company_principal(principal, conn) if conn is not None else principal
    if (current.organization_id is None or not current.organization_is_active
            or current.company_role not in {"owner", "admin"}):
        raise HTTPException(status_code=403, detail="Company administrator access required")
    return current


def require_company_owner(
    principal: AuthenticatedPrincipal, conn=None
) -> AuthenticatedPrincipal:
    """Require the current owner role, refreshing it from the scoped database transaction."""
    current = current_company_principal(principal, conn) if conn is not None else principal
    if (current.organization_id is None or not current.organization_is_active
            or current.company_role != "owner"):
        raise HTTPException(status_code=403, detail="Company owner access required")
    return current


def require_platform_admin(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    """Require platform authority independently of any company role."""
    if not principal.is_platform_admin:
        raise HTTPException(status_code=403, detail="Platform administrator access required")
    return principal


def require_archive_admin(conn,user_id):
    if isinstance(user_id, AuthenticatedPrincipal):
        require_company_admin(user_id, conn=conn)
        return
    if is_postgres(conn):
        raise HTTPException(status_code=403, detail="Company administrator access required")
    actor=conn.execute('SELECT role FROM users WHERE id=? AND archived_at IS NULL',(user_id,)).fetchone()
    if not actor or actor['role'] not in ('admin','superadmin'):
        raise HTTPException(status_code=403,detail='Admin access required')


def require_user_management(user_id: int | AuthenticatedPrincipal, requested_role=None,
                            target_user_id=None, *, conn=None, get_connection=None):
    """Protect legacy SQLite user-role management and superadmin accounts.

    PostgreSQL management is scoped to the actor's current organization membership.
    """
    if isinstance(user_id, AuthenticatedPrincipal):
        if user_id.organization_id is None:
            raise HTTPException(status_code=403, detail="Admin access required")
        if conn is None:
            raise ValueError("A tenant transaction connection is required for company user management")
        actor = conn.execute(
            """SELECT om.company_role FROM organization_memberships AS om
               JOIN organizations AS o ON o.id = om.organization_id
               WHERE om.organization_id = %s AND om.user_id = %s
                 AND om.is_active = TRUE AND o.is_active = TRUE""",
            (user_id.organization_id, user_id.user_id),
        ).fetchone()
        if actor is None or actor["company_role"] not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Admin access required")
        actor_role = actor["company_role"]
        if requested_role == "superadmin":
            raise HTTPException(status_code=403, detail="Platform administrator access required")
        if requested_role == "admin" and actor_role != "owner":
            raise HTTPException(status_code=403, detail="Only the owner can assign the admin role")
        if target_user_id is None:
            return
        target = conn.execute(
            """SELECT company_role FROM organization_memberships
               WHERE organization_id = %s AND user_id = %s""",
            (user_id.organization_id, target_user_id),
        ).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="Company member not found")
        if target["company_role"] == "owner":
            raise HTTPException(status_code=403, detail="Use the ownership transfer operation")
        if target["company_role"] == "admin" and actor_role != "owner":
            raise HTTPException(status_code=403, detail="Only the owner can manage an admin")
        return

    close = conn is None
    if close:
        conn = get_connection()
    try:
        if is_postgres(conn):
            raise HTTPException(status_code=403, detail="Company administrator access required")
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
        close = conn is None
        if close:
            conn = get_connection() if get_connection else None
        if conn is None:
            if user_id.is_platform_admin:
                return
            raise HTTPException(status_code=403, detail="Platform administrator access required")
        try:
            import psycopg
            if isinstance(conn, psycopg.Connection):
                row = conn.execute(
                    "SELECT 1 FROM platform_admins WHERE user_id = %s", (user_id.user_id,)
                ).fetchone()
                allowed = row is not None
            else:
                row = conn.execute(
                    "SELECT role FROM users WHERE id = ?", (user_id.user_id,)
                ).fetchone()
                allowed = bool(row and row["role"] == "superadmin")
        finally:
            if close and conn is not None:
                conn.close()
        if not allowed:
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

