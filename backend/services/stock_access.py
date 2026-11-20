"""Access and active-record checks on a caller-owned connection."""
from fastapi import HTTPException
from backend.database_sql import execute
from .principals import AuthenticatedPrincipal


def require_active_record(conn,table,identifier):
    if table not in ('users','stores','parts'):
        raise ValueError('Unsupported active record type')
    postgres = hasattr(conn, "info")
    if postgres and table == 'users':
        # Users are global; on PostgreSQL an active user means an active membership
        # in the company whose RLS context this transaction carries.
        row=conn.execute(
            """SELECT u.archived_at, m.is_active FROM users u
               JOIN organization_memberships m ON m.user_id = u.id
                AND m.organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
               WHERE u.id = %s""",
            (identifier,),
        ).fetchone()
        if row and row['archived_at'] is None and not row['is_active']:
            raise HTTPException(status_code=400,detail='users record is inactive in this company; reactivate the member first')
    else:
        placeholder = "%s" if postgres else "?"
        row=conn.execute(f'SELECT archived_at FROM {table} WHERE id={placeholder}',(identifier,)).fetchone()
    if not row:
        raise HTTPException(status_code=400,detail=f'{table} record does not exist')
    if row['archived_at'] is not None:
        raise HTTPException(status_code=400,detail=f'{table} record is archived; restore it first')



def require_stock_access(conn, user_id, store_type, store_owner, *, store_organization_id=None):
    if isinstance(user_id, AuthenticatedPrincipal):
        allowed = (
            user_id.organization_id is not None
            and user_id.organization_is_active
            and store_organization_id is not None
            and store_organization_id == user_id.organization_id
            and (
                user_id.company_role in {"owner", "admin"}
                or store_owner == user_id.user_id
                or store_type == "central"
            )
        )
        if allowed:
            return
        raise HTTPException(status_code=403, detail="Permission denied for this store")
    actor = execute(conn, "SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if actor and (actor["role"] in {"admin", "superadmin"}
                  or store_owner == user_id or store_type == "central"):
        return
    raise HTTPException(status_code=403, detail="Permission denied for this store")

