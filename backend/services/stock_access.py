"""Access and active-record checks on a caller-owned connection."""
from fastapi import HTTPException
from backend.database_sql import execute
from .principals import AuthenticatedPrincipal


def require_active_record(conn,table,identifier):
    if table not in ('users','stores','parts'):
        raise ValueError('Unsupported active record type')
    placeholder = "%s" if hasattr(conn, "info") else "?"
    row=conn.execute(f'SELECT archived_at FROM {table} WHERE id={placeholder}',(identifier,)).fetchone()
    if not row:
        raise HTTPException(status_code=400,detail=f'{table} record does not exist')
    if row['archived_at'] is not None:
        raise HTTPException(status_code=400,detail=f'{table} record is archived; restore it first')



def require_stock_access(conn, user_id, store_type, store_owner):
    if isinstance(user_id, AuthenticatedPrincipal):
        allowed = (
            user_id.organization_id is not None
            and user_id.company_role in {"owner", "admin"}
        ) or store_owner == user_id.user_id or store_type == "central"
        if allowed:
            return
        raise HTTPException(status_code=403, detail="Permission denied for this store")
    actor = execute(conn, "SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if actor and (actor["role"] in {"admin", "superadmin"}
                  or store_owner == user_id or store_type == "central"):
        return
    raise HTTPException(status_code=403, detail="Permission denied for this store")

