"""Read-only work-order queries using a caller-owned connection."""
import sqlite3
from backend.temporal_contract import register_instant_comparison
from fastapi import HTTPException

from .principals import AuthenticatedPrincipal


def list_work_orders(conn: sqlite3.Connection, user_id: int | AuthenticatedPrincipal) -> list[dict]:
    if isinstance(user_id, AuthenticatedPrincipal):
        if user_id.organization_id is None or user_id.company_role is None:
            raise HTTPException(status_code=403, detail="Company membership required")
        query = '''SELECT wo.*, u.name as engineer_name
            FROM work_orders wo
            LEFT JOIN users u ON wo.assigned_engineer_id = u.id
            WHERE wo.organization_id = %s'''
        params = [user_id.organization_id]
        if user_id.company_role not in ("owner", "admin"):
            query += " AND wo.assigned_engineer_id = %s"
            params.append(user_id.user_id)
        query += " ORDER BY wo.created_at DESC, wo.id DESC"
        return [dict(row) for row in conn.execute(query, params)]

    register_instant_comparison(conn)
    actor = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
    query = '''SELECT wo.*, u.name as engineer_name
        FROM work_orders wo
        LEFT JOIN users u ON wo.assigned_engineer_id = u.id'''
    params = ()
    if actor['role'] not in ('admin', 'superadmin'):
        query += ' WHERE wo.assigned_engineer_id = ?'
        params = (user_id,)
    query += ' ORDER BY utc_instant(wo.created_at) DESC, wo.id DESC'
    return [dict(row) for row in conn.execute(query, params)]
