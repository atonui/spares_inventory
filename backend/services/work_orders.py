"""Read-only work-order queries using a caller-owned connection."""
import sqlite3
from backend.temporal_contract import register_instant_comparison


def list_work_orders(conn: sqlite3.Connection, user_id: int) -> list[dict]:
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
