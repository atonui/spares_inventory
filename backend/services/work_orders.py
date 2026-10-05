"""Read-only work-order queries using a caller-owned connection."""
import sqlite3


def list_work_orders(conn: sqlite3.Connection, user_id: int) -> list[dict]:
    actor = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
    query = '''SELECT wo.*, u.name as engineer_name
        FROM work_orders wo
        LEFT JOIN users u ON wo.assigned_engineer_id = u.id'''
    params = ()
    if actor['role'] not in ('admin', 'superadmin'):
        query += ' WHERE wo.assigned_engineer_id = ?'
        params = (user_id,)
    query += ' ORDER BY wo.created_at DESC'
    return [dict(row) for row in conn.execute(query, params)]
