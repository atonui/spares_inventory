"""Inventory identity reuse inside a caller-owned transaction."""
from backend.services.stock_access import require_active_record


def add_inventory_quantity(conn, store_id, part_id, quantity, work_order_id):
    """Reuse one matching row, including NULL allocations, under a write lock."""
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    require_active_record(conn,"stores",store_id)
    require_active_record(conn,"parts",part_id)
    row = conn.execute(
        "SELECT id FROM inventory WHERE store_id = ? AND part_id = ? "
        "AND CAST(work_order_id AS NUMERIC) IS CAST(? AS NUMERIC) ORDER BY id LIMIT 1",
        (store_id, part_id, work_order_id),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE inventory SET quantity = quantity + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (quantity, row["id"]),
        )
        return row["id"]
    return conn.execute(
        "INSERT INTO inventory(store_id,part_id,quantity,work_order_id) VALUES(?,?,?,?)",
        (store_id, part_id, quantity, work_order_id),
    ).lastrowid

