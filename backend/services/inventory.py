"""Inventory identity reuse inside a caller-owned transaction."""
from backend.database_sql import execute
from backend.services.stock_access import require_active_record
from backend.temporal import serialize_instant, utc_now


def add_inventory_quantity(conn, store_id, part_id, quantity, work_order_id):
    """Reuse one matching row, including NULL allocations, under a write lock."""
    if conn.info.transaction_status.name == "IDLE":
        conn.execute("BEGIN")
    require_active_record(conn,"stores",store_id)
    require_active_record(conn,"parts",part_id)
    statement = (
        "SELECT id FROM inventory WHERE store_id = ? AND part_id = ? "
        "AND work_order_id IS NOT DISTINCT FROM ? ORDER BY id LIMIT 1 FOR UPDATE"
    )
    row = execute(conn, statement, (store_id, part_id, work_order_id)).fetchone()
    if row:
        execute(
            conn,
            "UPDATE inventory SET quantity = quantity + ?, updated_at = ? WHERE id = ?",
            (quantity, serialize_instant(utc_now()), row["id"]),
        )
        return row["id"]
    organization_id = conn.execute(
        "SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid AS id"
    ).fetchone()["id"]
    if work_order_id is None:
        conflict = "(organization_id, store_id, part_id) WHERE work_order_id IS NULL"
    else:
        conflict = "(organization_id, store_id, part_id, work_order_id) WHERE work_order_id IS NOT NULL"
    return conn.execute(
        f"""INSERT INTO inventory(organization_id,store_id,part_id,quantity,work_order_id)
                VALUES(%s,%s,%s,%s,%s)
                ON CONFLICT {conflict} DO UPDATE
                SET quantity = inventory.quantity + EXCLUDED.quantity,
                    updated_at = EXCLUDED.updated_at
                RETURNING id""",
        (organization_id, store_id, part_id, quantity, work_order_id),
    ).fetchone()["id"]

