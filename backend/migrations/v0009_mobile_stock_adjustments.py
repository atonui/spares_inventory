"""Version 9: add retry keys for native offline stock count updates."""

VERSION = 9
NAME = "mobile_stock_adjustments"


def upgrade(conn):
    conn.execute("ALTER TABLE movements ADD COLUMN client_operation_id TEXT")
    conn.execute("CREATE UNIQUE INDEX uq_movements_created_operation ON movements(created_by, client_operation_id) WHERE client_operation_id IS NOT NULL")


def validate(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(movements)").fetchall()}
    if "client_operation_id" not in columns:
        raise RuntimeError("mobile stock idempotency column is missing")
