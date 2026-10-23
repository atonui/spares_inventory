"""Version 12: add retry keys for native offline stock count updates."""

VERSION = 12
NAME = "mobile_stock_adjustments"
SQL = (
    "ALTER TABLE movements ADD COLUMN client_operation_id TEXT",
    "CREATE UNIQUE INDEX uq_movements_created_operation ON movements(created_by, client_operation_id) WHERE client_operation_id IS NOT NULL",
)
