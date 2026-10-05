"""Version 3: archive metadata and NULL-safe inventory identity constraints."""
VERSION = 3
NAME = 'archiving_integrity'

def upgrade(conn):
    conn.execute('UPDATE activity_logs SET user_id=NULL WHERE user_id=0 AND NOT EXISTS(SELECT 1 FROM users WHERE id=0)')
    from .validation import validate_integrity
    validate_integrity(conn)
    for table in ('users','stores','parts'):
        if 'archived_at' not in {r[1] for r in conn.execute(f'PRAGMA table_info({table})')}:
            conn.execute(f'ALTER TABLE {table} ADD COLUMN archived_at TEXT')
    conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_unallocated_unique ON inventory(store_id,part_id) WHERE work_order_id IS NULL')
    conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_allocated_unique ON inventory(store_id,part_id,CAST(work_order_id AS NUMERIC)) WHERE work_order_id IS NOT NULL')

def validate(conn):
    from .validation import validate_current
    validate_current(conn)
