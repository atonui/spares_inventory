"""Known additive archive migration and stock identity constraints."""


def ensure_archive_schema(connection):
    connection.execute('SAVEPOINT archive_migration')
    try:
        # 0 was the old anonymous-login sentinel. Keep the recorded name/text.
        connection.execute('UPDATE activity_logs SET user_id=NULL WHERE user_id=0 AND NOT EXISTS(SELECT 1 FROM users WHERE id=0)')
        violations=connection.execute('PRAGMA foreign_key_check').fetchall()
        if violations:
            raise ValueError(f'Database has invalid foreign references: {list(map(tuple,violations[:10]))}')
        duplicates=connection.execute('SELECT store_id,part_id,CAST(work_order_id AS NUMERIC),COUNT(*) FROM inventory GROUP BY store_id,part_id,CAST(work_order_id AS NUMERIC) HAVING COUNT(*)>1').fetchall()
        if duplicates:
            raise ValueError(f'Database has duplicate stock keys; reconcile before upgrading: {list(map(tuple,duplicates[:10]))}')
        for table in ('users','stores','parts'):
            columns={row[1] for row in connection.execute(f'PRAGMA table_info({table})')}
            if 'archived_at' not in columns:
                connection.execute(f'ALTER TABLE {table} ADD COLUMN archived_at TEXT')
        connection.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_unallocated_unique ON inventory(store_id,part_id) WHERE work_order_id IS NULL')
        connection.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_allocated_unique ON inventory(store_id,part_id,CAST(work_order_id AS NUMERIC)) WHERE work_order_id IS NOT NULL')
        connection.execute('RELEASE archive_migration')
    except Exception:
        connection.execute('ROLLBACK TO archive_migration')
        connection.execute('RELEASE archive_migration')
        raise
