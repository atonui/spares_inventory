"""Additive transfer lifecycle schema, shared by startup and backup restore."""


def ensure_transfer_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS stock_transfers (
            movement_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'in_transit'
                CHECK(status IN ('in_transit','received','returned')),
            source_min_threshold INTEGER NOT NULL DEFAULT 0,
            completed_by INTEGER,
            completed_at TIMESTAMP,
            completion_note TEXT,
            FOREIGN KEY(movement_id) REFERENCES movements(id),
            FOREIGN KEY(completed_by) REFERENCES users(id)
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_transfer_status ON stock_transfers(status)")
