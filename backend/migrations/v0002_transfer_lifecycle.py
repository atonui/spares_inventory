"""Version 2: transfer lifecycle; historical movements are not re-dispatched."""
VERSION = 2
NAME = 'transfer_lifecycle'
SQL = ("""CREATE TABLE IF NOT EXISTS stock_transfers (
            movement_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'in_transit'
                CHECK(status IN ('in_transit','received','returned')),
            source_min_threshold INTEGER NOT NULL DEFAULT 0,
            completed_by INTEGER,
            completed_at TIMESTAMP,
            completion_note TEXT,
            FOREIGN KEY(movement_id) REFERENCES movements(id),
            FOREIGN KEY(completed_by) REFERENCES users(id)
        )""",'CREATE INDEX IF NOT EXISTS idx_transfer_status ON stock_transfers(status)')

def upgrade(conn):
    for statement in SQL:conn.execute(statement)

def validate(conn):
    from .validation import validate_tables
    validate_tables(conn, include_transfer=True, allow_archive=True)
