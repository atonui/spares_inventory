"""Independent legacy schemas and real SQLite snapshots for migration tests."""
import sqlite3
from pathlib import Path

FIXTURES=Path(__file__).parent/'fixtures'

def legacy_connection(path, *, current=False):
    conn=sqlite3.connect(path)
    conn.row_factory=sqlite3.Row
    conn.executescript((FIXTURES/('current_unversioned.sql' if current else 'legacy_inventory.sql')).read_text())
    conn.execute("INSERT INTO users(id,email,name,password_hash,role) VALUES(7,'test@example.com','Test','hash','superadmin')")
    conn.execute("INSERT INTO stores(id,name,type) VALUES(1,'Warehouse','central')")
    conn.execute("INSERT INTO parts(id,part_number,description) VALUES(1,'PART','Part')")
    conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity,min_threshold) VALUES(1,1,1,19,2)')
    conn.execute("INSERT INTO movements(id,from_store_id,part_id,quantity,movement_type,created_by) VALUES(1,1,1,3,'consume',7)")
    conn.commit()
    return conn

def snapshot(conn, *, ledger=True):
    tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name") if ledger or r[0]!='schema_migrations']
    return {t:[tuple(r) for r in conn.execute('SELECT * FROM "'+t+'" ORDER BY rowid')] for t in tables}

def schema_snapshot(conn):
    return [tuple(r) for r in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
