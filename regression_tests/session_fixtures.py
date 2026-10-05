"""Explicitly closed disposable session databases for real SQLite tests."""
import sqlite3
from contextlib import closing
from backend.database import initialize_database, connect_database


def session_database(path):
    initialize_database(path, defaults={})
    with closing(connect_database(path)) as conn, conn:
        conn.executemany('INSERT INTO users(id,email,name,password_hash,role) VALUES(?,?,?,?,?)',
            [(1,'admin@example.test','Admin','unused','admin'),(2,'root@example.test','Root','unused','superadmin'),(3,'engineer@example.test','Engineer','unused','engineer')])
        conn.executemany('INSERT INTO sessions(id,user_id,session_token,expires_at) VALUES(?,?,?,?)',
            [(1,1,'admin-token','2099-01-01'),(2,2,'root-token','2099-01-01'),(3,3,'engineer-token','2099-01-01')])
        conn.execute("INSERT INTO stores(id,name,type) VALUES(1,'Warehouse','central')")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(1,'PART','Test part','test',0)")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(1,1,1,10)')
    return path


def record_state(path):
    with closing(connect_database(path)) as conn:
        return (conn.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0],
            conn.execute('SELECT COUNT(*) FROM movements').fetchone()[0],
            conn.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0])
