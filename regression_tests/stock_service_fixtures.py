"""Small real databases for shared stock-service tests."""
from backend.database import initialize_database,connect_database
from stock_audit import balance_snapshot,change_after,record_stock_audit


def make_stock_database(path):
    initialize_database(path,defaults={})
    with connect_database(path) as c:
        c.executemany('INSERT INTO users(id,email,name,password_hash,role) VALUES(?,?,?,?,?)',[
            (i,f'{i}@test',f'User {i}','unused',role) for i,role in [(1,'admin'),(2,'superadmin'),(3,'engineer'),(4,'manager')]])
        c.executemany('INSERT INTO stores(id,name,type,assigned_user_id) VALUES(?,?,?,?)',[(1,'Central','central',None),(2,'Car 3','car',3),(3,'Car 4','car',4)])
        c.execute("INSERT INTO parts(id,part_number) VALUES(1,'PART')")
        c.execute("INSERT INTO work_orders(id,work_order_number,assigned_engineer_id) VALUES(7,'WO-7',3)")
        c.executemany('INSERT INTO inventory(id,store_id,part_id,work_order_id,quantity,updated_at) VALUES(?,?,1,?,?,?)',[(11,1,None,10,'2000-01-01'),(12,2,None,5,'2000-01-01'),(13,2,7,8,'2000-01-01')])
    return path


def write_stock_evidence(conn,quantity):
    before=balance_snapshot(conn,1,1,None)
    conn.execute('UPDATE inventory SET quantity=? WHERE id=11',(quantity,))
    movement=conn.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,created_by) VALUES(1,1,1,'add',1)").lastrowid
    record_stock_audit(conn,1,'add_stock',[change_after(conn,before)],[movement])


def stock_state(conn):
    return (conn.execute('SELECT quantity FROM inventory WHERE id=11').fetchone()[0],
            conn.execute('SELECT COUNT(*) FROM movements').fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='add_stock'").fetchone()[0])
