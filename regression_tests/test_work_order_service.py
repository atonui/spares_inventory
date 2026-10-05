import pytest
from backend.database import initialize_database,connect_database
from regression_tests.test_work_orders import seed_orders
from backend.services.work_orders import list_work_orders

@pytest.fixture
def conn(tmp_path):
    path=tmp_path/'service.db';initialize_database(path,defaults={})
    c=connect_database(path)
    c.executemany('INSERT INTO users(id,email,name,password_hash,role) VALUES(?,?,?,?,?)',[
        (i,f'{i}@test','User '+str(i),'unused',role) for i,role in [(1,'admin'),(2,'superadmin'),(3,'engineer'),(4,'manager')]])
    seed_orders(c);c.commit()
    yield c
    c.close()

@pytest.mark.parametrize('actor,expected',[(1,[103,102,101,104]),(2,[103,102,101,104]),(3,[101]),(4,[102])])
def test_query_service_matches_role_visibility(conn,actor,expected):
    assert [r['id'] for r in list_work_orders(conn,actor)]==expected

def test_query_service_empty_result(conn):
    conn.execute('DELETE FROM work_orders');conn.commit()
    assert list_work_orders(conn,1)==[]

def test_query_service_preserves_borrowed_transaction(conn):
    conn.execute('BEGIN')
    conn.execute("INSERT INTO work_orders(id,work_order_number,assigned_engineer_id,created_at) VALUES(105,'TEMP',3,'2026-10-05')")
    assert [r['id'] for r in list_work_orders(conn,3)]==[105,101]
    assert conn.in_transaction
    assert conn.execute('SELECT 1').fetchone()[0]==1
    conn.rollback()
    assert conn.execute('SELECT id FROM work_orders WHERE id=105').fetchone() is None
