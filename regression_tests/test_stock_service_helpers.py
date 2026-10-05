import sqlite3
from contextlib import closing
import pytest
from fastapi import HTTPException
import main
from backend.database import connect_database
from regression_tests.stock_service_fixtures import make_stock_database

@pytest.fixture
def conn(tmp_path):
    path=make_stock_database(tmp_path/'helpers.db')
    with closing(connect_database(path)) as c:yield c

def test_access_rejection_preserves_borrowed_connection(conn):
    conn.execute('BEGIN IMMEDIATE')
    with pytest.raises(HTTPException) as caught:main.require_stock_access(conn,3,'car',4)
    assert caught.value.status_code==403
    assert caught.value.detail=='Permission denied for this store'
    assert conn.execute('SELECT 1').fetchone()[0]==1
    assert conn.in_transaction

@pytest.mark.parametrize('actor,owner,kind,allowed',[(1,4,'car',True),(2,4,'car',True),(3,3,'car',True),(4,4,'car',True),(3,None,'central',True),(3,4,'car',False),(999,None,'central',False)])
def test_access_matrix_keeps_connection_open(conn,actor,owner,kind,allowed):
    from backend.services.stock_access import require_stock_access
    if allowed:require_stock_access(conn,actor,kind,owner)
    else:
        with pytest.raises(HTTPException) as caught:require_stock_access(conn,actor,kind,owner)
        assert (caught.value.status_code,caught.value.detail)==(403,'Permission denied for this store')
    assert conn.execute('SELECT 1').fetchone()[0]==1

@pytest.mark.parametrize('table,identifier',[('users',3),('stores',2),('parts',1)])
@pytest.mark.parametrize('damage',['missing','archived'])
def test_active_record_rejections_preserve_connection(conn,table,identifier,damage):
    from backend.services.stock_access import require_active_record
    if damage=='missing':identifier=999
    else:conn.execute(f'UPDATE {table} SET archived_at=CURRENT_TIMESTAMP WHERE id=?',(identifier,))
    with pytest.raises(HTTPException) as caught:require_active_record(conn,table,identifier)
    assert caught.value.status_code==400
    assert caught.value.detail==(f'{table} record does not exist' if damage=='missing' else f'{table} record is archived; restore it first')
    assert conn.execute('SELECT 1').fetchone()[0]==1

@pytest.mark.parametrize('table,identifier',[('users',3),('stores',2),('parts',1)])
def test_active_record_accepts_existing_active(conn,table,identifier):
    from backend.services.stock_access import require_active_record
    require_active_record(conn,table,identifier)
    with pytest.raises(ValueError,match='Unsupported active record type'):require_active_record(conn,'system_logs',1)
    assert conn.execute('SELECT 1').fetchone()[0]==1

@pytest.mark.parametrize('allocation',[7,'007','7e0'])
def test_numeric_work_order_identity_is_reused_without_committing(conn,allocation):
    from backend.services.inventory import add_inventory_quantity
    assert add_inventory_quantity(conn,2,1,2,allocation)==13
    assert conn.execute('SELECT quantity FROM inventory WHERE id=13').fetchone()[0]==10
    assert conn.execute('SELECT quantity FROM inventory WHERE id=12').fetchone()[0]==5
    assert conn.execute('SELECT COUNT(*) FROM inventory').fetchone()[0]==3
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute('SELECT quantity FROM inventory WHERE id=13').fetchone()[0]==8

def test_unallocated_identity_and_timestamp_are_updated(conn):
    from backend.services.inventory import add_inventory_quantity
    assert add_inventory_quantity(conn,1,1,3,None)==11
    row=conn.execute('SELECT quantity,updated_at FROM inventory WHERE id=11').fetchone()
    assert row[0]==13 and row[1]!='2000-01-01'
    assert conn.execute('SELECT COUNT(*) FROM inventory').fetchone()[0]==3
    assert conn.in_transaction
    conn.rollback()
    assert tuple(conn.execute('SELECT quantity,updated_at FROM inventory WHERE id=11').fetchone())==(10,'2000-01-01')

def test_new_inventory_row_is_returned_but_not_committed(conn):
    from backend.services.inventory import add_inventory_quantity
    assert add_inventory_quantity(conn,3,1,4,None)==14
    assert tuple(conn.execute('SELECT store_id,part_id,quantity,work_order_id FROM inventory WHERE id=14').fetchone())==(3,1,4,None)
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute('SELECT id FROM inventory WHERE id=14').fetchone() is None
    assert conn.execute('SELECT 1').fetchone()[0]==1

@pytest.mark.parametrize('table,identifier',[('stores',1),('parts',1)])
@pytest.mark.parametrize('damage',['missing','archived'])
def test_inventory_rejects_inactive_records_without_committing(conn,table,identifier,damage):
    from backend.services.inventory import add_inventory_quantity
    store,part=1,1
    if damage=='archived':
        conn.execute(f'UPDATE {table} SET archived_at=CURRENT_TIMESTAMP WHERE id=?',(identifier,));conn.commit()
    elif table=='stores':store=999
    else:part=999
    with pytest.raises(HTTPException) as caught:add_inventory_quantity(conn,store,part,3,None)
    assert caught.value.status_code==400
    assert conn.in_transaction
    assert conn.execute('SELECT quantity FROM inventory WHERE id=11').fetchone()[0]==10
    conn.rollback()
