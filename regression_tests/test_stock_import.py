import sqlite3
import pytest
from regression_tests.test_stock_safety import api


def seed(api):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(90,'Import test','engineer',3)")
        c.executemany('INSERT INTO parts(id,part_number,description) VALUES(?,?,?)', [(900,'CSV-A','A'),(901,'CSV-B','B')])
        c.execute('INSERT INTO inventory(store_id,part_id,quantity,min_threshold) VALUES(90,900,7,2)')


def post(api, rows):
    return api[0].post('/api/inventory/import-balances', json={'store_id':90,'rows':rows})


def test_repeat_import_sets_balance_without_extra_movements(api):
    seed(api)
    assert post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':7}]).status_code == 200
    assert post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':4}]).status_code == 200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold FROM inventory WHERE store_id=90').fetchall() == [(4,2)]
        assert c.execute("SELECT COUNT(*) FROM movements WHERE part_id=900 AND movement_type='remove'").fetchone()[0] == 1


@pytest.mark.parametrize('bad_row',[
    {'part_number':'MISSING','quantity':2,'expected_quantity':None},
    {'part_number':'CSV-B','quantity':'4abc','expected_quantity':None},
    {'part_number':'CSV-B','quantity':-1,'expected_quantity':None},
    {'part_number':'CSV-B','quantity':True,'expected_quantity':None},
    {'part_number':'CSV-B','quantity':1.5,'expected_quantity':None},
])
def test_invalid_batch_leaves_all_stock_unchanged(api,bad_row):
    seed(api)
    response=post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':7},bad_row])
    assert response.status_code in (400,422)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT part_id,quantity FROM inventory WHERE store_id=90').fetchall() == [(900,7)]


def test_stale_preview_rejects_whole_batch(api):
    seed(api)
    response=post(api,[{'part_number':'CSV-B','quantity':2,'expected_quantity':None},{'part_number':'CSV-A','quantity':4,'expected_quantity':6}])
    assert response.status_code == 409
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT part_id,quantity FROM inventory WHERE store_id=90').fetchall() == [(900,7)]


def test_duplicate_parts_in_request_are_rejected(api):
    seed(api)
    row={'part_number':'CSV-A','quantity':4,'expected_quantity':7}
    assert post(api,[row,row]).status_code == 400


def test_unauthorized_store_import_is_rejected(api):
    seed(api)
    api[2]['id']=4
    assert post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':7}]).status_code == 403


def test_zero_balance_and_new_part_are_supported(api):
    seed(api)
    assert post(api,[{'part_number':'CSV-A','quantity':0,'expected_quantity':7},{'part_number':'CSV-B','quantity':2,'expected_quantity':None}]).status_code == 200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT part_id,quantity FROM inventory WHERE store_id=90 ORDER BY part_id').fetchall() == [(900,0),(901,2)]


def test_import_requires_csrf(api):
    import main
    seed(api)
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':7}]).status_code == 403


def test_inventory_identifies_store_by_id(api):
    seed(api)
    rows=api[0].get('/api/inventory').json()
    stock=next(row for row in rows if row['part_number']=='CSV-A')
    assert stock['store_id']==90


def test_database_write_failure_rolls_back_entire_import(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("CREATE TRIGGER block_import BEFORE INSERT ON inventory WHEN NEW.part_id=901 BEGIN SELECT RAISE(ABORT,'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':7},{'part_number':'CSV-B','quantity':2,'expected_quantity':None}])
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT part_id,quantity FROM inventory WHERE store_id=90').fetchall()==[(900,7)]
        assert c.execute('SELECT COUNT(*) FROM movements WHERE part_id=900').fetchone()[0]==0


def test_import_leaves_allocated_and_omitted_stock_unchanged(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(90,'ALLOCATED')")
        c.execute('INSERT INTO inventory(store_id,part_id,quantity,work_order_id) VALUES(90,900,8,90)')
        c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(90,901,12)')
    assert post(api,[{'part_number':'CSV-A','quantity':4,'expected_quantity':7}]).status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE work_order_id=90').fetchone()[0]==8
        assert c.execute('SELECT quantity FROM inventory WHERE store_id=90 AND part_id=901').fetchone()[0]==12
