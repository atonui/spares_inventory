import sqlite3
import pytest
import main
from regression_tests.test_stock_safety import api


def seed(api):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(980,'Sender','car',3),(981,'Recipient','car',4)")
        c.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(980,'RECEIPT','Receipt Test','test',0)")
        c.execute('INSERT INTO inventory(id,store_id,part_id,quantity,min_threshold) VALUES(980,980,980,10,2)')
    api[2]['id']=3


def dispatch(api, quantity=4):
    return api[0].post('/api/inventory/transfer',json={'inventory_id':980,'to_store_id':981,'quantity':quantity})


def finish(api,mid,action='receive',confirmed=True):
    return api[0].post(f'/api/inventory/transfers/{mid}/{action}',json={'confirmed':confirmed})


def test_dispatch_deducts_source_but_does_not_make_destination_available(api):
    seed(api)
    response=dispatch(api)
    assert response.status_code==200
    assert 'transfer_id' in response.json()
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=980').fetchone()[0]==6
        assert c.execute('SELECT COUNT(*) FROM inventory WHERE store_id=981').fetchone()[0]==0
    pending=api[0].get('/api/inventory/transfers').json()
    assert pending[0]['status']=='in_transit'
    assert pending[0]['quantity']==4
    assert api[0].get('/api/stats').json()['in_transit_quantity']==4


def test_receipt_adds_stock_once_and_records_recipient(api):
    seed(api);mid=dispatch(api).json()['transfer_id'];api[2]['id']=4
    assert finish(api,mid).status_code==200
    assert finish(api,mid).status_code==409
    assert finish(api,mid,'return').status_code in (403,409)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT SUM(quantity) FROM inventory WHERE part_id=980').fetchone()[0]==10
        assert c.execute('SELECT quantity FROM inventory WHERE store_id=981').fetchone()[0]==4
        assert c.execute('SELECT status,completed_by,completed_at FROM stock_transfers WHERE movement_id=?',(mid,)).fetchone()[:2]==('received',4)
    assert api[0].get('/api/inventory/transfers').json()==[]


def test_return_requires_sender_confirmation_and_restores_once(api):
    seed(api);mid=dispatch(api,10).json()['transfer_id']
    api[2]['id']=4
    assert finish(api,mid,'return').status_code==403
    api[2]['id']=3
    assert finish(api,mid,'return',False).status_code==400
    assert finish(api,mid,'return').status_code==200
    assert finish(api,mid,'return').status_code==409
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold FROM inventory WHERE store_id=980 AND part_id=980').fetchone()==(10,2)
        assert c.execute('SELECT COUNT(*) FROM inventory WHERE store_id=981').fetchone()[0]==0


def test_sender_cannot_confirm_receipt_for_another_engineer(api):
    seed(api);mid=dispatch(api).json()['transfer_id']
    assert finish(api,mid).status_code==403
    api[2]['id']=1
    assert finish(api,mid).status_code==200


@pytest.mark.parametrize('restock_threshold,expected_threshold',[(0,2),(7,7)])
def test_return_preserves_threshold_after_source_is_restocked(api,restock_threshold,expected_threshold):
    seed(api);mid=dispatch(api,10).json()['transfer_id']
    with sqlite3.connect(api[1]) as c:
        c.execute('INSERT INTO inventory(store_id,part_id,quantity,min_threshold) VALUES(980,980,5,?)',(restock_threshold,))
    assert finish(api,mid,'return').status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold FROM inventory WHERE store_id=980 AND part_id=980').fetchone()==(15,expected_threshold)


def test_confirmation_requires_csrf(api):
    seed(api);mid=dispatch(api).json()['transfer_id'];api[2]['id']=4
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert finish(api,mid).status_code==403


def test_legacy_transfers_remain_completed_after_repeated_initialization(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        mid=c.execute("INSERT INTO movements(from_store_id,to_store_id,part_id,quantity,movement_type,created_by) VALUES(980,981,980,1,'transfer',3)").lastrowid
    main.init_db();main.init_db()
    history=api[0].get('/api/movements').json()
    assert next(row for row in history if row['id']==mid)['transfer_status']=='completed'
    assert api[0].get('/api/inventory/transfers').json()==[]
    assert finish(api,mid).status_code==404


def test_transfer_preserves_work_order_allocation(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(980,'RESERVED')")
        c.execute('UPDATE inventory SET work_order_id=980 WHERE id=980')
    mid=dispatch(api).json()['transfer_id'];api[2]['id']=4
    assert finish(api,mid).status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,work_order_id FROM inventory WHERE store_id=981').fetchone()==(4,'980')


@pytest.mark.parametrize('target',['parts/980','stores/980','stores/981','users/3'])
def test_pending_transfer_references_cannot_be_deleted(api,target):
    seed(api);dispatch(api,10);api[2]['id']=1
    response=api[0].delete('/api/'+target)
    assert response.status_code==400


def test_completion_race_cannot_duplicate_or_return_received_stock(api):
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    seed(api);mid=dispatch(api).json()['transfer_id']
    def run(action):
        try:
            return main.complete_transfer(mid,main.TransferConfirmationRequest(confirmed=True),1,action)['success']
        except main.HTTPException as exc:
            return exc.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,['received','returned']))
    assert sorted(str(x) for x in results)==['409','True']
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT SUM(quantity) FROM inventory WHERE part_id=980').fetchone()[0]==10


def test_failed_receipt_does_not_mark_received(api):
    seed(api);mid=dispatch(api).json()['transfer_id'];api[2]['id']=4
    with sqlite3.connect(api[1]) as c:
        c.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON inventory WHEN NEW.store_id=981 BEGIN SELECT RAISE(ABORT,'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):finish(api,mid)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT status FROM stock_transfers WHERE movement_id=?',(mid,)).fetchone()[0]=='in_transit'
        assert c.execute('SELECT COUNT(*) FROM inventory WHERE store_id=981').fetchone()[0]==0


def test_pre_receipt_backup_restores_with_empty_transfer_lifecycle(api,tmp_path):
    import shutil
    from database_restore import restore_database
    seed(api)
    upload=tmp_path/'old-backup.db'
    shutil.copyfile(api[1],upload)
    with sqlite3.connect(upload) as c:c.execute('DROP TABLE stock_transfers')
    restore_database(upload,api[1],2)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT COUNT(*) FROM stock_transfers').fetchone()[0]==0
        assert c.execute('SELECT quantity FROM inventory WHERE id=980').fetchone()[0]==10
