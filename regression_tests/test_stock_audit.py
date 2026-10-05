"""Audit omissions must never leave successful stock changes behind."""
import json
import sqlite3
import pytest
from regression_tests.test_stock_safety import api
from regression_tests.test_transfer_receipts import seed,dispatch


def execute(api,action):
    c=api[0]
    requests={
        'add_stock':('post','/api/inventory/add',{'store_id':980,'part_id':980,'quantity':3}),
        'consume_stock':('post','/api/inventory/consume',{'inventory_id':980,'quantity':3,'work_order_number':'AUDIT-WO'}),
        'update_stock':('put','/api/inventory/update',{'inventory_id':980,'new_quantity':4}),
        'import_stock_balances':('post','/api/inventory/import-balances',{'store_id':980,'rows':[{'part_number':'RECEIPT','quantity':6,'expected_quantity':10}]}),
        'transfer_stock':('post','/api/inventory/transfer',{'inventory_id':980,'to_store_id':981,'quantity':4}),
    }
    if action in ('receive_transfer','return_transfer'):
        mid=api[2]['mid'];operation='receive' if action=='receive_transfer' else 'return'
        return c.post(f'/api/inventory/transfers/{mid}/{operation}',json={'confirmed':True})
    method,path,body=requests[action]
    return getattr(c,method)(path,json=body)


def snapshot(api):
    with sqlite3.connect(api[1]) as c:
        return [c.execute('SELECT * FROM '+table+' ORDER BY id').fetchall() for table in ('inventory','movements','work_orders')]+[c.execute('SELECT * FROM stock_transfers ORDER BY movement_id').fetchall()]


@pytest.mark.parametrize('action',['add_stock','consume_stock','update_stock','import_stock_balances','transfer_stock','receive_transfer','return_transfer'])
def test_failed_audit_rolls_back_balance_movement_and_transfer(api,action):
    seed(api)
    if action in ('receive_transfer','return_transfer'):
        api[2]['mid']=dispatch(api).json()['transfer_id']
        if action=='receive_transfer': api[2]['id']=4
    before=snapshot(api)
    with sqlite3.connect(api[1]) as c:
        c.execute(f"CREATE TRIGGER fail_audit BEFORE INSERT ON activity_logs WHEN NEW.action='{action}' AND NEW.status='success' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError): execute(api,action)
    assert snapshot(api)==before
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT COUNT(*) FROM activity_logs WHERE action=? AND status=?',(action,'success')).fetchone()[0]==(1 if action=='transfer_stock' and 'mid' in api[2] else 0)


@pytest.mark.parametrize('action,after',[('add_stock',13),('consume_stock',7),('update_stock',4),('import_stock_balances',6),('transfer_stock',6)])
def test_success_records_one_linked_before_after_event(api,action,after):
    seed(api)
    assert execute(api,action).status_code==200
    with sqlite3.connect(api[1]) as c:
        rows=c.execute('SELECT user_id,details FROM activity_logs WHERE action=? AND status=?',(action,'success')).fetchall()
        assert len(rows)==1
        assert rows[0][0]==3
        data=json.loads(rows[0][1]);assert data['schema_version']==1
        change=data['balance_changes'][0]
        assert (change['before']['quantity'],change['after']['quantity'])==(10,after)
        assert change['before']['part_number']=='RECEIPT'
        assert change['before']['store_name']=='Sender'
        assert change['before']['work_order_id'] is None
        assert data['movement_ids']==[c.execute('SELECT id FROM movements').fetchone()[0]]


def test_receive_and_return_capture_destination_and_source_and_transfer_state(api):
    seed(api);mid=dispatch(api).json()['transfer_id'];api[2]['mid']=mid;api[2]['id']=4
    assert execute(api,'receive_transfer').status_code==200
    with sqlite3.connect(api[1]) as c:
        data=json.loads(c.execute("SELECT details FROM activity_logs WHERE action='receive_transfer' AND status='success'").fetchone()[0])
        assert data['transfer_id']==mid
        assert data['before_status']=='in_transit' and data['after_status']=='received'
        change=data['balance_changes'][0]
        assert (change['before']['quantity'],change['after']['quantity'])==(0,4)
        assert change['after']['store_name']=='Recipient'
    assert execute(api,'receive_transfer').status_code==409
    with sqlite3.connect(api[1]) as c:
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='receive_transfer' AND status='success'").fetchone()[0]==1


@pytest.mark.parametrize('endpoint,actor',[('/api/logs/activity/cleanup?days=1',1),('/api/superadmin/database/logs/purge?days=0',2)])
def test_cleanup_retains_stock_evidence_and_removes_old_general_events(api,endpoint,actor):
    seed(api);execute(api,'consume_stock')
    with sqlite3.connect(api[1]) as c:
        c.execute("UPDATE activity_logs SET created_at='2000-01-01'")
        c.execute("INSERT INTO activity_logs(user_id,username,action,created_at) VALUES(3,'User 3','view_parts','2000-01-01')")
    api[2]['id']=actor
    response=api[0].delete(endpoint)
    assert response.status_code==200,response.text
    with sqlite3.connect(api[1]) as c:
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='consume_stock'").fetchone()[0]==1
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='view_parts'").fetchone()[0]==0


@pytest.mark.parametrize('kind',['minimum','count'])
def test_existing_minimum_and_count_audits_have_linked_balance_evidence(api,kind):
    seed(api)
    if kind=='minimum':
        response=api[0].put('/api/inventory/minimum',json={'store_id':980,'part_id':980,'min_threshold':5,'expected_minimum':2})
        action='set_stock_minimum';quantity=10
    else:
        sheet=api[0].get('/api/inventory/count-sheet/980').json()
        preview=api[0].post('/api/inventory/count-preview',json={'sheet_token':sheet['sheet_token'],'rows':[{'inventory_id':980,'counted_quantity':8,'reason':'Physical check'}]}).json()
        response=api[0].post('/api/inventory/count-confirm',json={'preview_token':preview['preview_token'],'confirmed':True})
        action='confirm_stock_count';quantity=8
    assert response.status_code==200,response.text
    with sqlite3.connect(api[1]) as c:
        data=json.loads(c.execute('SELECT details FROM activity_logs WHERE action=?',(action,)).fetchone()[0])
        assert data['schema_version']==1
        change=data['balance_changes'][0]
        assert (change['before']['quantity'],change['after']['quantity'])==(10,quantity)
        if kind=='minimum':assert change['after']['min_threshold']==5
        else: assert len(data['movement_ids'])==1


def test_denied_stock_change_never_creates_successful_evidence(api):
    seed(api);api[2]['id']=4
    assert execute(api,'consume_stock').status_code==403
    with sqlite3.connect(api[1]) as c:
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='consume_stock' AND status='success'").fetchone()[0]==0
        assert c.execute('SELECT quantity FROM inventory WHERE id=980').fetchone()[0]==10


def test_concurrent_consumption_evidence_forms_a_balance_chain(api):
    from concurrent.futures import ThreadPoolExecutor
    seed(api)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:execute(api,'consume_stock').status_code,range(2)))
    assert results==[200,200]
    with sqlite3.connect(api[1]) as c:
        records=[json.loads(row[0]) for row in c.execute("SELECT details FROM activity_logs WHERE action='consume_stock' AND status='success' ORDER BY id")]
        assert [(r['balance_changes'][0]['before']['quantity'],r['balance_changes'][0]['after']['quantity']) for r in records]==[(10,7),(7,4)]
        assert len({r['movement_ids'][0] for r in records})==2


def test_scientific_text_work_order_is_snapshotted_without_changing_allocation(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(980,'ALLOCATED')")
        c.execute("INSERT INTO inventory(id,store_id,part_id,quantity,work_order_id) VALUES(982,980,980,5,'9.8e2')")
    response=api[0].post('/api/inventory/consume',json={'inventory_id':982,'quantity':2,'work_order_number':'SERVICE-WO'})
    assert response.status_code==200
    with sqlite3.connect(api[1]) as c:
        data=json.loads(c.execute("SELECT details FROM activity_logs WHERE action='consume_stock' AND status='success'").fetchone()[0])
        before,after=data['balance_changes'][0]['before'],data['balance_changes'][0]['after']
        assert (before['work_order_id'],before['work_order'],before['quantity'],after['quantity'])==(980,'ALLOCATED',5,3)
        assert data['consumed_work_order']=='SERVICE-WO'
        assert c.execute('SELECT quantity FROM inventory WHERE id=980').fetchone()[0]==10


def test_return_evidence_links_dispatch_and_return_movement(api):
    seed(api);mid=dispatch(api).json()['transfer_id'];api[2]['mid']=mid
    assert execute(api,'return_transfer').status_code==200
    with sqlite3.connect(api[1]) as c:
        data=json.loads(c.execute("SELECT details FROM activity_logs WHERE action='return_transfer' AND status='success'").fetchone()[0])
        assert data['movement_ids']==[mid,c.execute("SELECT id FROM movements WHERE movement_type='return'").fetchone()[0]]
        assert data['before_status']=='in_transit' and data['after_status']=='returned'
        change=data['balance_changes'][0]
        assert (change['before']['quantity'],change['after']['quantity'])==(6,10)
