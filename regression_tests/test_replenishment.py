import json
import sqlite3

import pytest
import main
from regression_tests.test_stock_safety import api


def seed(api):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(950,'A Need','car',3),(951,'B Need','car',4),(952,'Central Supply','central',NULL),(953,'Other Supply','car',4),(954,'Reserved','central',NULL)")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(950,'PLAN','Planned part'),(951,'NEW-PLAN','New target')")
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(950,'PLAN-WO')")
        c.execute("INSERT INTO inventory(id,store_id,part_id,quantity,min_threshold,work_order_id) VALUES(950,950,950,1,5,NULL),(951,951,950,0,4,NULL),(952,952,950,10,3,NULL),(953,953,950,6,5,NULL),(954,954,950,100,0,'950')")
    api[2]['id']=3


def plan(api):
    response=api[0].get('/api/inventory/replenishment')
    assert response.status_code==200,response.text
    return response.json()


def minimum(api,store=950,part=950,value=7,expected=5):
    return api[0].put('/api/inventory/minimum',json={'store_id':store,'part_id':part,'min_threshold':value,'expected_minimum':expected})


def test_plan_uses_each_surplus_once_and_preserves_donor_minimums_and_reservations(api):
    seed(api)
    result=plan(api)
    rows=result['rows']
    assert [(r['store_id'],r['shortage'],r['purchase_quantity']) for r in rows]==[(950,4,0),(951,4,0)]
    assert [(s['inventory_id'],s['quantity']) for s in rows[0]['suggestions']]==[(952,4)]
    assert [(s['inventory_id'],s['quantity']) for s in rows[1]['suggestions']]==[(952,3),(953,1)]
    assert rows[0]['suggestions'][0]['can_dispatch'] is True
    assert rows[1]['suggestions'][1]['can_dispatch'] is False
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT SUM(quantity) FROM inventory').fetchone()[0]==117
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0]==0


def test_incoming_unallocated_stock_reduces_purchasing_need_without_becoming_available(api):
    seed(api)
    dispatch=api[0].post('/api/inventory/transfer',json={'inventory_id':952,'to_store_id':950,'quantity':2})
    assert dispatch.status_code==200
    rows=plan(api)['rows']
    assert (rows[0]['quantity'],rows[0]['shortage'],rows[0]['incoming_quantity'])==(1,4,2)
    assert [(s['inventory_id'],s['quantity']) for s in rows[0]['suggestions']]==[(952,2)]
    assert sum(s['quantity'] for r in rows for s in r['suggestions'] if s['inventory_id']==952)==5
    assert rows[1]['purchase_quantity']==0
    api[0].post(f"/api/inventory/transfers/{dispatch.json()['transfer_id']}/receive",json={'confirmed':True})
    refreshed=plan(api)['rows'][0]
    assert (refreshed['quantity'],refreshed['incoming_quantity'])==(3,0)


def test_allocated_incoming_does_not_cover_unallocated_shortage(api):
    seed(api)
    assert api[0].post('/api/inventory/transfer',json={'inventory_id':954,'to_store_id':950,'quantity':10}).status_code==200
    first=plan(api)['rows'][0]
    assert first['incoming_quantity']==0
    assert sum(s['quantity'] for s in first['suggestions'])==4


def test_insufficient_internal_surplus_is_listed_for_purchase(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute('UPDATE inventory SET quantity=5 WHERE id=952')
    rows=plan(api)['rows']
    assert sum(r['purchase_quantity'] for r in rows)==5
    assert sum(s['quantity'] for r in rows for s in r['suggestions'])==3


def test_minimum_change_is_audited_without_changing_stock(api):
    seed(api)
    response=minimum(api)
    assert response.status_code==200,response.text
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold FROM inventory WHERE id=950').fetchone()==(1,7)
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0]==0
        log=c.execute("SELECT user_id,details FROM activity_logs WHERE action='set_stock_minimum'").fetchone()
        assert log[0]==3
        assert json.loads(log[1])['before_minimum']==5
        assert json.loads(log[1])['after_minimum']==7
    assert minimum(api,value=8,expected=5).status_code==409


def test_minimum_can_configure_missing_unallocated_stock_without_adding_units(api):
    seed(api)
    response=minimum(api,part=951,value=2,expected=0)
    assert response.status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold,work_order_id FROM inventory WHERE store_id=950 AND part_id=951').fetchone()==(0,2,None)
    assert any(r['part_id']==951 and r['shortage']==2 for r in plan(api)['rows'])


@pytest.mark.parametrize('value',[-1,True,1.5,'5'])
def test_invalid_minimum_is_rejected(api,value):
    seed(api)
    assert minimum(api,value=value).status_code==422


def test_minimum_respects_store_permissions_and_csrf(api):
    seed(api)
    assert minimum(api,store=951,expected=4).status_code==403
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert minimum(api).status_code==403


@pytest.mark.parametrize('operation',['consume','transfer'])
def test_emptying_stock_preserves_configured_minimum_and_allocation_id(api,operation):
    seed(api)
    if operation=='consume':
        response=api[0].post('/api/inventory/consume',json={'inventory_id':950,'quantity':1,'work_order_number':'EMPTY-TARGET'})
    else:
        response=api[0].post('/api/inventory/transfer',json={'inventory_id':950,'quantity':1,'to_store_id':952})
    assert response.status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold,work_order_id FROM inventory WHERE id=950').fetchone()==(0,5,None)
    assert plan(api)['rows'][0]['shortage']==5


def test_suggested_dispatch_rechecks_plan_and_rejects_donor_minimum_violation(api):
    seed(api)
    response=api[0].post('/api/inventory/transfer',json={'inventory_id':952,'quantity':8,'to_store_id':950,'replenishment':True})
    assert response.status_code==409
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=952').fetchone()[0]==10
        assert c.execute('SELECT COUNT(*) FROM movements').fetchone()[0]==0


def test_suggested_dispatch_follows_existing_receipt_lifecycle(api):
    seed(api)
    response=api[0].post('/api/inventory/transfer',json={'inventory_id':952,'quantity':4,'to_store_id':950,'replenishment':True})
    assert response.status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=952').fetchone()[0]==6
        assert c.execute('SELECT quantity FROM inventory WHERE id=950').fetchone()[0]==1
    first=plan(api)['rows'][0]
    assert first['incoming_quantity']==4 and first['suggestions']==[] and first['purchase_quantity']==0
    assert api[0].post(f"/api/inventory/transfers/{response.json()['transfer_id']}/receive",json={'confirmed':True}).status_code==200
    assert all(r['store_id']!=950 for r in plan(api)['rows'])


def test_archived_stock_is_not_a_donor_or_target(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute('UPDATE stores SET archived_at=CURRENT_TIMESTAMP WHERE id=952')
    rows=plan(api)['rows']
    assert sum(r['purchase_quantity'] for r in rows)==7
    assert minimum(api,store=952,expected=3).status_code==400


def test_minimum_audit_failure_rolls_back_setting_and_new_target(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("CREATE TRIGGER fail_minimum BEFORE INSERT ON activity_logs WHEN NEW.action='set_stock_minimum' BEGIN SELECT RAISE(ABORT,'minimum audit failed'); END")
    with pytest.raises(sqlite3.IntegrityError):
        minimum(api,part=951,value=2,expected=0)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT COUNT(*) FROM inventory WHERE part_id=951').fetchone()[0]==0


def test_return_respects_minimum_disabled_after_dispatch(api):
    seed(api)
    sent=api[0].post('/api/inventory/transfer',json={'inventory_id':950,'to_store_id':952,'quantity':1})
    assert sent.status_code==200
    assert minimum(api,value=0,expected=5).status_code==200
    assert api[0].post(f"/api/inventory/transfers/{sent.json()['transfer_id']}/return",json={'confirmed':True}).status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold FROM inventory WHERE id=950').fetchone()==(1,0)


def test_disable_target_for_legacy_deleted_source_survives_return(api):
    seed(api)
    sent=api[0].post('/api/inventory/transfer',json={'inventory_id':950,'to_store_id':952,'quantity':1})
    with sqlite3.connect(api[1]) as c:
        c.execute('DELETE FROM inventory WHERE id=950 AND quantity=0')
    assert minimum(api,value=0,expected=0).status_code==200
    assert api[0].post(f"/api/inventory/transfers/{sent.json()['transfer_id']}/return",json={'confirmed':True}).status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity,min_threshold FROM inventory WHERE store_id=950 AND part_id=950 AND work_order_id IS NULL').fetchone()==(1,0)


def test_low_stock_summary_matches_configured_unallocated_shortages(api):
    seed(api)
    assert api[0].get('/api/stats').json()['low_stock']==2
    assert minimum(api,value=1,expected=5).status_code==200
    assert api[0].get('/api/stats').json()['low_stock']==1
    assert minimum(api,value=0,expected=1).status_code==200
    with sqlite3.connect(api[1]) as c:
        c.execute('UPDATE inventory SET quantity=0 WHERE id=950')
        c.execute('UPDATE inventory SET min_threshold=200 WHERE id=954')
    assert api[0].get('/api/stats').json()['low_stock']==1
