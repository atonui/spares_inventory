import json
import sqlite3
from pathlib import Path
import pytest
import main
from regression_tests.test_stock_safety import api
from regression_tests.migration_fixtures import snapshot

KEYS={'id','work_order_number','customer_name','description','status','assigned_engineer_id','engineer_name'}

def seed_orders(conn):
    conn.executemany('INSERT INTO work_orders(id,work_order_number,assigned_engineer_id,created_at) VALUES(?,?,?,?)',[
        (101,'WO-101',3,'2026-10-02'),(102,'WO-102',4,'2026-10-03'),
        (103,'WO-103',None,'2026-10-04'),(104,'WO-104',2,'2026-10-01')])

def seed(api):
    with sqlite3.connect(api[1]) as c:seed_orders(c)

def rows(api,actor):
    api[2]['id']=actor
    response=api[0].get('/api/work-orders')
    assert response.status_code==200,response.text
    return response.json()

@pytest.mark.parametrize('actor,expected',[(1,[103,102,101,104]),(3,[101]),(4,[102])])
def test_work_order_role_scope(api,actor,expected):
    seed(api);assert [r['id'] for r in rows(api,actor)]==expected

def test_superadmin_sees_all_work_orders(api):
    seed(api);assert [r['id'] for r in rows(api,2)]==[103,102,101,104]

def test_work_order_response_contract(api):
    seed(api);result=rows(api,1)
    assert all(set(r)==KEYS for r in result)
    assert result[0]=={'id':103,'work_order_number':'WO-103','customer_name':None,'description':None,'status':'open','assigned_engineer_id':None,'engineer_name':None}
    assert next(r for r in result if r['id']==101)['engineer_name']=='User 3'

def test_work_order_ordering(api):
    seed(api);assert [r['work_order_number'] for r in rows(api,1)]==['WO-103','WO-102','WO-101','WO-104']

def test_archived_engineer_name_is_retained(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:c.execute('UPDATE users SET archived_at=CURRENT_TIMESTAMP WHERE id=3')
    assert next(r for r in rows(api,1) if r['id']==101)['engineer_name']=='User 3'

def test_work_order_get_is_readonly(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:before=snapshot(c)
    rows(api,1)
    with sqlite3.connect(api[1]) as c:assert snapshot(c)==before

def test_work_orders_require_authentication(api):
    main.app.dependency_overrides.pop(main.get_current_user)
    assert api[0].get('/api/work-orders').status_code==401

def test_work_order_openapi_contract():
    schema=main.app.openapi()
    operation=schema['paths']['/api/work-orders']['get']
    assert operation['operationId']=='get_work_orders_api_work_orders_get'
    response=operation['responses']['200']['content']['application/json']['schema']
    assert response['type']=='array' and response['items']=={'$ref':'#/components/schemas/WorkOrderResponse'}
    model=schema['components']['schemas']['WorkOrderResponse']
    assert set(model['properties'])==KEYS and set(model['required'])==KEYS
    for name in ('customer_name','description','assigned_engineer_id','engineer_name'):
        assert {'type':'null'} in model['properties'][name]['anyOf']

def test_existing_archive_restore_routes_remain_registered():
    paths=main.app.openapi()['paths']
    for path in ('/api/parts/{part_id}/restore','/api/stores/{store_id}/restore','/api/users/{target_user_id}/restore'):
        assert path in paths
        assert 'post' in paths[path]
