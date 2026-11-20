import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
import main
from fastapi import Request
from regression_tests.postgres_app import fail_inserts
from regression_tests.test_auth_router import auth_api


@pytest.fixture
def api(auth_api):
    return auth_api


def test_login_cookie_requires_https(api):
    response=api[0].post('/api/auth/login',json={'email':'admin@example.test','password':'test-password'})
    assert response.status_code==200
    cookie=response.headers['set-cookie'].lower()
    assert '; secure' in cookie
    assert '; httponly' in cookie


def test_untrusted_origin_cannot_use_credentialed_cors(api):
    response=api[0].options('/api/inventory',headers={'Origin':'https://untrusted.example','Access-Control-Request-Method':'GET'})
    assert response.status_code==400
    assert 'access-control-allow-origin' not in response.headers


def test_railway_origin_remains_allowed(api):
    origin='https://sparesinventory-production.up.railway.app'
    response=api[0].options('/api/inventory',headers={'Origin':origin,'Access-Control-Request-Method':'GET'})
    assert response.status_code==200
    assert response.headers['access-control-allow-origin']==origin


def test_wildcard_cors_configuration_is_rejected():
    from pydantic import ValidationError
    config=main.settings.model_dump()
    config['CORS_ALLOWED_ORIGINS']=['*']
    with pytest.raises(ValidationError):
        main.Settings(**config)


def test_local_http_cookie_can_be_explicitly_enabled(api,monkeypatch):
    monkeypatch.setattr(main.settings,'COOKIE_SECURE',False)
    response=api[0].post('/api/auth/login',json={'email':'admin@example.test','password':'test-password'})
    assert response.status_code==200
    assert '; secure' not in response.headers['set-cookie'].lower()


@pytest.mark.parametrize('operation',['consume','update'])
def test_failed_movement_rolls_back_balance_and_work_order(api,operation):
    with api[1] as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(990,'Rollback','central')")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(990,'ROLLBACK','Test')")
        c.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(990,990,990,5)')
    trigger=fail_inserts(api[1], 'movements', 'test failure', "NEW.part_id=990")
    with pytest.raises(psycopg.errors.RaiseException):
        if operation=='consume':
            api[0].post('/api/inventory/consume',json={'inventory_id':990,'quantity':2,'work_order_number':'ROLLBACK-WO'})
        else:
            api[0].put('/api/inventory/update',json={'inventory_id':990,'new_quantity':3})
    with api[1] as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=990').fetchone()[0]==5
        assert c.execute("SELECT COUNT(*) FROM work_orders WHERE work_order_number='ROLLBACK-WO'").fetchone()[0]==0
    # A failed request must release its row locks: a new write succeeds at once.
    api[1].execute(f'DROP TRIGGER "{trigger}" ON movements')
    assert api[0].put('/api/inventory/update',json={'inventory_id':990,'new_quantity':4}).status_code==200


@pytest.mark.parametrize('operation',['consume','update'])
def test_concurrent_stock_mutations_preserve_balances_and_history(api,operation):
    with api[1] as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(990,'Concurrent','central')")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(990,'CONCURRENT','Test')")
        c.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(990,990,990,5)')
    admin=asyncio.run(main.get_current_user('admin-token'))
    start=threading.Barrier(2)
    def run(index):
        request=Request({'type':'http','headers':[(b'cookie',b'session_token=admin-token')]})
        start.wait(timeout=5)  # release both writers together; row locks must serialize them
        try:
            if operation=='consume':
                payload=main.ConsumeStockRequest(inventory_id=990,quantity=4,work_order_number=f'CONCURRENT-{index}')
                asyncio.run(main.consume_stock.__wrapped__(payload,user_id=admin,csrf_valid=True,request=request))
            else:
                payload=main.UpdateStockRequest(inventory_id=990,new_quantity=[3,1][index])
                asyncio.run(main.update_stock.__wrapped__(payload,user_id=admin,csrf_valid=True,request=request))
            return 200
        except main.HTTPException as exc:
            return exc.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,[0,1]))
    with api[1] as c:
        balance=c.execute('SELECT quantity FROM inventory WHERE id=990').fetchone()[0]
        if operation=='consume':
            assert sorted(results)==[200,400]
            assert balance==1
            assert c.execute("SELECT SUM(quantity) FROM movements WHERE part_id=990 AND movement_type='consume'").fetchone()[0]==4
        else:
            assert results==[200,200]
            net=c.execute("SELECT SUM(CASE WHEN movement_type='add' THEN quantity ELSE -quantity END) FROM movements WHERE part_id=990").fetchone()[0]
            assert 5+net==balance
