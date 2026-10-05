import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
import main
from fastapi import Request
from regression_tests.test_stock_safety import api


def test_login_cookie_requires_https(api):
    response=api[0].post('/api/auth/login',json={'email':'user1@example.com','password':'test-password'})
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
    response=api[0].post('/api/auth/login',json={'email':'user1@example.com','password':'test-password'})
    assert response.status_code==200
    assert '; secure' not in response.headers['set-cookie'].lower()


@pytest.mark.parametrize('operation',['consume','update'])
def test_failed_movement_rolls_back_balance_and_work_order(api,operation):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(990,'Rollback','central')")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(990,'ROLLBACK','Test')")
        c.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(990,990,990,5)')
        c.execute("CREATE TRIGGER fail_movement BEFORE INSERT ON movements WHEN NEW.part_id=990 BEGIN SELECT RAISE(ABORT,'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        if operation=='consume':
            api[0].post('/api/inventory/consume',json={'inventory_id':990,'quantity':2,'work_order_number':'ROLLBACK-WO'})
        else:
            api[0].put('/api/inventory/update',json={'inventory_id':990,'new_quantity':3})
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=990').fetchone()[0]==5
        assert c.execute("SELECT COUNT(*) FROM work_orders WHERE work_order_number='ROLLBACK-WO'").fetchone()[0]==0
        c.execute('BEGIN IMMEDIATE')  # A failed request must release its write lock.


@pytest.mark.parametrize('operation',['consume','update'])
def test_concurrent_stock_mutations_preserve_balances_and_history(api,monkeypatch,operation):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(990,'Concurrent','central')")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(990,'CONCURRENT','Test')")
        c.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(990,990,990,5)')
    barrier=threading.Barrier(2)
    # Synchronize unsafe reads; locked transactions must serialize instead.
    class Cursor(sqlite3.Cursor):
        def execute(self,sql,*args):
            self.stock_read='SELECT i.*' in sql
            return super().execute(sql,*args)
        def fetchone(self):
            row=super().fetchone()
            if getattr(self,'stock_read',False) and not self.connection.in_transaction:
                barrier.wait(timeout=5)
            return row
    class Connection(sqlite3.Connection):
        def cursor(self,*args,**kwargs):
            return super().cursor(factory=Cursor)
    def connect():
        c=sqlite3.connect(api[1],factory=Connection,timeout=5)
        c.row_factory=sqlite3.Row
        return c
    monkeypatch.setattr(main,'get_db_connection',connect)
    def run(index):
        request=Request({'type':'http','headers':[(b'cookie',b'session_token=fixture-session-1')]})
        try:
            if operation=='consume':
                payload=main.ConsumeStockRequest(inventory_id=990,quantity=4,work_order_number=f'CONCURRENT-{index}')
                asyncio.run(main.consume_stock.__wrapped__(payload,user_id=1,csrf_valid=True,request=request))
            else:
                payload=main.UpdateStockRequest(inventory_id=990,new_quantity=[3,1][index])
                asyncio.run(main.update_stock.__wrapped__(payload,user_id=1,csrf_valid=True,request=request))
            return 200
        except main.HTTPException as exc:
            return exc.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,[0,1]))
    with sqlite3.connect(api[1]) as c:
        balance=c.execute('SELECT quantity FROM inventory WHERE id=990').fetchone()[0]
        if operation=='consume':
            assert sorted(results)==[200,400]
            assert balance==1
            assert c.execute("SELECT SUM(quantity) FROM movements WHERE part_id=990 AND movement_type='consume'").fetchone()[0]==4
        else:
            assert results==[200,200]
            net=c.execute("SELECT SUM(CASE WHEN movement_type='add' THEN quantity ELSE -quantity END) FROM movements WHERE part_id=990").fetchone()[0]
            assert 5+net==balance
