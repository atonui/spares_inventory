import psycopg
import pytest

import main
from backend.security import hash_session_credential


@pytest.fixture
def api(stock_api):
    """Shared by the stock test files: (client, db, current) on PostgreSQL."""
    return stock_api


@pytest.mark.parametrize('endpoint,payload', [
    ('/api/inventory/add', {'part_id': 1, 'store_id': 1, 'quantity': 0}),
    ('/api/inventory/transfer', {'inventory_id': 1, 'to_store_id': 2, 'quantity': -3}),
    ('/api/inventory/consume', {'inventory_id': 1, 'quantity': -1, 'work_order_number': 'TEST'}),
    ('/api/inventory/update', {'inventory_id': 1, 'new_quantity': -2}),
])
def test_invalid_quantity_is_rejected_before_writing(api, endpoint, payload):
    client, db, _ = api
    before = db.execute('SELECT SUM(quantity),COUNT(*) FROM inventory').fetchone()
    response = client.request('PUT' if endpoint.endswith('/update') else 'POST', endpoint, json=payload)
    assert response.status_code == 422
    assert db.execute('SELECT SUM(quantity),COUNT(*) FROM inventory').fetchone() == before


@pytest.mark.parametrize('quantity', [1.5, True, '2'])
def test_quantity_must_be_integer(api, quantity):
    response = api[0].post('/api/inventory/add', json={'part_id': 1, 'store_id': 1, 'quantity': quantity})
    assert response.status_code == 422


def test_invalid_role_rejected(api):
    assert api[0].put('/api/users/3', json={'role': 'made-up'}).status_code == 422


def test_admin_can_update_engineer(api):
    assert api[0].put('/api/users/3', json={'name': 'Updated'}).status_code == 200


def test_owner_can_assign_privileged_role(api):
    client, db, current = api
    current['id'] = 2
    assert client.put('/api/users/3', json={'role': 'admin'}).status_code == 200
    assert db.execute('SELECT company_role FROM organization_memberships WHERE user_id=3').fetchone()[0] == 'admin'


def test_same_store_transfer_rejected(api):
    with api[1] as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Test Store','central')")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'TEST','Test','test',0)")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9999,999,999,10)')
    response = api[0].post('/api/inventory/transfer', json={'inventory_id': 9999, 'to_store_id': 999, 'quantity': 2})
    assert response.status_code == 400
    assert api[1].execute('SELECT quantity FROM inventory WHERE id=9999').fetchone()[0] == 10


def test_valid_stock_workflow(api):
    client, db, _ = api
    with db as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Test Source','central'),(998,'Test Destination','central')")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'TEST','Test','test',0)")
    assert client.post('/api/inventory/add', json={'part_id': 999, 'store_id': 999, 'quantity': 10}).status_code == 200
    iid = db.execute('SELECT id FROM inventory WHERE part_id=999').fetchone()[0]
    transfer = client.post('/api/inventory/transfer', json={'inventory_id': iid, 'to_store_id': 998, 'quantity': 3})
    assert transfer.status_code == 200
    assert client.post(f"/api/inventory/transfers/{transfer.json()['transfer_id']}/receive", json={'confirmed':True}).status_code == 200
    assert client.post('/api/inventory/consume', json={'inventory_id': iid, 'quantity': 2, 'work_order_number': 'TEST-WO'}).status_code == 200
    assert client.put('/api/inventory/update', json={'inventory_id': iid, 'new_quantity': 0}).status_code == 200
    with db as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE part_id=999 AND store_id=999').fetchone()[0] == 0
        assert conn.execute('SELECT quantity FROM inventory WHERE part_id=999 AND store_id=998').fetchone()[0] == 3


def test_add_stock_form_sends_numeric_quantity():
    import subprocess
    from pathlib import Path
    helper = Path(main.__file__).parent / 'regression_tests' / 'helpers' / 'frontend.cjs'
    code = """
const {loadPageScripts} = require(process.argv[1]); const vm = require('vm');
const context = { console, setTimeout:()=>{} }; vm.createContext(context);
loadPageScripts('index.html', context);
const app = context.inventoryApp(); let sent;
app.addForm = {part_id: '1', store_id: '1', quantity: '2', work_order_number: ''};
app.apiCall = async (path, options) => { sent = JSON.parse(options.body); };
app.loadInventory = async () => {}; app.loadStats = async () => {};
(async () => { await app.addStock();
if (sent.quantity !== 2) throw new Error('Stock form must send quantity as a number');
})();
"""
    result = subprocess.run(['node', '-e', code, str(helper)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

@pytest.mark.parametrize('role', [3, 4])
@pytest.mark.parametrize('operation', ['add', 'update', 'consume', 'transfer'])
def test_other_users_store_cannot_be_changed(api, role, operation):
    client, db, current = api
    current['id'] = role
    with db as conn:
        conn.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(999,'Other Store','car',2),(998,'Destination','central',NULL)")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'PERM','Permission Test','test',0)")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9999,999,999,10)')
    payloads = {
        'add': {'store_id':999,'part_id':999,'quantity':2},
        'update': {'inventory_id':9999,'new_quantity':5},
        'consume': {'inventory_id':9999,'quantity':2,'work_order_number':'TEST'},
        'transfer': {'inventory_id':9999,'to_store_id':998,'quantity':2},
    }
    response = client.request('PUT' if operation == 'update' else 'POST', '/api/inventory/' + operation, json=payloads[operation])
    assert response.status_code == 403
    with db as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE id=9999').fetchone()[0] == 10
        assert conn.execute('SELECT COUNT(*) FROM inventory WHERE part_id=999').fetchone()[0] == 1

def test_temporary_restore_route_removed():
    assert not any(route.path == '/upload-database' for route in main.app.routes)


def test_engineer_can_deliver_from_own_store_to_other_engineer(api):
    client, db, current = api
    current['id'] = 3
    with db as conn:
        conn.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(999,'Mine','car',3),(998,'Other','car',4)")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'DELIVERY','Delivery Test','test',0)")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9999,999,999,10)')
    transfer = client.post('/api/inventory/transfer', json={'inventory_id':9999,'to_store_id':998,'quantity':2})
    assert transfer.status_code == 200
    current['id'] = 4
    assert client.post(f"/api/inventory/transfers/{transfer.json()['transfer_id']}/receive",json={'confirmed':True}).status_code == 200
    with db as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE store_id=999 AND part_id=999').fetchone()[0] == 8
        assert conn.execute('SELECT quantity FROM inventory WHERE store_id=998 AND part_id=999').fetchone()[0] == 2

@pytest.mark.parametrize('operation', ['logout', 'reset'])
def test_session_revocation(api, operation):
    import asyncio
    from datetime import timedelta
    from backend.temporal import serialize_instant, utc_now
    client, db, current = api
    expires = serialize_instant(utc_now() + timedelta(days=1))
    for token, uid in [('current', 3), ('other', 3), ('unrelated', 4)]:
        db.execute('INSERT INTO sessions(user_id,session_token_hash,expires_at,is_active) VALUES(?,?,?,TRUE)',
                   (uid, hash_session_credential(token), expires))
    db.execute('UPDATE users SET reset_token=?,reset_token_expires=? WHERE id=3',
               ('reset-test', serialize_instant(utc_now() + timedelta(hours=1))))
    if operation == 'logout':
        current['id'] = 3
        client.cookies.set('session_token', 'current')
        response = client.post('/api/auth/logout', headers={'X-CSRF-Token': main.generate_csrf_token('current')})
    else:
        response = client.post('/api/reset-password', json={'token': 'reset-test', 'new_password': 'new-test-password'})
    assert response.status_code == 200, response.text
    states = {row[0]: row[1] for row in db.execute('SELECT session_token_hash,is_active FROM sessions')}
    assert states[hash_session_credential('current')] is False
    assert states[hash_session_credential('other')] is (operation == 'logout')
    assert states[hash_session_credential('unrelated')] is True
    # Exercise the real auth dependency directly.
    with pytest.raises(main.HTTPException) as error:
        asyncio.run(main.get_current_user('current'))
    assert error.value.status_code == 401


def test_company_admin_cannot_set_another_users_password(api):
    """SaaS password changes go through account recovery, never an admin-chosen password."""
    client, db, _ = api
    before = db.execute('SELECT password_hash FROM users WHERE id=3').fetchone()[0]
    sessions = db.execute('SELECT id,is_active FROM sessions ORDER BY id').fetchall()
    response = client.put('/api/users/3', json={'password': 'new-test-password'})
    assert response.status_code == 400
    assert response.json() == {'detail': 'Password changes use the account recovery flow'}
    assert db.execute('SELECT password_hash FROM users WHERE id=3').fetchone()[0] == before
    assert db.execute('SELECT id,is_active FROM sessions ORDER BY id').fetchall() == sessions


@pytest.mark.parametrize('work_order', [None, 'DUP-WO'])
def test_repeated_receipts_and_transfers_reuse_inventory_row(api, work_order):
    client, db, _ = api
    with db as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Source','central'),(998,'Destination','central')")
        conn.execute("INSERT INTO parts(id,part_number) VALUES(999,'DUP-TEST')")
    for store, qty in [(999,10),(999,5),(998,2)]:
        assert client.post('/api/inventory/add',json={'store_id':store,'part_id':999,'quantity':qty,'work_order_number':work_order}).status_code == 200
    with db as conn:
        rows = conn.execute('SELECT id,store_id,quantity FROM inventory WHERE part_id=999 ORDER BY store_id').fetchall()
        assert len(rows) == 2
        source_id = next(row[0] for row in rows if row[1] == 999)
    for _ in range(2):
        transfer = client.post('/api/inventory/transfer',json={'inventory_id':source_id,'to_store_id':998,'quantity':3})
        assert transfer.status_code == 200
        assert client.post(f"/api/inventory/transfers/{transfer.json()['transfer_id']}/receive",json={'confirmed':True}).status_code == 200
    with db as conn:
        assert conn.execute('SELECT store_id,quantity FROM inventory WHERE part_id=999 ORDER BY store_id').fetchall() == [(998,8),(999,9)]
        assert conn.execute('SELECT COUNT(*) FROM movements WHERE part_id=999').fetchone()[0] == 5


def test_duplicate_stock_is_rejected_and_receipt_preserves_existing_balance(api):
    client, db, _ = api
    with db as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Source','central')")
        conn.execute("INSERT INTO parts(id,part_number) VALUES(999,'OLD-DUP')")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9998,999,999,4)')
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9999,999,999,7)')
    assert client.post('/api/inventory/add',json={'store_id':999,'part_id':999,'quantity':2}).status_code == 200
    with db as conn:
        assert conn.execute('SELECT id,quantity FROM inventory WHERE part_id=999 ORDER BY id').fetchall() == [(9998,6)]


def test_simultaneous_receipts_create_one_row(api, stock_database):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from backend.services.tenant_context import set_tenant_context
    from regression_tests.postgres_app import ORG_A
    db = api[1]
    with db as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Concurrent','central')")
        conn.execute("INSERT INTO parts(id,part_number) VALUES(999,'CONCURRENT')")
    start = Barrier(2)
    def receipt():
        # Two runtime-role connections inside company A's RLS context.
        with stock_database.connect() as conn, conn.transaction():
            set_tenant_context(conn, ORG_A)
            start.wait(timeout=5)
            main.add_inventory_quantity(conn,999,999,3,None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(receipt) for _ in range(2)]
        for future in futures:
            future.result(timeout=10)
    with db as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE part_id=999').fetchall() == [(6,)]
