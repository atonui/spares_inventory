import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def api(tmp_path, monkeypatch):
    db = tmp_path / 'inventory.db'
    backup = os.environ.get('INVENTORY_TEST_BACKUP')
    if backup:
        with sqlite3.connect('file:' + backup + '?mode=ro', uri=True) as src:
            with sqlite3.connect(db) as dst:
                src.backup(dst)
    monkeypatch.setattr(main, 'DATABASE', str(db))
    main.init_db()
    # Complete a fresh fixture's schema without changing the app's existing
    # startup migration behaviour (outside this patch's scope).
    import ast
    import inspect
    schema = ast.parse(inspect.getsource(main.init_db))
    with sqlite3.connect(db) as conn:
        for node in ast.walk(schema):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.strip().upper().startswith('CREATE TABLE IF NOT EXISTS'):
                    conn.execute(node.value)
    with sqlite3.connect(db) as conn:
        conn.execute('DELETE FROM users')
        for uid, role in [(1, 'admin'), (2, 'superadmin'), (3, 'engineer'), (4, 'manager')]:
            conn.execute('INSERT INTO users(id,email,name,password_hash,role) VALUES(?,?,?,?,?)',
                         (uid, f'user{uid}@example.com', f'User {uid}', main.hash_password('test-password'), role))
    current = {'id': 1}
    main.app.dependency_overrides[main.get_current_user] = lambda: current['id']
    main.app.dependency_overrides[main.verify_csrf] = lambda: True
    with TestClient(main.app) as client:
        yield client, db, current
    main.app.dependency_overrides.clear()


@pytest.mark.parametrize('endpoint,payload', [
    ('/api/inventory/add', {'part_id': 1, 'store_id': 1, 'quantity': 0}),
    ('/api/inventory/transfer', {'inventory_id': 1, 'to_store_id': 2, 'quantity': -3}),
    ('/api/inventory/consume', {'inventory_id': 1, 'quantity': -1, 'work_order_number': 'TEST'}),
    ('/api/inventory/update', {'inventory_id': 1, 'new_quantity': -2}),
])
def test_invalid_quantity_is_rejected_before_writing(api, endpoint, payload):
    client, db, _ = api
    before = sqlite3.connect(db).execute('SELECT SUM(quantity),COUNT(*) FROM inventory').fetchone()
    response = client.request('PUT' if endpoint.endswith('/update') else 'POST', endpoint, json=payload)
    assert response.status_code == 422
    assert sqlite3.connect(db).execute('SELECT SUM(quantity),COUNT(*) FROM inventory').fetchone() == before


@pytest.mark.parametrize('quantity', [1.5, True, '2'])
def test_quantity_must_be_integer(api, quantity):
    response = api[0].post('/api/inventory/add', json={'part_id': 1, 'store_id': 1, 'quantity': quantity})
    assert response.status_code == 422


@pytest.mark.parametrize('method,path,payload', [
    ('POST', '/api/users', {'email': 'new@example.com', 'name': 'New', 'password': 'test-password', 'role': 'superadmin'}),
    ('PUT', '/api/users/3', {'role': 'superadmin'}),
    ('PUT', '/api/users/2', {'name': 'Changed'}),
    ('DELETE', '/api/users/2', None),
])
def test_admin_cannot_assign_or_modify_superadmin(api, method, path, payload):
    response = api[0].request(method, path, json=payload)
    assert response.status_code == 403
    with sqlite3.connect(api[1]) as conn:
        assert conn.execute('SELECT role,name FROM users WHERE id=2').fetchone() == ('superadmin', 'User 2')
        assert conn.execute('SELECT role FROM users WHERE id=3').fetchone()[0] == 'engineer'


def test_invalid_role_rejected(api):
    assert api[0].put('/api/users/3', json={'role': 'made-up'}).status_code == 422


def test_admin_can_update_engineer(api):
    assert api[0].put('/api/users/3', json={'name': 'Updated'}).status_code == 200


def test_superadmin_can_assign_privileged_role(api):
    api[2]['id'] = 2
    assert api[0].put('/api/users/3', json={'role': 'superadmin'}).status_code == 200


def test_same_store_transfer_rejected(api):
    with sqlite3.connect(api[1]) as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Test Store','central')")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'TEST','Test','test',0)")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9999,999,999,10)')
    response = api[0].post('/api/inventory/transfer', json={'inventory_id': 9999, 'to_store_id': 999, 'quantity': 2})
    assert response.status_code == 400
    assert sqlite3.connect(api[1]).execute('SELECT quantity FROM inventory WHERE id=9999').fetchone()[0] == 10


def test_valid_stock_workflow(api):
    client, db, _ = api
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO stores(id,name,type) VALUES(999,'Test Source','central'),(998,'Test Destination','central')")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'TEST','Test','test',0)")
    assert client.post('/api/inventory/add', json={'part_id': 999, 'store_id': 999, 'quantity': 10}).status_code == 200
    iid = sqlite3.connect(db).execute('SELECT id FROM inventory WHERE part_id=999').fetchone()[0]
    assert client.post('/api/inventory/transfer', json={'inventory_id': iid, 'to_store_id': 998, 'quantity': 3}).status_code == 200
    assert client.post('/api/inventory/consume', json={'inventory_id': iid, 'quantity': 2, 'work_order_number': 'TEST-WO'}).status_code == 200
    assert client.put('/api/inventory/update', json={'inventory_id': iid, 'new_quantity': 0}).status_code == 200
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE part_id=999 AND store_id=999').fetchone()[0] == 0
        assert conn.execute('SELECT quantity FROM inventory WHERE part_id=999 AND store_id=998').fetchone()[0] == 3


def test_add_stock_form_sends_numeric_quantity():
    import subprocess
    from pathlib import Path
    script = Path(main.__file__).parent / 'static' / 'script.js'
    code = """
const fs = require('fs'); const vm = require('vm');
const context = { console }; vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const app = context.inventoryApp(); let sent;
app.addForm = {part_id: '1', store_id: '1', quantity: '2', work_order_number: ''};
app.apiCall = async (path, options) => { sent = JSON.parse(options.body); };
app.loadInventory = async () => {}; app.loadStats = async () => {};
(async () => { await app.addStock();
if (sent.quantity !== 2) throw new Error('Stock form must send quantity as a number');
})();
"""
    result = subprocess.run(['node', '-e', code, str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

@pytest.mark.parametrize('role', [3, 4])
@pytest.mark.parametrize('operation', ['add', 'update', 'consume', 'transfer'])
def test_other_users_store_cannot_be_changed(api, role, operation):
    client, db, current = api
    current['id'] = role
    with sqlite3.connect(db) as conn:
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
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE id=9999').fetchone()[0] == 10
        assert conn.execute('SELECT COUNT(*) FROM inventory WHERE part_id=999').fetchone()[0] == 1

@pytest.mark.parametrize('actor,owner,kind', [(1,2,'car'),(2,1,'car'),(3,3,'car'),(3,None,'central')])
def test_existing_authorized_store_access(api, actor, owner, kind):
    with sqlite3.connect(api[1]) as conn:
        conn.row_factory = sqlite3.Row
        main.require_stock_access(conn, actor, kind, owner)


def test_temporary_restore_route_removed():
    assert not any(route.path == '/upload-database' for route in main.app.routes)


def test_engineer_can_deliver_from_own_store_to_other_engineer(api):
    client, db, current = api
    current['id'] = 3
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(999,'Mine','car',3),(998,'Other','car',4)")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(999,'DELIVERY','Delivery Test','test',0)")
        conn.execute('INSERT INTO inventory(id,store_id,part_id,quantity) VALUES(9999,999,999,10)')
    assert client.post('/api/inventory/transfer', json={'inventory_id':9999,'to_store_id':998,'quantity':2}).status_code == 200
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE store_id=999 AND part_id=999').fetchone()[0] == 8
        assert conn.execute('SELECT quantity FROM inventory WHERE store_id=998 AND part_id=999').fetchone()[0] == 2

@pytest.mark.parametrize('operation', ['logout', 'reset', 'admin_password'])
def test_session_revocation(api, operation):
    from datetime import datetime, timedelta
    client, db, current = api
    with sqlite3.connect(db) as conn:
        columns = {row[1] for row in conn.execute('PRAGMA table_info(users)')}
        for column in ['reset_token', 'reset_token_expires', 'session_token']:
            if column not in columns:
                conn.execute(f'ALTER TABLE users ADD COLUMN {column} TEXT')
        conn.execute('DELETE FROM sessions')
        for token, uid in [('current',3),('other',3),('unrelated',4)]:
            conn.execute('INSERT INTO sessions(user_id,session_token,expires_at,is_active) VALUES(?,?,?,1)', (uid,token,(datetime.utcnow()+timedelta(days=1)).isoformat()))
        conn.execute('UPDATE users SET reset_token=?,reset_token_expires=? WHERE id=3', ('reset-test',(datetime.utcnow()+timedelta(hours=1)).isoformat()))
    if operation == 'logout':
        current['id'] = 3
        client.cookies.set('session_token','current')
        response = client.post('/api/auth/logout')
    elif operation == 'reset':
        response = client.post('/api/reset-password',json={'token':'reset-test','new_password':'new-test-password'})
    else:
        response = client.put('/api/users/3',json={'password':'new-test-password'})
    assert response.status_code == 200
    with sqlite3.connect(db) as conn:
        states = dict(conn.execute('SELECT session_token,is_active FROM sessions'))
    assert states['current'] == 0
    assert states['other'] == (1 if operation == 'logout' else 0)
    assert states['unrelated'] == 1
    # Exercise the real auth dependency, independently of the test API override.
    import asyncio
    with pytest.raises(main.HTTPException) as error:
        asyncio.run(main.get_current_user('current'))
    assert error.value.status_code == 401
