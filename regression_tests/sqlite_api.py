"""TEMPORARY: the former SQLite `api` fixture, for test files not yet moved to Postgres.

Delete this module once the auth, session, timezone and security-event tests are
ported (PR3c/PR3d). New tests must use `stock_api` from regression_tests.postgres_app.
"""
import os
import sqlite3
from contextlib import closing

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

import main
from backend.database import connect_database
from backend.security import hash_session_credential
from regression_tests.session_fixtures import session_database


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
    with sqlite3.connect(db) as conn:
        conn.execute('DELETE FROM users')
        password_hash = main.hash_password('test-password')
        for uid, role in [(1, 'admin'), (2, 'superadmin'), (3, 'engineer'), (4, 'manager')]:
            conn.execute('INSERT INTO users(id,email,name,password_hash,role) VALUES(?,?,?,?,?)',
                         (uid, f'user{uid}@example.com', f'User {uid}', password_hash, role))
        conn.executemany('INSERT INTO sessions(user_id,session_token,expires_at) VALUES(?,?,?)',
            [(uid,hash_session_credential(f'fixture-session-{uid}'),'2099-01-01T00:00:00.000000Z') for uid in (1,2,3,4)])
    current = {'id': 1}
    main.app.dependency_overrides[main.get_current_user] = lambda: current['id']
    main.app.dependency_overrides[main.verify_csrf] = lambda: True
    main.app.dependency_overrides[main.verify_authenticated_csrf] = lambda: True
    with TestClient(main.app) as client:
        def credential(request):
            # Preserve tokens explicitly supplied by session-management tests.
            if main.get_current_user in main.app.dependency_overrides and 'session_token=' not in request.headers.get('cookie',''):
                prior=request.headers.get('cookie','')
                request.headers['cookie']=(prior+'; ' if prior else '')+f"session_token=fixture-session-{current['id']}"
        client.event_hooks['request'].append(credential)
        yield client, db, current
    main.app.dependency_overrides.clear()


def database_state(path):
    with closing(connect_database(path)) as conn:
        result={}
        tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for table in tables:
            columns=[r[1] for r in conn.execute(f'PRAGMA table_info("{table}")') if not (table=='sessions' and r[1]=='last_activity')]
            result[table]=[tuple(r) for r in conn.execute('SELECT '+','.join('"'+c+'"' for c in columns)+f' FROM "{table}" ORDER BY rowid')]
        return result


@pytest.fixture
def session_api(tmp_path,monkeypatch):
    path=session_database(tmp_path/'http.db');monkeypatch.setattr(main,'DATABASE',str(path))
    with closing(connect_database(path)) as conn,conn:
        conn.execute("INSERT INTO users(id,email,name,password_hash,role) VALUES(4,'manager@example.test','Manager','unused','manager')")
        conn.execute("INSERT INTO sessions(id,user_id,session_token,expires_at) VALUES(4,4,?,'2099-01-01T00:00:00.000000Z')", (hash_session_credential('manager-token'),))
        conn.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(2,'Car','engineer',3),(3,'Empty','central',NULL)")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(2,'EMPTY','Empty part','test',0)")
        conn.execute("INSERT INTO store_types(type_code,type_name) VALUES('unused','Unused')")
        conn.execute("INSERT INTO equipment(id,equipment_name,make,model,serial_number,assigned_user_id) VALUES(1,'Meter','Maker','M1','SERIAL',3)")
    control={'damage':None,'before':None}
    async def initial_auth(request:Request):
        uid=await main.get_current_user(request.cookies.get('session_token'))
        if control['damage']:
            with closing(connect_database(path)) as conn,conn:
                conn.execute(control['damage'])
            control['before']=database_state(path)
        return uid
    main.app.dependency_overrides[main.get_current_user]=initial_auth
    main.app.dependency_overrides[main.verify_csrf]=lambda:True
    main.app.dependency_overrides[main.verify_authenticated_csrf]=lambda:True
    try:
        with TestClient(main.app) as client:
            client.cookies.set('session_token','admin-token')
            yield client,path,control
    finally:main.app.dependency_overrides.clear()
