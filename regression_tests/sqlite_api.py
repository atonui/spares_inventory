"""TEMPORARY: the former SQLite `api` fixture, for test files not yet moved to Postgres.

Delete this module once the auth, session, timezone and security-event tests are
ported (PR3c/PR3d). New tests must use `stock_api` from regression_tests.postgres_app.
"""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import main
from backend.security import hash_session_credential


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

