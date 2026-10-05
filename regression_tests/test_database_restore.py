import sqlite3
import shutil
import pytest
from database_restore import restore_database


def test_restore_saves_current_database_and_revokes_sessions(tmp_path):
    live=tmp_path/'live.db'; upload=tmp_path/'upload.db'
    with sqlite3.connect(live) as c:
        c.executescript("""
        CREATE TABLE users(id INTEGER,email TEXT,role TEXT,session_token TEXT,reset_token TEXT,reset_token_expires TEXT);
        INSERT INTO users VALUES(7,'test@example.com','superadmin','old',NULL,NULL);
        CREATE TABLE sessions(is_active INTEGER);
        INSERT INTO sessions VALUES(1);
        CREATE TABLE inventory(id INTEGER,quantity INTEGER);
        INSERT INTO inventory VALUES(13,1);
        CREATE TABLE activity_logs(user_id INTEGER,username TEXT,action TEXT,resource_type TEXT,details TEXT);
        """)
    shutil.copyfile(live,upload)
    with sqlite3.connect(live) as c:c.execute('UPDATE inventory SET quantity=99 WHERE id=13')
    name=restore_database(upload,live,7)
    with sqlite3.connect(live) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=13').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM sessions WHERE is_active=1').fetchone()[0]==0
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='database_restore'").fetchone()[0]==1
    with sqlite3.connect(tmp_path/'restore_backups'/name) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=13').fetchone()[0]==99


def test_wrong_schema_is_rejected_without_live_changes(tmp_path):
    live=tmp_path/'live.db';upload=tmp_path/'upload.db'
    with sqlite3.connect(live) as c:c.execute('CREATE TABLE users(id INTEGER)')
    with sqlite3.connect(upload) as c:c.execute('CREATE TABLE wrong(id INTEGER)')
    before=live.read_bytes()
    with pytest.raises(ValueError):restore_database(upload,live,7)
    assert live.read_bytes()==before


from regression_tests.test_stock_safety import api

@pytest.mark.parametrize('actor',[1,3,4])
def test_restore_requires_superadmin(api,actor):
    api[2]['id']=actor
    response=api[0].post('/api/superadmin/database/restore',files={'file':('bad.db',b'not sqlite')})
    assert response.status_code==403


def test_restore_rejects_invalid_upload(api):
    api[2]['id']=2
    response=api[0].post('/api/superadmin/database/restore',files={'file':('bad.db',b'not sqlite')})
    assert response.status_code==400


def test_restore_requires_csrf(api):
    import main
    api[2]['id']=2
    main.app.dependency_overrides.pop(main.verify_csrf)
    response=api[0].post('/api/superadmin/database/restore',files={'file':('bad.db',b'not sqlite')})
    assert response.status_code==403


@pytest.mark.parametrize('extra_sql',[
    'CREATE TABLE unexpected(id INTEGER)',
    'CREATE UNIQUE INDEX unexpected ON users(id)',
])
def test_extra_schema_objects_are_rejected(tmp_path, extra_sql):
    live=tmp_path/'live.db'; upload=tmp_path/'upload.db'
    with sqlite3.connect(live) as c:c.execute('CREATE TABLE users(id INTEGER)')
    shutil.copyfile(live,upload)
    with sqlite3.connect(upload) as c:c.execute(extra_sql)
    before=live.read_bytes()
    with pytest.raises(ValueError):restore_database(upload,live,7)
    assert live.read_bytes()==before
