import sqlite3
import shutil
import pytest
from database_restore import restore_database


def test_restore_saves_current_database_and_revokes_sessions(tmp_path):
    live=tmp_path/'live.db'; upload=tmp_path/'upload.db'
    from regression_tests.migration_fixtures import legacy_connection
    from backend.database import initialize_database,DEFAULT_SETTINGS
    c=legacy_connection(live)
    c.execute('UPDATE inventory SET quantity=1 WHERE id=1')
    c.execute("UPDATE users SET session_token='old' WHERE id=7")
    c.execute("INSERT INTO sessions(user_id,session_token,expires_at) VALUES(7,'old','2099-01-01')")
    c.commit();c.close();initialize_database(live,defaults=DEFAULT_SETTINGS)
    shutil.copyfile(live,upload)
    with sqlite3.connect(live) as c:c.execute('UPDATE inventory SET quantity=99 WHERE id=1')
    name=restore_database(upload,live,7)
    with sqlite3.connect(live) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM sessions WHERE is_active=1').fetchone()[0]==0
        assert c.execute("SELECT COUNT(*) FROM activity_logs WHERE action='database_restore'").fetchone()[0]==1
    with sqlite3.connect(tmp_path/'restore_backups'/name) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0]==99


def test_wrong_schema_is_rejected_without_live_changes(tmp_path):
    live=tmp_path/'live.db';upload=tmp_path/'upload.db'
    from backend.database import initialize_database,DEFAULT_SETTINGS
    from regression_tests.migration_fixtures import legacy_connection
    legacy_connection(live).close();initialize_database(live,defaults=DEFAULT_SETTINGS)
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
    from backend.database import initialize_database,DEFAULT_SETTINGS
    from regression_tests.migration_fixtures import legacy_connection
    legacy_connection(live).close();initialize_database(live,defaults=DEFAULT_SETTINGS)
    shutil.copyfile(live,upload)
    with sqlite3.connect(upload) as c:c.execute(extra_sql)
    before=live.read_bytes()
    with pytest.raises(ValueError):restore_database(upload,live,7)
    assert live.read_bytes()==before


def restore_pair(tmp_path,*,legacy=False):
    from regression_tests.migration_fixtures import legacy_connection
    from backend.database import initialize_database,DEFAULT_SETTINGS
    live=tmp_path/'live.db';upload=tmp_path/'upload.db'
    c=legacy_connection(live);c.close();initialize_database(live,defaults=DEFAULT_SETTINGS)
    if legacy:legacy_connection(upload).close()
    else:shutil.copyfile(live,upload)
    return live,upload


def test_restore_legacy_without_ledger(tmp_path):
    from regression_tests.migration_fixtures import snapshot
    live,upload=restore_pair(tmp_path,legacy=True)
    restore_database(upload,live,7)
    with sqlite3.connect(live) as c:
        assert c.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0]==3
        assert c.execute('SELECT quantity FROM inventory').fetchone()[0]==19
        assert c.execute('PRAGMA foreign_key_check').fetchall()==[]


def test_restore_current_migrated_backup(tmp_path):
    live,upload=restore_pair(tmp_path)
    restore_database(upload,live,7)
    with sqlite3.connect(live) as c:assert c.execute('SELECT version FROM schema_migrations ORDER BY version').fetchall()==[(1,),(2,),(3,)]


def test_restore_newer_ledger_rejected_without_live_changes(tmp_path):
    live,upload=restore_pair(tmp_path)
    with sqlite3.connect(upload) as c:c.execute("INSERT INTO schema_migrations VALUES(99,'future','abc','now')")
    before=live.read_bytes()
    with pytest.raises(ValueError,match='newer|Unknown|history'):restore_database(upload,live,7)
    assert live.read_bytes()==before


def test_restore_migration_failure_preserves_live_sessions_and_stock(tmp_path,monkeypatch):
    from dataclasses import replace
    from backend.migrations import registry
    live,upload=restore_pair(tmp_path,legacy=True);before=live.read_bytes()
    def fail(c):
        c.execute('UPDATE inventory SET quantity=999')
        raise RuntimeError('injected upgrade failure')
    monkeypatch.setattr(registry,'MIGRATIONS',(registry.MIGRATIONS[0],replace(registry.MIGRATIONS[1],upgrade=fail),registry.MIGRATIONS[2]))
    with pytest.raises(ValueError,match='injected upgrade failure'):restore_database(upload,live,7)
    assert live.read_bytes()==before


def test_restore_requires_matching_superadmin_after_upgrade(tmp_path):
    live,upload=restore_pair(tmp_path,legacy=True)
    with sqlite3.connect(upload) as c:c.execute("UPDATE users SET email='someone-else@example.com' WHERE id=7")
    before=live.read_bytes()
    with pytest.raises(ValueError,match='superadmin'):restore_database(upload,live,7)
    assert live.read_bytes()==before


def test_restore_older_optional_columns(tmp_path):
    live,upload=restore_pair(tmp_path,legacy=True)
    with sqlite3.connect(upload) as c:
        for col in ['session_expires','failed_login_attempts','account_locked_until','last_login','reset_token','reset_token_expires']:
            c.execute('ALTER TABLE users DROP COLUMN '+col)
        c.execute('ALTER TABLE movements DROP COLUMN notes')
    restore_database(upload,live,7)
    with sqlite3.connect(live) as c:assert c.execute('SELECT quantity FROM inventory').fetchone()[0]==19

@pytest.mark.parametrize('damage',['generated','conflict'])
def test_restore_rejects_hidden_columns_and_changed_conflicts(tmp_path,damage):
    live,upload=restore_pair(tmp_path)
    with sqlite3.connect(upload) as c:
        if damage=='generated':
            c.execute('ALTER TABLE parts ADD COLUMN hidden_extra TEXT GENERATED ALWAYS AS (part_number) VIRTUAL')
        else:
            upload.unlink()
            from regression_tests.migration_fixtures import FIXTURES
            with sqlite3.connect(upload) as altered:
                sql=(FIXTURES/'legacy_inventory.sql').read_text()
                altered.executescript(sql.replace('part_number TEXT UNIQUE NOT NULL','part_number TEXT UNIQUE ON CONFLICT REPLACE NOT NULL'))
                altered.execute("INSERT INTO users(id,email,name,password_hash,role) VALUES(7,'test@example.com','Test','hash','superadmin')")
    before=live.read_bytes()
    with pytest.raises(ValueError):restore_database(upload,live,7)
    assert live.read_bytes()==before
