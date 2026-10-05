"""Restore and authenticated HTTP writes serialize on the same SQLite writer lock."""
import shutil
import sqlite3
import threading
from contextlib import closing,contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
import main
import database_restore
from backend.database import connect_database
from backend.services.session_access import require_session
from regression_tests.session_fixtures import session_database,record_state
from regression_tests.test_session_write_routes import session_api,database_state


def restore_validator(conn):
    require_session(conn,'root-token',expected_user_id=2)
    main.require_superadmin(2,conn)


@pytest.mark.parametrize('damage,status',[
    ('UPDATE sessions SET is_active=0 WHERE id=2',401),
    ("UPDATE sessions SET expires_at='2000-01-01' WHERE id=2",401),
    ("UPDATE users SET role='engineer' WHERE id=2",403),
])
def test_restore_rechecks_original_session_under_lock(session_api,tmp_path,damage,status):
    client,live,control=session_api;upload=tmp_path/'upload.db';shutil.copyfile(live,upload)
    client.cookies.set('session_token','root-token');control['damage']=damage
    response=client.post('/api/superadmin/database/restore',files={'file':('upload.db',upload.read_bytes())})
    assert response.status_code==status,response.text
    assert database_state(live)==control['before']
    assert not list((live.parent/'restore_backups').glob('*.db'))
    with closing(connect_database(live)) as conn:conn.execute('BEGIN IMMEDIATE')


def test_unauthorized_restore_creates_no_snapshot(tmp_path):
    live=session_database(tmp_path/'live.db');upload=tmp_path/'upload.db';shutil.copyfile(live,upload)
    with closing(connect_database(live)) as conn,conn:conn.execute('UPDATE sessions SET is_active=0 WHERE id=2')
    before=database_state(live)
    with pytest.raises(main.HTTPException) as error:
        database_restore.restore_database(upload,live,2,validate_actor=restore_validator)
    assert error.value.status_code==401
    assert database_state(live)==before
    assert not list((tmp_path/'restore_backups').glob('*.db'))
    with closing(connect_database(live)) as conn:conn.execute('BEGIN IMMEDIATE')


def test_restore_first_rejects_waiting_http_write(session_api,tmp_path,monkeypatch):
    client,live,_=session_api;upload=tmp_path/'upload.db';shutil.copyfile(live,upload)
    reached=threading.Event();resume=threading.Event();original=main.authenticated_write_transaction
    @contextmanager
    def waiting(*args,**kwargs):
        reached.set();assert resume.wait(5),'writer not resumed'
        with original(*args,**kwargs) as conn:yield conn
    monkeypatch.setattr(main,'authenticated_write_transaction',waiting)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(client.post,'/api/inventory/add',json={'store_id':1,'part_id':1,'quantity':2})
        try:
            assert reached.wait(5),'request did not pass initial auth'
            database_restore.restore_database(upload,live,2,validate_actor=restore_validator)
            after_restore=database_state(live)
        finally:resume.set()
        response=future.result(timeout=5)
    assert response.status_code==401,response.text
    assert database_state(live)==after_restore
    assert record_state(live)==(10,0,1)


def test_write_first_is_in_pre_restore_snapshot(session_api,tmp_path,monkeypatch):
    client,live,_=session_api;upload=tmp_path/'upload.db';shutil.copyfile(live,upload)
    locked=threading.Event();attempted=threading.Event();resume=threading.Event()
    original=main.authenticated_write_transaction;connect=sqlite3.connect
    class Probe(sqlite3.Connection):
        def execute(self,sql,*args,**kwargs):
            if sql=='BEGIN IMMEDIATE' and locked.is_set() and Path(super().execute('PRAGMA database_list').fetchone()[2])==live:
                attempted.set()
            return super().execute(sql,*args,**kwargs)
    monkeypatch.setattr(database_restore.sqlite3,'connect',lambda *args,**kwargs:connect(*args,**{**kwargs,'factory':Probe}))
    @contextmanager
    def holding(*args,**kwargs):
        with original(*args,**kwargs) as conn:
            locked.set();assert resume.wait(5),'writer not resumed'
            yield conn
    monkeypatch.setattr(main,'authenticated_write_transaction',holding)
    with ThreadPoolExecutor(max_workers=2) as pool:
        write=pool.submit(client.post,'/api/inventory/add',json={'store_id':1,'part_id':1,'quantity':2})
        try:
            assert locked.wait(5)
            restore=pool.submit(database_restore.restore_database,upload,live,2,validate_actor=restore_validator)
            assert attempted.wait(5),'restore did not contend for live lock'
            assert not restore.done()
        finally:resume.set()
        response=write.result(timeout=5);backup_name=restore.result(timeout=5)
    assert response.status_code==200,response.text
    assert record_state(tmp_path/'restore_backups'/backup_name)==(12,1,1)
    assert record_state(live)==(10,0,1)


def test_restored_ids_do_not_authorize_original_token(session_api,tmp_path):
    client,live,_=session_api;upload=tmp_path/'upload.db';shutil.copyfile(live,upload)
    with closing(connect_database(upload)) as conn,conn:
        conn.execute("UPDATE sessions SET session_token='replacement-token' WHERE id=1")
        conn.execute("UPDATE users SET name='Restored different identity' WHERE id=1")
    database_restore.restore_database(upload,live,2,validate_actor=restore_validator)
    main.app.dependency_overrides[main.get_current_user]=lambda:1  # An ID retained before restore.
    before=database_state(live)
    response=client.post('/api/inventory/add',json={'store_id':1,'part_id':1,'quantity':2})
    assert response.status_code==401,response.text
    assert database_state(live)==before


def test_failed_restore_preserves_current_session(tmp_path):
    live=session_database(tmp_path/'live.db');upload=tmp_path/'upload.db';shutil.copyfile(live,upload)
    with closing(connect_database(upload)) as conn,conn:conn.execute("UPDATE users SET email='different@example.test' WHERE id=2")
    before=database_state(live)
    with pytest.raises(ValueError):database_restore.restore_database(upload,live,2,validate_actor=restore_validator)
    assert database_state(live)==before
    with closing(connect_database(live)) as conn:
        conn.execute('BEGIN IMMEDIATE')
        assert require_session(conn,'root-token',expected_user_id=2)['role']=='superadmin'
