import sqlite3
import subprocess
import sys
import os
from pathlib import Path
from contextlib import closing
import pytest
from fastapi import HTTPException
from backend.database import connect_database
from regression_tests.session_fixtures import session_database,record_state


def transaction():
    from backend.services.authenticated_transactions import authenticated_write_transaction
    return authenticated_write_transaction


def test_authenticated_transaction_commits_and_closes(tmp_path):
    path=session_database(tmp_path/'sessions.db')
    with transaction()(lambda:connect_database(path),user_id=1,session_token='admin-token') as conn:
        conn.execute('UPDATE inventory SET quantity=12 WHERE id=1')
    assert record_state(path)==(12,0,0)
    with pytest.raises(sqlite3.ProgrammingError):conn.execute('SELECT 1')


def test_denial_rolls_back_and_closes(tmp_path):
    path=session_database(tmp_path/'sessions.db');conn=connect_database(path)
    with pytest.raises(HTTPException) as error:
        with transaction()(lambda:conn,user_id=1,session_token='wrong'):
            pytest.fail('invalid session yielded to caller')
    assert error.value.status_code==401 and record_state(path)==(10,0,0)
    with pytest.raises(sqlite3.ProgrammingError):conn.execute('SELECT 1')
    with closing(connect_database(path)) as other:other.execute('BEGIN IMMEDIATE')


def test_exception_rolls_back_stock_movement_and_audit(tmp_path):
    path=session_database(tmp_path/'sessions.db')
    with pytest.raises(ValueError,match='stop'):
        with transaction()(lambda:connect_database(path),user_id=1,session_token='admin-token') as conn:
            conn.execute('UPDATE inventory SET quantity=12 WHERE id=1')
            conn.execute("INSERT INTO movements(part_id,quantity,movement_type,created_by) VALUES(1,2,'add',1)")
            conn.execute("INSERT INTO activity_logs(user_id,username,action) VALUES(1,'Admin','test')")
            raise ValueError('stop')
    assert record_state(path)==(10,0,0)


@pytest.mark.parametrize('detail',['Stock is busy; no changes saved. Try again','Database busy; no balances saved. Try again','Database is busy; no changes saved. Try again'])
def test_busy_details(tmp_path,detail):
    path=session_database(tmp_path/'sessions.db')
    with closing(connect_database(path)) as blocker:
        blocker.execute('BEGIN IMMEDIATE')
        with pytest.raises(HTTPException) as error:
            with transaction()(lambda:connect_database(path,timeout=.02),user_id=1,session_token='admin-token',busy_detail=detail):pytest.fail('locked writer yielded')
    assert (error.value.status_code,error.value.detail)==(409,detail)


def test_dynamic_database_factory(tmp_path,monkeypatch):
    import main
    first=session_database(tmp_path/'first.db');second=session_database(tmp_path/'second.db')
    monkeypatch.setattr(main,'DATABASE',str(first))
    with main.authenticated_write_transaction(1,'admin-token') as conn:
        monkeypatch.setattr(main,'DATABASE',str(second));conn.execute('UPDATE inventory SET quantity=12 WHERE id=1')
    with main.authenticated_write_transaction(1,'admin-token') as conn:conn.execute('UPDATE inventory SET quantity=15 WHERE id=1')
    assert record_state(first)==(12,0,0) and record_state(second)==(15,0,0)


def test_service_import_has_no_main_or_files(tmp_path):
    env={**os.environ,'PYTHONPATH':os.pathsep.join([str(Path(__file__).resolve().parents[1]),os.environ.get('PYTHONPATH','')])}
    code="import sys; import backend.services.session_access, backend.services.authenticated_transactions; assert 'main' not in sys.modules"
    result=subprocess.run([sys.executable,'-c',code],cwd=tmp_path,env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert list(tmp_path.iterdir())==[]
