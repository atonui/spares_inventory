import os
import sqlite3
import subprocess
import sys
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import main
from backend.database import initialize_database,connect_database
from backend.routes.work_orders import create_work_order_router
from regression_tests.test_work_order_service import conn
from regression_tests.test_work_orders import seed
from regression_tests.test_stock_safety import api

ROOT=Path(__file__).resolve().parents[1]

def test_router_uses_supplied_authentication_and_database(conn):
    path=conn.execute('PRAGMA database_list').fetchone()[2]
    app=FastAPI()
    def authenticate():return 3
    app.include_router(create_work_order_router(get_connection=lambda:connect_database(path),current_user=authenticate))
    with TestClient(app) as client:
        response=client.get('/api/work-orders')
        assert response.status_code==200
        assert [r['work_order_number'] for r in response.json()]==['WO-101']
        app.dependency_overrides[authenticate]=lambda:2
        assert [r['id'] for r in client.get('/api/work-orders').json()]==[103,102,101,104]

def test_registered_router_uses_changed_main_database(api,tmp_path,monkeypatch):
    seed(api);api[2]['id']=1
    assert [r['id'] for r in api[0].get('/api/work-orders').json()]==[103,102,101,104]
    second=tmp_path/'second.db';initialize_database(second,defaults={})
    with connect_database(second) as c:
        c.execute("INSERT INTO users(id,email,name,password_hash,role) VALUES(1,'one@test','One','unused','admin')")
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(500,'SECOND')")
    monkeypatch.setattr(main,'DATABASE',str(second))
    assert [r['work_order_number'] for r in api[0].get('/api/work-orders').json()]==['SECOND']
    monkeypatch.setattr(main,'DATABASE',str(api[1]))
    assert [r['id'] for r in api[0].get('/api/work-orders').json()]==[103,102,101,104]

def test_router_closes_connection_on_query_failure():
    c=sqlite3.connect(':memory:',check_same_thread=False);c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE users(id INTEGER,role TEXT)')
    c.execute("INSERT INTO users VALUES(1,'admin')")
    app=FastAPI();app.include_router(create_work_order_router(get_connection=lambda:c,current_user=lambda:1))
    with TestClient(app,raise_server_exceptions=False) as client:
        assert client.get('/api/work-orders').status_code==500
    with pytest.raises(sqlite3.ProgrammingError,match='closed'):c.execute('SELECT 1')

def test_backend_imports_have_no_application_side_effects(tmp_path):
    script='import sys; import backend.routes.work_orders, backend.services.work_orders, backend.schemas.work_orders; assert "main" not in sys.modules'
    result=subprocess.run([sys.executable,'-c',script],cwd=tmp_path,
        env={**os.environ,'PYTHONPATH':str(ROOT)+os.pathsep+os.environ.get('PYTHONPATH','')},capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert list(tmp_path.iterdir())==[]
