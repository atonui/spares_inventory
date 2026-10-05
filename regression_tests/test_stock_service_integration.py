import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from contextlib import closing
import pytest
from fastapi import HTTPException
import main
from backend.database import connect_database
from regression_tests.stock_service_fixtures import make_stock_database,write_stock_evidence,stock_state

ROOT=Path(__file__).resolve().parents[1]

def test_access_rejection_rolls_back_prior_stock_and_audit(tmp_path,monkeypatch):
    path=make_stock_database(tmp_path/'rejection.db');monkeypatch.setattr(main,'DATABASE',str(path))
    with pytest.raises(HTTPException) as caught:
        with main.stock_write_transaction() as c:
            write_stock_evidence(c,99)
            main.require_stock_access(c,3,'car',4)
    assert caught.value.status_code==403
    with pytest.raises(sqlite3.ProgrammingError,match='closed'):c.execute('SELECT 1')
    with closing(connect_database(path)) as saved:assert stock_state(saved)==(10,0,0)

def test_wrapper_uses_dynamic_database_path(tmp_path,monkeypatch):
    first=make_stock_database(tmp_path/'first.db');second=make_stock_database(tmp_path/'second.db')
    monkeypatch.setattr(main,'DATABASE',str(first))
    with main.stock_write_transaction() as c:
        monkeypatch.setattr(main,'DATABASE',str(second))
        c.execute('UPDATE inventory SET quantity=14 WHERE id=11')
    with closing(connect_database(first)) as a,closing(connect_database(second)) as b:
        assert stock_state(a)==(14,0,0) and stock_state(b)==(10,0,0)
    with main.stock_write_transaction() as c:c.execute('UPDATE inventory SET quantity=15 WHERE id=11')
    with closing(connect_database(first)) as a,closing(connect_database(second)) as b:
        assert stock_state(a)==(14,0,0) and stock_state(b)==(15,0,0)

def test_stock_service_imports_do_not_initialise_application(tmp_path):
    script='import sys; import backend.services.stock_transactions,backend.services.stock_access,backend.services.inventory; assert "main" not in sys.modules'
    result=subprocess.run([sys.executable,'-c',script],cwd=tmp_path,
        env={**os.environ,'PYTHONPATH':str(ROOT)+os.pathsep+os.environ.get('PYTHONPATH','')},capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert list(tmp_path.iterdir())==[]
