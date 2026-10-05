import sqlite3
from contextlib import closing
import pytest
from fastapi import HTTPException
import main
from backend.database import connect_database
from regression_tests.stock_service_fixtures import make_stock_database,write_stock_evidence,stock_state

@pytest.fixture
def path(tmp_path):return make_stock_database(tmp_path/'stock.db')

def assert_closed(conn):
    with pytest.raises(sqlite3.ProgrammingError,match='closed'):conn.execute('SELECT 1')

def test_main_transaction_commits_and_closes(path,monkeypatch):
    monkeypatch.setattr(main,'DATABASE',str(path))
    with main.stock_write_transaction() as c:write_stock_evidence(c,11)
    assert_closed(c)
    with closing(connect_database(path)) as saved:assert stock_state(saved)==(11,1,1)

def test_main_transaction_rolls_back_all_evidence(path,monkeypatch):
    monkeypatch.setattr(main,'DATABASE',str(path))
    with pytest.raises(ValueError,match='failure'):
        with main.stock_write_transaction() as c:
            write_stock_evidence(c,99)
            raise ValueError('failure')
    assert_closed(c)
    with closing(connect_database(path)) as saved:assert stock_state(saved)==(10,0,0)

def test_transaction_service_commits_and_closes(path):
    from backend.services.stock_transactions import write_stock_transaction
    with write_stock_transaction(lambda:connect_database(path)) as c:write_stock_evidence(c,11)
    assert_closed(c)
    with closing(connect_database(path)) as saved:assert stock_state(saved)==(11,1,1)

def test_transaction_service_rolls_back(path):
    from backend.services.stock_transactions import write_stock_transaction
    with pytest.raises(ValueError,match='failure'):
        with write_stock_transaction(lambda:connect_database(path)) as c:
            write_stock_evidence(c,99)
            raise ValueError('failure')
    assert_closed(c)
    with closing(connect_database(path)) as saved:assert stock_state(saved)==(10,0,0)

def test_transaction_service_blocks_another_writer(path):
    from backend.services.stock_transactions import write_stock_transaction
    with write_stock_transaction(lambda:connect_database(path)) as holder:
        entered=False
        with pytest.raises(HTTPException) as caught:
            with write_stock_transaction(lambda:connect_database(path,timeout=.02)):
                entered=True
        assert caught.value.status_code==409
        assert caught.value.detail=='Stock is busy; no changes saved. Try again'
        assert not entered
        assert stock_state(holder)==(10,0,0)
    with closing(connect_database(path)) as saved:assert stock_state(saved)==(10,0,0)

def test_transaction_preserves_error_when_caller_closes_connection(path):
    from backend.services.stock_transactions import write_stock_transaction
    with pytest.raises(ValueError,match='original failure'):
        with write_stock_transaction(lambda:connect_database(path)) as c:
            c.close()
            raise ValueError('original failure')
    assert_closed(c)
