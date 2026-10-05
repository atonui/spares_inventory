import sqlite3
from contextlib import closing
import pytest
from fastapi import HTTPException
from backend.database import connect_database
from regression_tests.session_fixtures import session_database


def validator():
    from backend.services.session_access import require_session
    return require_session


@pytest.mark.parametrize('row_factory',[None,sqlite3.Row])
def test_valid_session_borrows_connection(tmp_path,row_factory):
    path=session_database(tmp_path/'sessions.db')
    with closing(connect_database(path)) as conn:
        conn.row_factory=row_factory
        conn.execute('BEGIN IMMEDIATE')
        row=validator()(conn,'admin-token',expected_user_id=1)
        assert (row['user_id'],row['role'],row['session_id'])==(1,'admin',1)
        assert conn.in_transaction
        assert conn.execute('SELECT 1').fetchone()[0]==1


@pytest.mark.parametrize('damage,token,actor,detail',[
    ('',None,1,'Not authenticated'),('', 'absent',1,'Invalid or expired session'),
    ('UPDATE sessions SET is_active=0 WHERE id=1','admin-token',1,'Invalid or expired session'),
    ("UPDATE users SET archived_at='2020-01-01' WHERE id=1",'admin-token',1,'Invalid or expired session'),
    ('','engineer-token',1,'Invalid or expired session'),
    ("UPDATE sessions SET expires_at='2000-01-01' WHERE id=1",'admin-token',1,'Session expired'),
    ("UPDATE sessions SET expires_at='broken' WHERE id=1",'admin-token',1,'Invalid or expired session'),
    ("UPDATE sessions SET session_token='replacement' WHERE id=1",'admin-token',1,'Invalid or expired session'),
])
def test_session_rejects_invalid_credentials(tmp_path,damage,token,actor,detail):
    path=session_database(tmp_path/'sessions.db')
    with closing(connect_database(path)) as conn:
        if damage:conn.execute(damage);conn.commit()
        conn.execute('BEGIN IMMEDIATE')
        before=conn.total_changes
        with pytest.raises(HTTPException) as error:validator()(conn,token,expected_user_id=actor)
        assert (error.value.status_code,error.value.detail)==(401,detail)
        assert conn.total_changes==before and conn.in_transaction
        assert conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]==3


@pytest.mark.parametrize('expiry',['2099-01-01T00:00:00','2099-01-01T00:00:00+03:00','2099-01-01T00:00:00Z'])
def test_expiry_formats(tmp_path,expiry):
    with closing(connect_database(session_database(tmp_path/'sessions.db'))) as conn:
        conn.execute('UPDATE sessions SET expires_at=? WHERE id=1',(expiry,));conn.commit()
        conn.execute('BEGIN IMMEDIATE')
        assert validator()(conn,'admin-token')['user_id']==1


def test_requires_transaction(tmp_path):
    with closing(connect_database(session_database(tmp_path/'sessions.db'))) as conn:
        with pytest.raises(ValueError):validator()(conn,'admin-token')
