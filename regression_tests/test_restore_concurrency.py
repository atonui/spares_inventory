"""Real SQLite locking and rollback checks on disposable restore pairs."""
from pathlib import Path
import sqlite3
import pytest
import database_restore
from regression_tests.test_database_restore import restore_pair
from regression_tests.migration_fixtures import snapshot


@pytest.mark.parametrize('journal',['DELETE','WAL'])
def test_writer_cannot_commit_between_snapshot_and_restore(tmp_path,monkeypatch,journal):
    live,upload=restore_pair(tmp_path)
    connect=sqlite3.connect
    with connect(live) as c:c.execute('PRAGMA journal_mode='+journal)
    attempted=[]
    class ProbeConnection(sqlite3.Connection):
        def backup(self,destination,**kwargs):
            super().backup(destination,**kwargs)
            origin=Path(self.execute('PRAGMA database_list').fetchone()[2])
            if origin==live and not attempted:
                with connect(live,timeout=.02) as writer:
                    try:
                        writer.execute('UPDATE inventory SET quantity=999 WHERE id=1')
                        writer.commit()
                    except sqlite3.OperationalError as error:
                        assert 'locked' in str(error).lower()
                        attempted.append('blocked')
                    else:attempted.append('committed')
    monkeypatch.setattr(database_restore.sqlite3,'connect',lambda *a,**kw:connect(*a,**{**kw,'factory':ProbeConnection}))
    name=database_restore.restore_database(upload,live,7)
    assert attempted==['blocked']
    with connect(tmp_path/'restore_backups'/name) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0]==19
    with connect(live) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0]==19
        c.execute('UPDATE inventory SET quantity=20 WHERE id=1')
        c.commit()  # The restore releases its write lock on success.


def test_failure_after_stock_copy_rolls_back_every_table(tmp_path,monkeypatch):
    live,upload=restore_pair(tmp_path)
    connect=sqlite3.connect
    with connect(live) as c:
        c.execute('UPDATE inventory SET quantity=81 WHERE id=1')
        c.execute("UPDATE users SET session_token='keep-session' WHERE id=7")
        c.commit();before=snapshot(c)
        sequence=c.execute('SELECT * FROM sqlite_sequence ORDER BY name').fetchall()
    class FailingConnection(sqlite3.Connection):
        def executemany(self,sql,rows):
            result=super().executemany(sql,rows)
            if Path(self.execute('PRAGMA database_list').fetchone()[2])==live and sql.startswith('INSERT INTO "inventory"'):
                raise sqlite3.OperationalError('injected stock copy failure')
            return result
    monkeypatch.setattr(database_restore.sqlite3,'connect',lambda *a,**kw:connect(*a,**{**kw,'factory':FailingConnection}))
    with pytest.raises(sqlite3.OperationalError,match='injected stock copy failure'):
        database_restore.restore_database(upload,live,7)
    with connect(live) as c:
        assert snapshot(c)==before
        assert c.execute('SELECT * FROM sqlite_sequence ORDER BY name').fetchall()==sequence
        c.execute('UPDATE inventory SET quantity=82 WHERE id=1');c.commit()
    saved=list((tmp_path/'restore_backups').glob('*.db'))
    assert len(saved)==1
    with connect(saved[0]) as c:assert snapshot(c)==before


def test_restore_keeps_uploaded_autoincrement_state(tmp_path):
    live,upload=restore_pair(tmp_path)
    with sqlite3.connect(live) as c:
        c.execute("INSERT INTO parts(id,part_number) VALUES(900,'live-only')")
    with sqlite3.connect(upload) as c:
        c.execute("INSERT INTO parts(id,part_number) VALUES(300,'deleted-from-backup')")
        c.execute('DELETE FROM parts WHERE id=300')
    database_restore.restore_database(upload,live,7)
    with sqlite3.connect(live) as c:
        assert c.execute("INSERT INTO parts(part_number) VALUES('next')").lastrowid==301
        assert c.execute('PRAGMA foreign_key_check').fetchall()==[]


def test_busy_restore_returns_retry_without_snapshot_or_changes(tmp_path,monkeypatch):
    live,upload=restore_pair(tmp_path)
    connect=sqlite3.connect
    holder=connect(live)
    holder.execute('BEGIN IMMEDIATE')
    with connect(live) as c:before=snapshot(c)
    def fast_connect(*args,**kwargs):
        conn=connect(*args,**kwargs)
        if Path(args[0])==live:conn.execute('PRAGMA busy_timeout=20')
        return conn
    monkeypatch.setattr(database_restore.sqlite3,'connect',fast_connect)
    # Shorten the old backup retry loop as well, without waiting 30 seconds.
    clock=iter(range(0,10000,5))
    monkeypatch.setattr(database_restore.time,'monotonic',lambda:next(clock))
    try:
        with pytest.raises(TimeoutError,match='busy|retry'):
            database_restore.restore_database(upload,live,7)
        assert not list((tmp_path/'restore_backups').glob('*.db'))
        with connect(live) as c:assert snapshot(c)==before
    finally:holder.rollback();holder.close()
