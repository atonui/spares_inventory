import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
import pytest
from regression_tests.migration_fixtures import legacy_connection

ROOT=Path(__file__).resolve().parents[1]

def run(command,path,*extra):
    return subprocess.run([sys.executable,'-m','backend.migrations',command,'--database',str(path),*extra],cwd=ROOT,capture_output=True,text=True)

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

@pytest.mark.parametrize('command',['status','check'])
def test_status_and_check_are_readonly(tmp_path,command):
    from backend.database import initialize_database,DEFAULT_SETTINGS
    p=tmp_path/'db with spaces.db';legacy_connection(p).close();initialize_database(p,defaults=DEFAULT_SETTINGS);before=digest(p)
    result=run(command,p)
    assert result.returncode==0,result.stderr
    assert '3' in result.stdout
    assert digest(p)==before

@pytest.mark.parametrize('command',['status','check'])
def test_readonly_commands_do_not_create_missing_database(tmp_path,command):
    p=tmp_path/'missing.db';result=run(command,p)
    assert result.returncode==1 and not p.exists()

def test_check_pending_returns_nonzero(tmp_path):
    p=tmp_path/'legacy.db';legacy_connection(p).close();before=digest(p)
    result=run('check',p);assert result.returncode==1
    assert 'pending' in result.stdout.lower() and digest(p)==before

def test_upgrade_requires_create_for_missing_path(tmp_path):
    p=tmp_path/'missing.db'
    assert run('upgrade',p).returncode==1 and not p.exists()
    result=run('upgrade',p,'--create');assert result.returncode==0,result.stderr
    with sqlite3.connect(p) as c:
        assert c.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0]==3
        assert c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0

@pytest.mark.parametrize('command',['status','check','upgrade'])
def test_cli_rejects_newer_history(tmp_path,command):
    from backend.database import initialize_database,DEFAULT_SETTINGS
    p=tmp_path/'future.db';initialize_database(p,defaults=DEFAULT_SETTINGS)
    with sqlite3.connect(p) as c:c.execute("INSERT INTO schema_migrations VALUES(99,'future','abc','now')")
    before=digest(p);result=run(command,p)
    assert result.returncode==1 and digest(p)==before
    assert 'history' in result.stderr.lower()

def test_cli_check_detects_legacy_orphans_without_repair(tmp_path):
    p=tmp_path/'broken.db';c=legacy_connection(p);c.execute('UPDATE inventory SET part_id=999');c.commit();c.close();before=digest(p)
    result=run('check',p);assert result.returncode==1
    assert 'foreign' in result.stderr.lower() and digest(p)==before
