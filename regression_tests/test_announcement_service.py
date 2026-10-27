from datetime import datetime,timezone
import json
import pytest
from fastapi import HTTPException
from regression_tests.migration_fixtures import legacy_connection
from backend.migrations import apply_migrations,check_database
from backend.services.announcements import normalize_notice,save_notice,load_notice,remove_notice,dismiss_notice

@pytest.fixture
def db(tmp_path):
    c=legacy_connection(tmp_path/'notice.db');apply_migrations(c);yield c;c.close()

def test_legacy_notice_defaults_are_stable():
    raw={'message':'Notice','level':'info','set_at':'2026-10-14T12:00:00.000000Z'}
    n=normalize_notice(raw)
    assert n['audience']=='everyone' and not n['dismissible']
    assert n['starts_at'] is None and n['expires_at'] is None
    assert n['revision']==normalize_notice(raw)['revision']

def test_save_revision_resets_dismissals(db):
    n=save_notice(db,{'message':'Notice','level':'info'},actor_id=7,expected_revision=None)
    dismiss_notice(db,user_id=7,revision=n['revision'],now=datetime.now(timezone.utc))
    assert db.execute('SELECT COUNT(*) FROM announcement_dismissals').fetchone()[0]==1
    m=save_notice(db,{'message':'Updated','level':'warning'},actor_id=7,expected_revision=n['revision'])
    assert m['revision']!=n['revision'] and load_notice(db)['message']=='Updated'
    assert db.execute('SELECT COUNT(*) FROM announcement_dismissals').fetchone()[0]==0
    with pytest.raises(HTTPException) as e:remove_notice(db,expected_revision=n['revision'])
    assert e.value.status_code==409
    remove_notice(db,expected_revision=m['revision']);assert load_notice(db) is None

def test_migrations_are_idempotent_at_current_schema_version(db):
    status=check_database(db)
    assert 6 in status.applied
    assert status.current_version==status.target_version
    db.commit();apply_migrations(db);assert check_database(db).pending==()
    assert db.execute('PRAGMA foreign_key_list(announcement_dismissals)').fetchone()[2]=='users'

def test_old_backup_upgrades_without_changing_notice(tmp_path,monkeypatch):
    from backend.migrations.registry import MIGRATIONS
    from backend.migrations.runner import apply_migrations
    c=legacy_connection(tmp_path/'old.db')
    from backend.migrations import registry
    with monkeypatch.context() as patch:
        patch.setattr(registry,'MIGRATIONS',MIGRATIONS[:5])
        apply_migrations(c)
    payload=json.dumps({'message':'Original','level':'info','set_at':'2026-10-14T12:00:00.000000Z'})
    c.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('system_announcement',?)",(payload,));c.commit()
    apply_migrations(c)
    assert c.execute("SELECT setting_value FROM system_settings WHERE setting_key='system_announcement'").fetchone()[0]==payload
    assert c.execute('SELECT quantity FROM inventory').fetchone()[0]==19

@pytest.mark.parametrize('missing',['revision','audience','roles','starts_at','expires_at','dismissible'])
def test_partial_modern_notice_fails_closed(missing):
    payload={'message':'Secret','level':'info','revision':'A','audience':'roles','roles':['superadmin'],'starts_at':None,'expires_at':None,'dismissible':False}
    del payload[missing]
    with pytest.raises(ValueError):normalize_notice(payload)
