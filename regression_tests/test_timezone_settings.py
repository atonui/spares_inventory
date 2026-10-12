import json
import sqlite3
import pytest
import main
from regression_tests.test_stock_safety import api


def test_context_defaults_and_personal_omission_vs_null(api):
    client, db, actor = api
    actor['id'] = 3
    initial = client.get('/api/timezone-context')
    assert initial.status_code == 200
    assert initial.json() == {'organisation_id':1,'business_timezone':'Africa/Nairobi','display_timezone':'Africa/Nairobi','revision':1}
    assert client.put('/api/profile', json={'display_timezone':'Europe/London'}).status_code == 200
    assert client.put('/api/profile', json={'email':'new@example.com'}).status_code == 200
    assert client.get('/api/profile').json()['display_timezone'] == 'Europe/London'
    assert client.get('/api/timezone-context').json()['display_timezone'] == 'Europe/London'
    assert client.put('/api/profile', json={'display_timezone':None}).status_code == 200
    assert client.get('/api/timezone-context').json()['display_timezone'] == 'Africa/Nairobi'


@pytest.mark.parametrize('actor_id', [1,2])
def test_authorised_business_change_audits_and_conflicting_revision_is_rejected(api, actor_id):
    client, db, actor = api
    actor['id'] = actor_id
    changed = client.put('/api/organisation/timezone',json={'timezone':'America/New_York','expected_revision':1})
    assert changed.status_code == 200
    assert changed.json()['revision'] == 2
    conflict = client.put('/api/organisation/timezone',json={'timezone':'UTC','expected_revision':1})
    assert conflict.status_code == 409
    assert client.get('/api/timezone-context').json()['business_timezone'] == 'America/New_York'
    with sqlite3.connect(db) as conn:
        records=conn.execute("SELECT user_id,details FROM activity_logs WHERE action='update_business_timezone'").fetchall()
    assert len(records)==1 and records[0][0]==actor_id
    details=json.loads(records[0][1]);assert details['old_timezone']=='Africa/Nairobi' and details['new_timezone']=='America/New_York'


@pytest.mark.parametrize('actor_id',[3,4])
def test_nonadmins_cannot_change_business_zone(api, actor_id):
    api[2]['id']=actor_id
    assert api[0].put('/api/organisation/timezone',json={'timezone':'UTC','expected_revision':1}).status_code==403


@pytest.mark.parametrize('body',[{'timezone':'IST','expected_revision':1},
 {'timezone':'UTC','expected_revision':True}, {'timezone':'UTC','expected_revision':0},
 {'timezone':'UTC','expected_revision':1,'tenant_id':9}])
def test_invalid_business_settings_are_rejected(api, body):
    assert api[0].put('/api/organisation/timezone',json=body).status_code==422


def test_personal_invalid_zone_and_business_csrf_rejected(api):
    client, db, actor=api
    assert client.put('/api/profile',json={'display_timezone':'BST'}).status_code==422
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert client.put('/api/organisation/timezone',json={'timezone':'UTC','expected_revision':1}).status_code==403


def test_inactive_actor_and_revoked_session_cannot_write(api):
    client, db, actor=api
    client.cookies.set('session_token','revoked')
    assert client.put('/api/organisation/timezone',json={'timezone':'UTC','expected_revision':1}).status_code==401
    with sqlite3.connect(db) as c:c.execute('UPDATE users SET archived_at=CURRENT_TIMESTAMP WHERE id=1')
    assert client.get('/api/timezone-context').status_code==403


def test_failed_audit_rolls_back_setting_update(api, monkeypatch):
    from backend.routes import timezone_settings
    def broken_audit(*args, **kwargs):
        raise RuntimeError('Audit storage unavailable')
    monkeypatch.setattr(timezone_settings,'record_activity',broken_audit)
    with pytest.raises(RuntimeError):
        api[0].put('/api/organisation/timezone',json={'timezone':'UTC','expected_revision':1})
    assert api[0].get('/api/timezone-context').json()['business_timezone']=='Africa/Nairobi'
    with sqlite3.connect(api[1]) as conn:
        assert conn.execute('SELECT revision FROM organisation_settings').fetchone()[0]==1


def test_concurrent_writers_cannot_both_save_same_revision(api):
    from concurrent.futures import ThreadPoolExecutor
    def save(zone):
        return api[0].put('/api/organisation/timezone',json={'timezone':zone,'expected_revision':1}).status_code
    with ThreadPoolExecutor(2) as workers:
        results=list(workers.map(save,['Europe/London','America/New_York']))
    assert sorted(results)==[200,409]
    assert api[0].get('/api/timezone-context').json()['revision']==2
