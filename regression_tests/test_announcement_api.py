from contextlib import closing
import pytest
import main
from backend.database import connect_database
from regression_tests.test_session_write_routes import session_api,database_state
from regression_tests.test_superadmin_router import super_api

PREFIX='/api/superadmin/announcement'
def publish(c,**fields):
    c.cookies.set('session_token','root-token')
    old=c.get(PREFIX+'/manage').json()['announcement']
    body={'message':'Restricted notice','level':'info','timezone_revision':1,'expected_revision':old['revision'] if old else None,**fields}
    r=c.post(PREFIX,json=body);assert r.status_code==200,r.text
    return c.get(PREFIX+'/manage').json()['announcement']

@pytest.mark.parametrize('audience,roles',[('everyone',[]),('authenticated',[]),('roles',['manager'])])
@pytest.mark.parametrize('token,role',[(None,None),('unknown',None),('root-token','superadmin'),('admin-token','admin'),('manager-token','manager'),('engineer-token','engineer')])
def test_audience_matrix(super_api,audience,roles,token,role):
    c,_,_=super_api;publish(c,audience=audience,roles=roles)
    c.cookies.clear()
    if token:c.cookies.set('session_token',token)
    r=c.get(PREFIX);assert r.status_code==200
    assert r.headers['cache-control']=='no-store'
    expected=audience=='everyone' or audience=='authenticated' and role is not None or audience=='roles' and role in roles
    assert (r.json()['announcement'] is not None)==expected
    if not expected:assert 'Restricted notice' not in r.text

def test_management_permissions_and_expired_visibility(super_api):
    c,path,_=super_api
    n=publish(c,audience='roles',roles=['engineer'])
    with closing(connect_database(path)) as db,db:
        import json
        n['expires_at']='2020-01-01T00:00:00.000000Z'
        db.execute("UPDATE system_settings SET setting_value=? WHERE setting_key='system_announcement'",(json.dumps(n),))
    assert c.get(PREFIX).json()['announcement'] is None
    assert c.get(PREFIX+'/manage').json()['status']=='expired'
    c.cookies.set('session_token','engineer-token');assert c.get(PREFIX+'/manage').status_code==403

@pytest.mark.parametrize('fields',[{'audience':'roles','roles':[]},{'audience':'unknown'},{'audience':'roles','roles':['unknown']},{'starts_local':'2027-01-01T12:00','expires_local':'2027-01-01T11:00'},{'expires_local':'2020-01-01T12:00'}])
def test_invalid_controls_rollback(super_api,fields):
    c,path,_=super_api;before=database_state(path)
    r=c.post(PREFIX,json={'message':'x','level':'info','timezone_revision':1,**fields})
    assert r.status_code in (400,422);assert database_state(path)==before

def test_account_dismissal_revision_isolation_and_republish(super_api):
    c,_,_=super_api;n=publish(c,audience='authenticated',dismissible=True)
    c.cookies.set('session_token','engineer-token')
    for _ in range(2):assert c.post(PREFIX+'/dismiss',json={'revision':n['revision']}).status_code==200
    assert c.get(PREFIX).json()['announcement'] is None
    c.cookies.set('session_token','manager-token');assert c.get(PREFIX).json()['announcement'] is not None
    m=publish(c,audience='authenticated',dismissible=True)
    c.cookies.set('session_token','engineer-token')
    assert c.post(PREFIX+'/dismiss',json={'revision':n['revision']}).status_code==409
    assert c.get(PREFIX).json()['announcement']['revision']==m['revision']

def test_timezone_and_administrative_conflicts(super_api):
    c,_,_=super_api;n=publish(c)
    assert c.post(PREFIX,json={'message':'x','timezone_revision':2,'expected_revision':n['revision']}).status_code==409
    assert c.post(PREFIX,json={'message':'x','timezone_revision':1,'expected_revision':'stale'}).status_code==409
    assert c.delete(PREFIX,params={'expected_revision':'stale'}).status_code==409
    assert c.delete(PREFIX,params={'expected_revision':n['revision']}).status_code==200

def test_role_change_revocation_and_non_dismissible(super_api):
    c,path,_=super_api;n=publish(c,audience='roles',roles=['engineer'])
    c.cookies.set('session_token','engineer-token')
    assert c.post(PREFIX+'/dismiss',json={'revision':n['revision']}).status_code==403
    with closing(connect_database(path)) as db,db:db.execute("UPDATE users SET role='manager' WHERE id=3")
    assert c.get(PREFIX).json()['announcement'] is None
    with closing(connect_database(path)) as db,db:db.execute("UPDATE sessions SET is_active=0 WHERE session_token='root-token'")
    c.cookies.set('session_token','root-token');assert c.get(PREFIX).json()['announcement'] is None
    assert c.get(PREFIX+'/manage').status_code==401

def test_dismissal_rejects_account_switch_and_requires_csrf(super_api):
    c,_,_=super_api;n=publish(c,dismissible=True)
    c.cookies.set('session_token','engineer-token')
    assert c.post(PREFIX+'/dismiss',json={'revision':n['revision'],'viewer_key':'user:2'}).status_code==409
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert c.post(PREFIX+'/dismiss',json={'revision':n['revision']}).status_code==403
    assert c.get(PREFIX).json()['announcement'] is not None

def test_database_failure_is_not_anonymous_success(super_api,monkeypatch):
    from backend.services import announcements
    c,_,_=super_api
    monkeypatch.setattr(announcements,'load_notice',lambda conn: (_ for _ in ()).throw(RuntimeError('private details')))
    r=c.get(PREFIX)
    assert r.status_code==503 and r.headers['cache-control']=='no-store'
    assert 'private details' not in r.text

def test_corrupt_restricted_notice_rejected_by_reads_and_restore_validation(super_api):
    import json
    from backend.migrations import check_database
    c,path,_=super_api;n=publish(c,audience='roles',roles=['superadmin'])
    del n['audience']
    with closing(connect_database(path)) as db,db:
        db.execute("UPDATE system_settings SET setting_value=? WHERE setting_key='system_announcement'",(json.dumps(n),))
    c.cookies.clear()
    r=c.get(PREFIX)
    assert r.status_code==503 and 'Restricted notice' not in r.text
    with closing(connect_database(path)) as db:
        with pytest.raises(ValueError,match="Incomplete saved announcement controls"):check_database(db)
