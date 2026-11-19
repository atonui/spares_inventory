"""Actual HTTP mutations must reject credentials revoked after initial auth."""
import psycopg
import pytest
from fastapi import Request
import main
from backend.security import hash_session_credential
from regression_tests.postgres_app import database_state as _database_state, fail_inserts


def database_state(api):
    return _database_state(api.db)


@pytest.fixture
def session_api(tenant_api):
    """(client, api, control) on Postgres. control['damage'] runs SQL as the owner
    right after real authentication and before the route's write transaction."""
    control={'damage':None,'before':None}
    async def initial_auth(request:Request):
        uid=await main.get_current_user(request.cookies.get('session_token'))
        if control['damage']:
            tenant_api.legacy_db.execute(control['damage'])
            control['before']=database_state(tenant_api)
        return uid
    main.app.dependency_overrides[main.get_current_user]=initial_auth
    try:
        yield tenant_api.client,tenant_api,control
    finally:
        main.app.dependency_overrides.clear()


def unused_store_type(api):
    return api.db.execute("SELECT id FROM store_types WHERE type_code='unused'").fetchone()['id']


STOCK_CASES=[
 ('stock_consume','POST','/api/inventory/consume',{'inventory_id':1,'quantity':2,'work_order_number':'WO-NEW'},None),
 ('stock_add','POST','/api/inventory/add',{'store_id':1,'part_id':1,'quantity':2},None),
 ('stock_update','PUT','/api/inventory/update',{'inventory_id':1,'new_quantity':8},None),
 ('stock_transfer','POST','/api/inventory/transfer',{'inventory_id':1,'to_store_id':2,'quantity':2},None),
 ('import_balances','POST','/api/inventory/import-balances',{'store_id':1,'rows':[{'part_number':'PART','quantity':8,'expected_quantity':10}]},None),
 ('minimum','PUT','/api/inventory/minimum',{'store_id':1,'part_id':1,'min_threshold':3,'expected_minimum':0},None),
 ('stock_receive','POST','/api/inventory/transfers/8/receive',{'confirmed':True},'transfer'),
 ('stock_return','POST','/api/inventory/transfers/8/return',{'confirmed':True},'transfer'),
 ('count','POST','/api/inventory/count-confirm',None,'count'),
 ('archive_user','DELETE','/api/users/4',None,None),
 ('archive_store','DELETE','/api/stores/3',None,None),
 ('archive_part','DELETE','/api/parts/2',None,None),
 ('archive_restore_user','POST','/api/users/4/restore',None,"UPDATE organization_memberships SET is_active=FALSE WHERE user_id=4"),
 ('archive_restore_store','POST','/api/stores/3/restore',None,"UPDATE stores SET archived_at='2000-01-01T00:00:00.000000Z' WHERE id=3"),
 ('archive_restore_part','POST','/api/parts/2/restore',None,"UPDATE parts SET archived_at='2000-01-01T00:00:00.000000Z' WHERE id=2"),
]


def prepare(session_api,preparation,body):
    client,api,_=session_api
    if preparation=='count':
        sheet=client.get('/api/inventory/count-sheet/1');assert sheet.status_code==200,sheet.text
        preview=client.post('/api/inventory/count-preview',json={'sheet_token':sheet.json()['sheet_token'],'rows':[{'inventory_id':1,'counted_quantity':8,'reason':'Physical count'}]})
        assert preview.status_code==200,preview.text
        return {'preview_token':preview.json()['preview_token'],'confirmed':True}
    if preparation:
        with api.legacy_db as conn:
            if preparation=='transfer':
                conn.execute("INSERT INTO movements(id,from_store_id,to_store_id,part_id,quantity,movement_type,created_by) VALUES(8,1,2,1,2,'transfer',1)")
                conn.execute("INSERT INTO stock_transfers(movement_id,status,source_min_threshold) VALUES(8,'in_transit',0)")
            else:conn.execute(preparation)
    return body


@pytest.mark.parametrize('case',STOCK_CASES,ids=lambda c:c[0])
@pytest.mark.parametrize('revoked',[False,True],ids=['valid','revoked'])
def test_stock_write_routes(session_api,case,revoked):
    name,method,path,body,preparation=case
    body=prepare(session_api,preparation,body)
    client,db,control=session_api
    if revoked:control['damage']='UPDATE sessions SET is_active=FALSE WHERE id=1'
    response=client.request(method,path,json=body)
    if revoked:
        assert response.status_code==401,response.text
        assert database_state(db)==control['before']
    else:assert response.status_code==200,response.text


def test_waiting_stock_write_rechecks_store_owner(session_api):
    client,path,control=session_api;client.cookies.set('session_token','engineer-token')
    client.headers['X-CSRF-Token']=main.generate_csrf_token('engineer-token')
    control['damage']='UPDATE stores SET assigned_user_id=4 WHERE id=2'
    response=client.post('/api/inventory/add',json={'store_id':2,'part_id':1,'quantity':2})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_waiting_archive_rechecks_privileged_target(session_api):
    client,path,control=session_api
    control['damage']="UPDATE organization_memberships SET company_role='owner' WHERE user_id=4"
    response=client.delete('/api/users/4')
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_stock_cookie_missing_even_with_actor_override(session_api):
    client,path,_=session_api;client.cookies.clear()
    main.app.dependency_overrides[main.get_current_user]=lambda:1
    before=database_state(path)
    response=client.post('/api/inventory/add',json={'store_id':1,'part_id':1,'quantity':2})
    assert response.status_code==401,response.text
    assert database_state(path)==before

CATALOG_CASES=[
 ('catalog_update_user','PUT','/api/users/4',{'name':'Renamed'},None),
 ('catalog_create_store','POST','/api/stores',{'name':'New store','type':'office'},None),
 ('catalog_update_store','PUT','/api/stores/3',{'name':'Renamed store'},None),
 ('catalog_import_stores','POST','/api/stores/bulk-import',{'csv':'name,type,location,assigned_user_id\nNew CSV,office,Office,\n'},None),
 ('store_type_create','POST','/api/store-types',{'type_code':'new_type','type_name':'New'},None),
 ('store_type_update','PUT','/api/store-types/{unused}',{'type_name':'Renamed type'},None),
 ('store_type_delete','DELETE','/api/store-types/{unused}',None,None),
 ('catalog_create_part','POST','/api/parts',{'part_number':'NEW','description':'New part','category':'test','unit_cost':0},None),
 ('catalog_update_part','PUT','/api/parts/2',{'description':'Updated empty part'},None),
 ('catalog_import_parts','POST','/api/parts/bulk-import',{'csv':'part_number,description,category,unit_cost\nCSV,CSV Part,test,1\n'},None),
 ('equipment_create','POST','/api/equipment',{'equipment_name':'New meter','make':'Maker','model':'M2','serial_number':'NEW'},None),
 ('equipment_update','PUT','/api/equipment/1',{'notes':'Updated'},None),
 ('equipment_transfer','POST','/api/equipment/1/transfer',{'to_user_id':4,'notes':'Moved'},None),
 ('equipment_calibrate','POST','/api/equipment/1/calibrate',{'calibration_cert_number':'CERT','calibration_authority':'Lab','calibration_date':'2026-01-01','next_calibration_date':'2027-01-01'},None),
 ('equipment_delete','DELETE','/api/equipment/1',None,None),
 ('equipment_setting','PUT','/api/settings/calibration-reminder-days?days=20',None,None),
]


def send_case(client,method,path,body,api=None):
    if api is not None and '{unused}' in path:path=path.replace('{unused}',str(unused_store_type(api)))
    if isinstance(body,dict) and 'csv' in body:return client.request(method,path,files={'file':('input.csv',body['csv'].encode(),'text/csv')})
    return client.request(method,path,json=body)


@pytest.mark.parametrize('case',CATALOG_CASES,ids=lambda c:c[0])
@pytest.mark.parametrize('revoked',[False,True],ids=['valid','revoked'])
def test_catalog_and_equipment_write_routes(session_api,case,revoked):
    _,method,path,body,preparation=case;body=prepare(session_api,preparation,body)
    client,db,control=session_api
    if revoked:control['damage']='UPDATE sessions SET is_active=FALSE WHERE id=1'
    response=send_case(client,method,path,body,db)
    if revoked:
        assert response.status_code==401,response.text
        assert database_state(db)==control['before']
    else:assert response.status_code==200,response.text


def test_catalog_role_changed_before_write(session_api):
    client,path,control=session_api;control['damage']="UPDATE organization_memberships SET company_role='engineer' WHERE user_id=1"
    response=client.post('/api/parts',json={'part_number':'NEW','description':'New','category':'test','unit_cost':1})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_equipment_owner_changed_before_write(session_api):
    client,path,control=session_api;client.cookies.set('session_token','engineer-token')
    client.headers['X-CSRF-Token']=main.generate_csrf_token('engineer-token')
    control['damage']='UPDATE equipment SET assigned_user_id=4 WHERE id=1'
    response=client.post('/api/equipment/1/calibrate',json={'calibration_cert_number':'CERT','calibration_authority':'Lab','calibration_date':'2026-01-01','next_calibration_date':'2027-01-01'})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_mutation_audit_rolls_back_with_record(session_api):
    client,path,_=session_api
    fail_inserts(path.db,'activity_logs','audit unavailable')
    before=database_state(path)
    with pytest.raises(psycopg.errors.RaiseException,match='audit unavailable'):
        client.post('/api/parts',json={'part_number':'NEW','description':'New','category':'test','unit_cost':1})
    assert database_state(path)==before

ADMIN_CASES=[
 ('business_timezone','PUT','/api/organisation/timezone',{'timezone':'Europe/London','expected_revision':1},None,1),
 ('profile_password','POST','/api/profile/change-password',{'current_password':'test-password','new_password':'new-password'},'password',1),
 ('session_revoke_others','POST','/api/auth/revoke-other-sessions',None,'extra_session',1),
 ('session_revoke_all','POST','/api/auth/sessions/revoke-all',None,'extra_session',1),
 ('session_revoke_one','DELETE','/api/auth/sessions/50',None,'extra_session',1),
 ('session_logout','POST','/api/auth/logout',None,None,1),
 ('admin_cleanup','DELETE','/api/logs/activity/cleanup?days=0',None,None,1),
]


def prepare_account(api,preparation):
    if preparation:
        with api.legacy_db as conn:
            if preparation=='password':conn.execute('UPDATE users SET password_hash=? WHERE id=1',(main.hash_password('test-password'),))
            elif preparation=='extra_session':conn.execute("INSERT INTO sessions(id,user_id,session_token_hash,expires_at) VALUES(50,1,?,'2099-01-01T00:00:00.000000Z')",(hash_session_credential('other-admin'),))


@pytest.mark.parametrize('case',ADMIN_CASES,ids=lambda c:c[0])
@pytest.mark.parametrize('revoked',[False,True],ids=['valid','revoked'])
def test_profile_session_and_admin_write_routes(session_api,case,revoked):
    _,method,url,body,preparation,actor=case;client,path,control=session_api
    prepare_account(path,preparation)
    if revoked:control['damage']=f'UPDATE sessions SET is_active=FALSE WHERE id={actor}'
    response=send_case(client,method,url,body)
    if revoked:
        assert response.status_code==401,response.text
        assert database_state(path)==control['before']
    else:assert response.status_code==200,response.text


def test_read_after_session_revocation_is_rejected_without_writes(session_api):
    # Postgres reads re-validate the session inside their transaction.
    client,path,control=session_api;control['damage']='UPDATE sessions SET is_active=FALSE WHERE id=1'
    response=client.get('/api/parts')
    assert response.status_code==401,response.text
    assert database_state(path)==control['before']


def test_saas_users_cannot_change_their_own_email(session_api):
    client,path,_=session_api
    before=database_state(path)
    response=client.put('/api/profile',json={'email':'updated@example.com'})
    assert response.status_code==403
    assert response.json()=={'detail':'Ask your company owner or administrator to change your email address.'}
    assert database_state(path)==before


def test_logout_has_one_atomic_audit(session_api):
    client,path,_=session_api
    assert client.post('/api/auth/logout').status_code==200
    with path.legacy_db as conn:
        # SaaS records sign-out in the platform audit trail, not company activity.
        assert conn.execute("SELECT COUNT(*) FROM platform_audit_events WHERE action='user_logout' AND actor_user_id=1").fetchone()[0]==1
        assert conn.execute('SELECT is_active FROM sessions WHERE id=1').fetchone()[0] is False


def test_public_authentication_remains_compatible(session_api):
    client,path,_=session_api;prepare_account(path,'password');client.cookies.clear();main.app.state.limiter.reset()
    client.headers.pop('X-CSRF-Token',None)
    csrf=client.get('/api/csrf-token').json()['csrf_token']
    response=client.post('/api/auth/login',json={'email':'admin@example.test','password':'test-password'},headers={'X-CSRF-Token':csrf})
    assert response.status_code==200,response.text
    assert 'session_token=' in response.headers['set-cookie']

def test_activity_details_do_not_store_session_token(session_api):
    client,path,_=session_api
    assert client.post('/api/parts',json={'part_number':'NEW','description':'New','category':'test','unit_cost':0}).status_code==200
    with path.legacy_db as conn:
        details=conn.execute("SELECT details FROM activity_logs WHERE action='create_part'").fetchone()[0]
        assert 'admin-token' not in details and 'session_token' not in details


def _route_template(path):
    import re
    path=path.split('?')[0]
    path=path.replace('/store-types/{unused}','/store-types/{type_id}')
    if path.startswith('/api/superadmin/security-config/'):
        return '/api/superadmin/security-config/{key}'
    if path.startswith('/api/superadmin/users/'):
        return re.sub(r'/users/\d+', '/users/{target_id}', path)
    replacements={'users':'target_user_id','stores':'store_id','parts':'part_id','equipment':'equipment_id','store-types':'type_id','transfers':'transfer_id','sessions':'session_id'}
    for prefix,identifier in replacements.items():
        path=re.sub('/'+prefix+r'/\d+', '/'+prefix+'/{'+identifier+'}', path)
    return path


def test_every_registered_mutation_has_a_behavioral_classification():
    from fastapi.routing import APIRoute
    protected={(case[1],_route_template(case[2])) for case in STOCK_CASES+CATALOG_CASES+ADMIN_CASES}
    protected.add(('POST','/api/superadmin/database/restore'))
    # CSRF-protected writes this module does not exercise on Postgres: the legacy
    # SQLite-only superadmin console (removed with SQLite) and the self-service
    # email route, which SaaS refuses (test_saas_users_cannot_change_their_own_email).
    protected.update({
        ('PUT', '/api/profile'),
        ('POST', '/api/superadmin/users/{target_id}/reset-password'),
        ('POST', '/api/superadmin/unlock-account'),
        ('POST', '/api/superadmin/unlock-accounts/bulk'),
        ('POST', '/api/superadmin/sessions/force-logout'),
        ('POST', '/api/superadmin/sessions/force-logout-all'),
        ('PUT', '/api/superadmin/security-config/{key}'),
        ('PUT', '/api/superadmin/users/{target_id}/role'),
        ('DELETE', '/api/superadmin/database/logs/purge'),
        ('POST', '/api/superadmin/announcement'),
        ('POST', '/api/superadmin/announcement/dismiss'),
        ('DELETE', '/api/superadmin/announcement'),
        ('POST', '/api/users'),
    })
    protected.update({('PUT', '/api/organization/settings'),
                      ('PUT', '/api/organization/mobile-session-policy'),
                      ('POST', '/api/organization/owner-transfer'),
                      ('POST', '/api/equipment/{equipment_id}/restore')})
    protected.update({
        ('POST', '/api/users/invitations'),
        ('POST', '/api/users/invitations/{invitation_id}/resend'),
        ('DELETE', '/api/users/invitations/{invitation_id}'),
        ('POST', '/api/invitations/accept'),
        ('POST', '/api/platform/organizations'),
        ('POST', '/api/platform/support-sessions'),
        ('DELETE', '/api/platform/support-sessions/{support_session_id}'),
        ('PATCH', '/api/platform/support-inbox/{conversation_id}/state'),
        ('POST', '/api/platform/support-inbox/{conversation_id}/reply'),
        ('POST', '/api/platform/support-sessions/{support_session_id}/accounts/{user_id}/unlock'),
        ('POST', '/api/platform/support-sessions/{support_session_id}/locked-accounts/unlock'),
        ('POST', '/api/platform/support-sessions/{support_session_id}/accounts/{user_id}/sign-out'),
        ('POST', '/api/platform/support-sessions/{support_session_id}/accounts/{user_id}/password-reset'),
        ('DELETE', '/api/platform/database/logs'),
        ('PUT', '/api/platform/organizations/{organization_id}/members/{user_id}/role'),
        ('POST', '/api/platform/admins'),
        ('PUT', '/api/platform/admins/{target_user_id}'),
        ('DELETE', '/api/platform/admins/{target_user_id}'),
        ('PUT', '/api/platform/organizations/{organization_id}/status'),
        ('POST', '/api/platform/announcement'),
        ('DELETE', '/api/platform/announcement'),
        ('PUT', '/api/platform/security-config/{key}'),
        ('POST', '/api/profile/mobile-pairings'),
        ('POST', '/api/profile/mobile-pairings/{request_id}/approve'),
        ('POST', '/api/profile/mobile-pairings/{request_id}/cancel'),
        ('DELETE', '/api/profile/mobile-devices/{request_id}'),
        ('POST', '/api/profile/email-change-requests'),
        ('DELETE', '/api/profile/email-change-request'),
        ('POST', '/api/users/{target_user_id}/email-change-requests'),
        ('DELETE', '/api/users/{target_user_id}/email-change-request'),
        ('POST', '/api/auth/email-change/confirm'),
        ('POST', '/api/v1/auth/email-change/confirm'),
        ('POST', '/api/v1/auth/mobile-pairing/claim'),
        ('POST', '/api/v1/auth/mobile-pairing/complete'),
        ('POST', '/api/v1/inventory/adjustments'),
        ('POST', '/api/users/{target_user_id}/remove'),
    })
    exempt={('POST',p) for p in ['/api/auth/login','/api/auth/native/login','/api/v1/auth/native/login','/api/auth/native/refresh','/api/v1/auth/native/refresh','/api/forgot-password','/api/reset-password','/api/inventory/count-preview','/api/superadmin/database/query','/api/superadmin/database/vacuum']}
    bearer_only={('POST', '/api/v1/auth/logout')}
    bearer_only.update(('POST', '/api/v1/inventory/' + path) for path in (
        'add', 'consume', 'transfer', 'transfers/{transfer_id}/receive', 'transfers/{transfer_id}/return'))
    registered={(method,route.path) for route in main.app.routes if isinstance(route,APIRoute) for method in route.methods if method in {'POST','PUT','DELETE','PATCH'}}
    assert len(protected)==92
    assert registered==protected|exempt|bearer_only


