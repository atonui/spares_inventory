"""Actual HTTP mutations must reject credentials revoked after initial auth."""
import sqlite3
from contextlib import closing
import pytest
from fastapi import Request
from fastapi.testclient import TestClient
import main
from backend.database import connect_database
from regression_tests.session_fixtures import session_database


def database_state(path):
    with closing(connect_database(path)) as conn:
        result={}
        tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for table in tables:
            columns=[r[1] for r in conn.execute(f'PRAGMA table_info("{table}")') if not (table=='sessions' and r[1]=='last_activity')]
            result[table]=[tuple(r) for r in conn.execute('SELECT '+','.join('"'+c+'"' for c in columns)+f' FROM "{table}" ORDER BY rowid')]
        return result


@pytest.fixture
def session_api(tmp_path,monkeypatch):
    path=session_database(tmp_path/'http.db');monkeypatch.setattr(main,'DATABASE',str(path))
    with closing(connect_database(path)) as conn,conn:
        conn.execute("INSERT INTO users(id,email,name,password_hash,role) VALUES(4,'manager@example.test','Manager','unused','manager')")
        conn.execute("INSERT INTO sessions(id,user_id,session_token,expires_at) VALUES(4,4,'manager-token','2099-01-01')")
        conn.execute("INSERT INTO stores(id,name,type,assigned_user_id) VALUES(2,'Car','engineer',3),(3,'Empty','central',NULL)")
        conn.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(2,'EMPTY','Empty part','test',0)")
        conn.execute("INSERT INTO store_types(type_code,type_name) VALUES('unused','Unused')")
        conn.execute("INSERT INTO equipment(id,equipment_name,make,model,serial_number,assigned_user_id) VALUES(1,'Meter','Maker','M1','SERIAL',3)")
    control={'damage':None,'before':None}
    async def initial_auth(request:Request):
        uid=await main.get_current_user(request.cookies.get('session_token'))
        if control['damage']:
            with closing(connect_database(path)) as conn,conn:
                conn.execute(control['damage'])
            control['before']=database_state(path)
        return uid
    main.app.dependency_overrides[main.get_current_user]=initial_auth
    main.app.dependency_overrides[main.verify_csrf]=lambda:True
    try:
        with TestClient(main.app) as client:
            client.cookies.set('session_token','admin-token')
            yield client,path,control
    finally:main.app.dependency_overrides.clear()


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
 ('archive_restore_user','POST','/api/users/4/restore',None,"UPDATE users SET archived_at='2000-01-01' WHERE id=4"),
 ('archive_restore_store','POST','/api/stores/3/restore',None,"UPDATE stores SET archived_at='2000-01-01' WHERE id=3"),
 ('archive_restore_part','POST','/api/parts/2/restore',None,"UPDATE parts SET archived_at='2000-01-01' WHERE id=2"),
]


def prepare(session_api,preparation,body):
    client,path,_=session_api
    if preparation=='count':
        sheet=client.get('/api/inventory/count-sheet/1');assert sheet.status_code==200,sheet.text
        preview=client.post('/api/inventory/count-preview',json={'sheet_token':sheet.json()['sheet_token'],'rows':[{'inventory_id':1,'counted_quantity':8,'reason':'Physical count'}]})
        assert preview.status_code==200,preview.text
        return {'preview_token':preview.json()['preview_token'],'confirmed':True}
    if preparation:
        with closing(connect_database(path)) as conn,conn:
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
    if revoked:control['damage']='UPDATE sessions SET is_active=0 WHERE id=1'
    response=client.request(method,path,json=body)
    if revoked:
        assert response.status_code==401,response.text
        assert database_state(db)==control['before']
    else:assert response.status_code==200,response.text


def test_waiting_stock_write_rechecks_store_owner(session_api):
    client,path,control=session_api;client.cookies.set('session_token','engineer-token')
    control['damage']='UPDATE stores SET assigned_user_id=4 WHERE id=2'
    response=client.post('/api/inventory/add',json={'store_id':2,'part_id':1,'quantity':2})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_waiting_archive_rechecks_privileged_target(session_api):
    client,path,control=session_api
    control['damage']="UPDATE users SET role='superadmin' WHERE id=4"
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
 ('catalog_create_user','POST','/api/users',{'email':'new@example.test','name':'New','password':'test-password','role':'engineer'},None),
 ('catalog_update_user','PUT','/api/users/4',{'name':'Renamed'},None),
 ('catalog_create_store','POST','/api/stores',{'name':'New store','type':'office'},None),
 ('catalog_update_store','PUT','/api/stores/3',{'name':'Renamed store'},None),
 ('catalog_import_stores','POST','/api/stores/bulk-import',{'csv':'name,type,location,assigned_user_id\nNew CSV,office,Office,\n'},None),
 ('store_type_create','POST','/api/store-types',{'type_code':'new_type','type_name':'New'},None),
 ('store_type_update','PUT','/api/store-types/7',{'type_name':'Renamed type'},None),
 ('store_type_delete','DELETE','/api/store-types/7',None,None),
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


def send_case(client,method,path,body):
    if isinstance(body,dict) and 'csv' in body:return client.request(method,path,files={'file':('input.csv',body['csv'].encode(),'text/csv')})
    return client.request(method,path,json=body)


@pytest.mark.parametrize('case',CATALOG_CASES,ids=lambda c:c[0])
@pytest.mark.parametrize('revoked',[False,True],ids=['valid','revoked'])
def test_catalog_and_equipment_write_routes(session_api,case,revoked):
    _,method,path,body,preparation=case;body=prepare(session_api,preparation,body)
    client,db,control=session_api
    if revoked:control['damage']='UPDATE sessions SET is_active=0 WHERE id=1'
    response=send_case(client,method,path,body)
    if revoked:
        assert response.status_code==401,response.text
        assert database_state(db)==control['before']
    else:assert response.status_code==200,response.text


def test_catalog_role_changed_before_write(session_api):
    client,path,control=session_api;control['damage']="UPDATE users SET role='engineer' WHERE id=1"
    response=client.post('/api/parts',json={'part_number':'NEW','description':'New','category':'test','unit_cost':1})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_equipment_owner_changed_before_write(session_api):
    client,path,control=session_api;client.cookies.set('session_token','engineer-token')
    control['damage']='UPDATE equipment SET assigned_user_id=4 WHERE id=1'
    response=client.post('/api/equipment/1/calibrate',json={'calibration_cert_number':'CERT','calibration_authority':'Lab','calibration_date':'2026-01-01','next_calibration_date':'2027-01-01'})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_mutation_audit_rolls_back_with_record(session_api):
    client,path,_=session_api
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before=database_state(path)
    with pytest.raises(sqlite3.IntegrityError,match='audit unavailable'):
        client.post('/api/parts',json={'part_number':'NEW','description':'New','category':'test','unit_cost':1})
    assert database_state(path)==before

ADMIN_CASES=[
 ('profile_update','PUT','/api/profile',{'email':'updated@example.com'},None,1),
 ('profile_password','POST','/api/profile/change-password',{'current_password':'test-password','new_password':'new-password'},'password',1),
 ('session_revoke_others','POST','/api/auth/revoke-other-sessions',None,'extra_session',1),
 ('session_revoke_all','POST','/api/auth/sessions/revoke-all',None,'extra_session',1),
 ('session_revoke_one','DELETE','/api/auth/sessions/5',None,'extra_session',1),
 ('session_logout','POST','/api/auth/logout',None,None,1),
 ('admin_cleanup','DELETE','/api/logs/activity/cleanup?days=0',None,None,1),
 ('admin_password','POST','/api/superadmin/users/3/reset-password',{'user_id':3,'new_password':'new-password'},None,2),
 ('admin_unlock','POST','/api/superadmin/unlock-account',{'user_id':3},None,2),
 ('admin_unlock_bulk','POST','/api/superadmin/unlock-accounts/bulk',{'user_ids':[3,4]},None,2),
 ('admin_force_logout','POST','/api/superadmin/sessions/force-logout',{'user_id':3},None,2),
 ('admin_force_logout_all','POST','/api/superadmin/sessions/force-logout-all',None,None,2),
 ('admin_security','PUT','/api/superadmin/security-config/max_login_attempts',{'value':'6'},None,2),
 ('admin_role','PUT','/api/superadmin/users/3/role',{'role':'manager'},None,2),
 ('admin_purge','DELETE','/api/superadmin/database/logs/purge?days=0',None,None,2),
 ('admin_announcement_set','POST','/api/superadmin/announcement',{'message':'Test announcement'},None,2),
 ('admin_announcement_clear','DELETE','/api/superadmin/announcement',None,None,2),
]


def prepare_account(path,preparation):
    if preparation:
        with closing(connect_database(path)) as conn,conn:
            if preparation=='password':conn.execute('UPDATE users SET password_hash=? WHERE id=1',(main.hash_password('test-password'),))
            elif preparation=='extra_session':conn.execute("INSERT INTO sessions(id,user_id,session_token,expires_at) VALUES(5,1,'other-admin','2099-01-01')")


@pytest.mark.parametrize('case',ADMIN_CASES,ids=lambda c:c[0])
@pytest.mark.parametrize('revoked',[False,True],ids=['valid','revoked'])
def test_profile_session_and_admin_write_routes(session_api,case,revoked):
    _,method,url,body,preparation,actor=case;client,path,control=session_api
    client.cookies.set('session_token','root-token' if actor==2 else 'admin-token')
    prepare_account(path,preparation)
    if revoked:control['damage']=f'UPDATE sessions SET is_active=0 WHERE id={actor}'
    response=send_case(client,method,url,body)
    if revoked:
        assert response.status_code==401,response.text
        assert database_state(path)==control['before']
    else:assert response.status_code==200,response.text


def test_admin_role_changed_before_write(session_api):
    client,path,control=session_api;client.cookies.set('session_token','root-token')
    control['damage']="UPDATE users SET role='engineer' WHERE id=2"
    response=client.post('/api/superadmin/announcement',json={'message':'Test'})
    assert response.status_code==403,response.text
    assert database_state(path)==control['before']


def test_read_audit_after_restore_does_not_write(session_api):
    client,path,control=session_api;control['damage']='UPDATE sessions SET is_active=0 WHERE id=1'
    response=client.get('/api/parts')
    assert response.status_code==200,response.text
    assert database_state(path)==control['before']


def test_logout_has_one_atomic_audit(session_api):
    client,path,_=session_api
    assert client.post('/api/auth/logout').status_code==200
    with closing(connect_database(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM activity_logs WHERE action='logout' AND status='success'").fetchone()[0]==1
        assert conn.execute('SELECT is_active FROM sessions WHERE id=1').fetchone()[0]==0


def test_admin_audit_failure_rolls_back_mutation(session_api):
    client,path,_=session_api;client.cookies.set('session_token','root-token')
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before=database_state(path)
    with pytest.raises(sqlite3.IntegrityError,match='audit unavailable'):
        client.post('/api/superadmin/unlock-account',json={'user_id':3})
    assert database_state(path)==before


def test_public_authentication_remains_compatible(session_api):
    client,path,_=session_api;prepare_account(path,'password');client.cookies.clear();main.app.state.limiter.reset()
    response=client.post('/api/auth/login',json={'email':'admin@example.test','password':'test-password'})
    assert response.status_code==200,response.text
    assert 'session_token=' in response.headers['set-cookie']

@pytest.mark.parametrize('method,url,body,action',[
    ('POST','/api/superadmin/database/query',{'sql':'SELECT id FROM users'},'db_query'),
    ('POST','/api/superadmin/database/vacuum',None,'db_vacuum'),
    ('GET','/api/superadmin/database/backup',None,'db_backup'),
])
@pytest.mark.parametrize('revoked',[False,True])
def test_maintenance_audit_uses_current_session(session_api,method,url,body,action,revoked):
    client,path,control=session_api;client.cookies.set('session_token','root-token')
    if revoked:control['damage']='UPDATE sessions SET is_active=0 WHERE id=2'
    response=client.request(method,url,json=body)
    assert response.status_code==200
    if revoked:assert database_state(path)==control['before']
    else:
        with closing(connect_database(path)) as conn:
            assert conn.execute('SELECT COUNT(*) FROM activity_logs WHERE action=?',(action,)).fetchone()[0]==1


def test_activity_details_do_not_store_session_token(session_api):
    client,path,_=session_api
    assert client.post('/api/parts',json={'part_number':'NEW','description':'New','category':'test','unit_cost':0}).status_code==200
    with closing(connect_database(path)) as conn:
        details=conn.execute("SELECT details FROM activity_logs WHERE action='create_part'").fetchone()[0]
        assert 'admin-token' not in details and 'session_token' not in details


def _route_template(path):
    import re
    path=path.split('?')[0]
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
    exempt={('POST',p) for p in ['/api/auth/login','/api/forgot-password','/api/reset-password','/api/inventory/count-preview','/api/superadmin/database/query','/api/superadmin/database/vacuum']}
    registered={(method,route.path) for route in main.app.routes if isinstance(route,APIRoute) for method in route.methods if method in {'POST','PUT','DELETE','PATCH'}}
    assert len(protected)==50
    assert registered==protected|exempt


def test_initial_auth_holds_lock_through_activity_update(session_api,monkeypatch):
    import asyncio
    _,path,_=session_api;original=main.get_db_connection;attempts=[]
    def trace(sql):
        if ' '.join(sql.split()).startswith('UPDATE sessions') and 'last_activity' in sql:
            with closing(connect_database(path,timeout=.02)) as competitor:
                try:
                    competitor.execute('UPDATE inventory SET quantity=999 WHERE id=1');competitor.commit()
                except sqlite3.OperationalError:attempts.append('blocked')
                else:attempts.append('committed')
    def connection():
        conn=original();conn.set_trace_callback(trace);return conn
    monkeypatch.setattr(main,'get_db_connection',connection)
    assert asyncio.run(main.get_current_user('admin-token'))==1
    assert attempts==['blocked']
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0]==10
