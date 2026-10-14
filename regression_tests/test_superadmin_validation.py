import pytest
from regression_tests.test_superadmin_router import super_api
from regression_tests.test_session_write_routes import session_api, database_state

LIMITS={'max_login_attempts':100,'lockout_duration_minutes':1440,'session_duration_hours':720,'remember_me_duration_days':365,'calibration_reminder_days':365}

@pytest.mark.parametrize('key,maximum',LIMITS.items())
def test_configuration_bounds_and_persistence(super_api,key,maximum):
    client,path,_=super_api
    for value in ['0','-1','1.5','bad',str(maximum+1)]:
        before=database_state(path)
        response=client.put('/api/superadmin/security-config/'+key,json={'value':value})
        assert response.status_code==400,response.text
        assert database_state(path)==before
    for value in ['1',str(maximum)]:
        assert client.put('/api/superadmin/security-config/'+key,json={'value':value}).status_code==200
        assert client.get('/api/superadmin/security-config').json()[key]['setting_value']==value

@pytest.mark.parametrize('message,level',[('','info'),('   ','warning'),('x'*2001,'info'),('notice','unknown')])
def test_invalid_announcement_preserves_existing_notice(super_api,message,level):
    client,path,_=super_api
    assert client.post('/api/superadmin/announcement',json={'message':'Existing','level':'info'}).status_code==200
    before=database_state(path)
    assert client.post('/api/superadmin/announcement',json={'message':message,'level':level}).status_code==400
    assert database_state(path)==before

@pytest.mark.parametrize('level',['info','warning','danger'])
def test_announcement_roundtrip_and_clear(super_api,level):
    client,_,_=super_api
    assert client.post('/api/superadmin/announcement',json={'message':'  <b>Notice</b>  ','level':level}).status_code==200
    client.cookies.clear()
    notice=client.get('/api/superadmin/announcement').json()['announcement']
    assert notice['message']=='<b>Notice</b>' and notice['level']==level
    client.cookies.set('session_token','root-token')
    assert client.delete('/api/superadmin/announcement').status_code==200
    assert client.get('/api/superadmin/announcement').json()=={'announcement':None}
