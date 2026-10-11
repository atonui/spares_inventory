"""Audit history filters operate on full history and Nairobi calendar days."""
import sqlite3
import pytest
from regression_tests.test_superadmin_router import super_api
from regression_tests.test_session_write_routes import session_api


def seed(path):
    with sqlite3.connect(path) as conn:
        conn.execute('DELETE FROM activity_logs')
        for stamp, action, status, actor in [
            ('2026-10-04 20:59:59', 'DB_BACKUP', 'success', 'superadmin'),
            ('2026-10-04 21:00:00', 'DB_BACKUP', 'success', 'superadmin'),
            ('2026-10-05T20:59:59+00:00', 'DB_QUERY', 'error', 'superadmin'),
            ('2026-10-05 21:00:00', 'DB_BACKUP', 'success', 'superadmin'),
            ('2026-10-05 12:00:00', 'DB_BACKUP', 'success', 'ordinary'),
        ]:
            conn.execute('INSERT INTO activity_logs(username,action,status,created_at) VALUES(?,?,?,?)', (actor,action,status,stamp))


def test_audit_nairobi_day_filters_and_full_totals(super_api):
    client,path,_=super_api
    seed(path)
    result=client.get('/api/superadmin/audit-log',params={'paginated':True,'start_date':'2026-10-05','end_date':'2026-10-05','limit':1}).json()
    assert result['total']==2
    assert len(result['rows'])==1
    assert result['rows'][0]['action']=='DB_QUERY'
    second=client.get('/api/superadmin/audit-log',params={'paginated':True,'start_date':'2026-10-05','end_date':'2026-10-05','limit':1,'offset':1}).json()
    assert second['rows'][0]['created_at']=='2026-10-04 21:00:00'
    assert second['total']==2


def test_audit_combined_filters_and_legacy_response(super_api):
    client,path,_=super_api
    seed(path)
    result=client.get('/api/superadmin/audit-log',params={'paginated':True,'action':'DB_QUERY','status':'error'}).json()
    assert result['total']==1
    assert result['actions']==['DB_BACKUP','DB_QUERY']
    assert len(client.get('/api/superadmin/audit-log').json())==4
    assert client.get('/api/superadmin/audit-log',params={'paginated':True,'action':"' OR 1=1--"}).json()['total']==0


@pytest.mark.parametrize('params',[{'limit':0},{'limit':201},{'offset':-1},{'status':'bad'},{'start_date':'2026-10-06','end_date':'2026-10-05'},{'end_date':'9999-12-31'}])
def test_audit_rejects_invalid_filters(super_api,params):
    assert super_api[0].get('/api/superadmin/audit-log',params=params).status_code==422


def test_audit_paginated_access_still_requires_superadmin(super_api):
    client,_,_=super_api
    client.cookies.set('session_token','manager-token')
    assert client.get('/api/superadmin/audit-log',params={'paginated':True}).status_code==403
