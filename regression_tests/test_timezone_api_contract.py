import sqlite3
import pytest
from regression_tests.test_stock_safety import api


def test_profile_and_session_instants_are_explicit_utc(api):
    client, db, _=api
    assert client.get('/api/profile').json()['created_at'].endswith('Z')
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE sessions SET expires_at='2099-01-01T00:00:00' WHERE user_id=1")
        before=conn.execute('SELECT created_at FROM users WHERE id=1').fetchone()[0]
    rows=client.get('/api/auth/sessions').json()
    assert rows[0]['created_at'].endswith('Z') and rows[0]['last_activity'].endswith('Z')
    with sqlite3.connect(db) as conn:assert conn.execute('SELECT created_at FROM users WHERE id=1').fetchone()[0]==before


def test_reports_use_business_zone_and_personal_zone_does_not_change_rows(api):
    client,db,actor=api
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(901,'Source','central')")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(901,'P','Part')")
        c.execute("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,created_by,created_at) VALUES(901,901,2,'consume',1,'2026-03-09T03:59:59.999999')")
        c.execute("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,created_by,created_at) VALUES(901,901,3,'consume',1,'2026-03-09T04:00:00')")
        c.execute("UPDATE organisation_settings SET business_timezone='America/New_York'")
    query='/api/reports/consumption?start_date=2026-03-08&end_date=2026-03-08'
    first=client.get(query).json()
    assert first['timezone']=='America/New_York'
    assert first['start_utc']=='2026-03-08T05:00:00.000000Z'
    assert first['end_utc']=='2026-03-09T04:00:00.000000Z'
    assert first['totals']['quantity']==2
    assert first['rows'][0]['created_at'].endswith('Z')
    assert first['rows'][0]['recorded_at'].endswith('Z')
    client.put('/api/profile',json={'display_timezone':'Asia/Kathmandu'})
    second=client.get(query).json()
    assert second['rows']==first['rows'] and second['totals']==first['totals']
    csv=client.get('/api/reports/consumption.csv?start_date=2026-03-08&end_date=2026-03-08')
    assert 'America/New_York' in csv.text and '-04:00' in csv.text


def test_history_includes_fractional_last_second_in_business_day(api):
    client,db,_=api
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO activity_logs(user_id,username,action,created_at) VALUES(1,'User 1','boundary','2026-10-12 20:59:59.999999')")
        c.execute("INSERT INTO activity_logs(user_id,username,action,created_at) VALUES(1,'User 1','boundary','2026-10-12 21:00:00')")
    response=client.get('/api/logs/activity?start_date=2026-10-12&end_date=2026-10-12&action=boundary')
    assert response.status_code==200
    assert len(response.json())==1
    assert response.json()[0]['created_at']=='2026-10-12T20:59:59.999999Z'


def test_calendar_dates_are_not_serialised_as_instants(api):
    client,db,_=api
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO equipment(equipment_name,make,model,serial_number,calibration_date,next_calibration_date,assigned_user_id) VALUES('Meter','M','M','TZ-1','2026-10-12','2027-10-12',1)")
    row=client.get('/api/equipment').json()[0]
    assert row['calibration_date']=='2026-10-12'
    assert row['next_calibration_date']=='2027-10-12'

@pytest.mark.parametrize('offset',['2026-10-12T13:00:00+03:00','2026-10-12T10:00:00'])
def test_lockout_reads_are_offset_equivalent(api, monkeypatch, offset):
    from datetime import datetime, timezone
    import backend.routes.auth as auth
    client,db,_=api
    monkeypatch.setattr(auth,'utc_now',lambda:datetime(2026,10,12,9,59,tzinfo=timezone.utc),raising=False)
    with sqlite3.connect(db) as c:
        c.execute('UPDATE users SET account_locked_until=? WHERE id=1',(offset,))
    response=client.post('/api/auth/login',json={'email':'user1@example.com','password':'wrong'})
    assert response.status_code==423


def test_wire_contract_is_strict_and_does_not_touch_dates_or_details():
    from fastapi import HTTPException
    from backend.temporal_contract import wire_instants
    source={'created_at':'2026-10-12 10:00:00.123456','completed_at':None,
            'calibration_date':'2026-10-12','details':{'created_at':'opaque'},
            'last_login':'2026-10-12T13:00:00+03:00'}
    assert wire_instants(source)=={**source,'created_at':'2026-10-12T10:00:00.123456Z','last_login':'2026-10-12T10:00:00.000000Z'}
    with pytest.raises(HTTPException) as error:wire_instants({'created_at':'SECRET'})
    assert error.value.status_code==500 and 'SECRET' not in error.value.detail


def test_all_history_metadata_has_no_invented_bounds(api):
    response=api[0].get('/api/reports/consumption').json()
    assert response['timezone']=='Africa/Nairobi'
    assert response['timezone_revision']==1
    for key in ['start_date','end_date','start_utc','end_utc']:assert response[key] is None


def test_equipment_due_day_uses_business_today(api,monkeypatch):
    from datetime import datetime,timezone
    import backend.routes.equipment as equipment
    client,db,_=api
    monkeypatch.setattr(equipment,'utc_now',lambda:datetime(2030,10,11,22,0,tzinfo=timezone.utc),raising=False)
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO equipment(equipment_name,make,model,serial_number,next_calibration_date,assigned_user_id) VALUES('Meter','M','M','TZ-DUE','2030-10-12',1)")
    row=client.get('/api/equipment').json()[0]
    assert row['days_until_calibration']==0
    result=client.get('/api/equipment/statistics').json()
    assert result['overdue']==0 and result['due_soon']==1


def test_log_formatter_is_explicit_utc():
    import logging
    from backend.logging_config import UTCFormatter
    record=logging.LogRecord('app',logging.INFO,'',1,'test',(),None)
    record.created=0;record.msecs=0
    assert UTCFormatter('%(asctime)s %(message)s').format(record)=='1970-01-01T00:00:00Z test'


def test_manifest_instant_fields_are_normalised_and_calendar_fields_untouched():
    from backend.temporal_manifest import TEMPORAL_FIELDS
    from backend.temporal_contract import wire_instants
    for field in TEMPORAL_FIELDS:
        if field.kind=='instant' and field.naive_policy=='utc':
            key=field.json_key or field.column
            assert wire_instants({key:'2026-10-12T13:00:00+03:00'})[key]=='2026-10-12T10:00:00.000000Z'
        elif field.kind=='date':
            assert wire_instants({field.column:'2026-10-12'})[field.column]=='2026-10-12'


def test_csv_rejects_timezone_revision_changed_since_report(api):
    client,db,_=api
    with sqlite3.connect(db) as c:c.execute('UPDATE organisation_settings SET revision=revision+1')
    response=client.get('/api/reports/consumption.csv?expected_timezone_revision=1')
    assert response.status_code==409


def test_session_ordering_uses_instants_not_offset_strings(api):
    client,db,_=api
    with sqlite3.connect(db) as c:
        c.execute("UPDATE sessions SET last_activity='2026-10-11 23:00:00' WHERE user_id=1")
        c.execute("INSERT INTO sessions(user_id,session_token,expires_at,last_activity) VALUES(1,'older-offset','2099-01-01T00:00:00','2026-10-12T00:00:00+03:00')")
    rows=client.get('/api/auth/sessions').json()
    assert rows[0]['last_activity']=='2026-10-11T23:00:00.000000Z'


def test_report_keeps_one_policy_snapshot_during_a_setting_change(api,monkeypatch):
    import backend.routes.reports as reports
    client,db,_=api
    with sqlite3.connect(db) as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.execute("INSERT INTO stores(id,name,type) VALUES(902,'Source','central')")
        c.execute("INSERT INTO parts(id,part_number,description) VALUES(902,'TZ-SNAPSHOT','Part')")
        c.execute("INSERT INTO movements(from_store_id,part_id,quantity,movement_type,created_by,created_at) VALUES(902,902,2,'consume',1,'2026-10-11T22:00:00')")
    original=reports.resolve_business_context
    calls=[]
    def change_after_resolution(conn,**kwargs):
        context=original(conn,**kwargs);calls.append(context)
        if len(calls)==1:
            with sqlite3.connect(db) as other:other.execute("UPDATE organisation_settings SET business_timezone='UTC',revision=2")
        return context
    monkeypatch.setattr(reports,'resolve_business_context',change_after_resolution)
    query='/api/reports/consumption?start_date=2026-10-12&end_date=2026-10-12'
    first=client.get(query).json()
    assert len(calls)==1 and first['timezone']=='Africa/Nairobi' and first['timezone_revision']==1
    assert first['totals']['quantity']==2
    second=client.get(query).json()
    assert len(calls)==2 and second['timezone']=='UTC' and second['timezone_revision']==2
    assert second['totals']['quantity']==0


def test_range_bounds_ignore_unrequested_interior_midnights():
    from backend.services.timezone_policy import BusinessTimeContext
    from backend.temporal_contract import date_metadata
    context=BusinessTimeContext(1,'Pacific/Apia',1)
    paired=date_metadata(context,'2011-12-29','2011-12-31')
    assert paired['start_utc']=='2011-12-29T10:00:00.000000Z'
    assert paired['end_utc']=='2011-12-31T10:00:00.000000Z'
    assert date_metadata(context,'2011-12-29')['start_utc']==paired['start_utc']
    assert date_metadata(context,None,'2011-12-30')['end_utc']=='2011-12-30T10:00:00.000000Z'


def test_history_lists_carry_snapshot_metadata_without_changing_json_shape(api):
    import json
    client,db,_=api
    with sqlite3.connect(db) as c:c.execute("UPDATE organisation_settings SET business_timezone='America/New_York',revision=2")
    for endpoint in ['/api/movements','/api/logs/activity']:
        response=client.get(endpoint+'?start_date=2026-03-08&end_date=2026-03-08')
        assert response.status_code==200 and isinstance(response.json(),list)
        context=json.loads(response.headers['X-Report-Time-Context'])
        assert context['timezone']=='America/New_York' and context['timezone_revision']==2
        assert context['start_utc']=='2026-03-08T05:00:00.000000Z'
        assert context['end_utc']=='2026-03-09T04:00:00.000000Z'
    assert client.get('/api/logs/activity/stats').json()['timezone']=='America/New_York'
