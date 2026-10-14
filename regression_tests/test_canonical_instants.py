import sqlite3
import pytest
from backend.migrations.runner import apply_migrations
from backend.migrations.validation import MigrationError
from regression_tests.migration_fixtures import legacy_connection, snapshot, schema_snapshot


def test_conversion_preserves_instants_stock_sequences_and_dates(tmp_path):
    c=legacy_connection(tmp_path/'old.db')
    c.execute("UPDATE users SET created_at='2026-01-02 03:04:05.123456', last_login='2026-01-02T06:04:05+03:00'")
    c.execute("INSERT INTO sessions(user_id,session_token,expires_at) VALUES(7,'fixture','2026-01-02T06:04:05.1+03:00')")
    c.execute("UPDATE sqlite_sequence SET seq=99 WHERE name='users'")
    c.commit()
    apply_migrations(c)
    assert tuple(c.execute('SELECT created_at,last_login FROM users').fetchone())==('2026-01-02T03:04:05.123456Z','2026-01-02T03:04:05.000000Z')
    assert c.execute('SELECT expires_at FROM sessions').fetchone()[0]=='2026-01-02T03:04:05.100000Z'
    assert c.execute('SELECT quantity FROM inventory').fetchone()[0]==19
    assert c.execute("SELECT seq FROM sqlite_sequence WHERE name='users'").fetchone()[0]==99
    assert not c.execute('PRAGMA foreign_key_check').fetchall()
    assert c.execute('PRAGMA foreign_keys').fetchone()[0]==1
    c.execute("INSERT INTO parts(part_number) VALUES('AFTER')")
    stamp=c.execute("SELECT created_at FROM parts WHERE part_number='AFTER'").fetchone()[0]
    from backend.temporal import parse_api_instant,serialize_instant
    assert stamp==serialize_instant(parse_api_instant(stamp))
    assert stamp.endswith('000Z')


@pytest.mark.parametrize('column,value',[('created_at','secret-invalid-value'),('session_expires','2026-01-02T03:04:05')])
def test_invalid_or_unapproved_instant_rolls_back_everything(tmp_path,column,value):
    c=legacy_connection(tmp_path/'bad.db')
    c.execute(f'UPDATE users SET {column}=?',(value,));c.commit()
    before=snapshot(c);schema=schema_snapshot(c)
    with pytest.raises(MigrationError) as error:apply_migrations(c)
    assert value not in str(error.value)
    assert snapshot(c)==before and schema_snapshot(c)==schema
    assert c.execute('PRAGMA foreign_keys').fetchone()[0]==1


def test_calendar_duration_and_announcement_payload_survive(tmp_path):
    import json
    c=legacy_connection(tmp_path/'old.db',current=True)
    c.execute("INSERT INTO equipment(equipment_name,make,model,serial_number,calibration_date,next_calibration_date) VALUES('Unit','Make','Model','SN','2026-01-02','2027-01-02')")
    payload={'message':'hello','set_at':'2026-01-02T06:04:05.12+03:00','other':{'keep':True}}
    c.execute('INSERT INTO system_settings(setting_key,setting_value) VALUES(?,?)',('system_announcement',json.dumps(payload)))
    c.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('session_duration_hours','48')")
    c.commit();apply_migrations(c)
    assert tuple(c.execute('SELECT calibration_date,next_calibration_date FROM equipment').fetchone())==('2026-01-02','2027-01-02')
    result=json.loads(c.execute("SELECT setting_value FROM system_settings WHERE setting_key='system_announcement'").fetchone()[0])
    assert result=={**payload,'set_at':'2026-01-02T03:04:05.120000Z'}
    assert c.execute("SELECT setting_value FROM system_settings WHERE setting_key='session_duration_hours'").fetchone()[0]=='48'


@pytest.mark.parametrize('payload',['invalid', '{}', '{"set_at":"secret-bad"}'])
def test_invalid_announcement_rolls_back_without_disclosing_payload(tmp_path,payload):
    c=legacy_connection(tmp_path/'bad.db',current=True)
    c.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('system_announcement',?)",(payload,));c.commit()
    before=snapshot(c);schema=schema_snapshot(c)
    with pytest.raises(MigrationError) as error:apply_migrations(c)
    assert payload not in str(error.value)
    assert snapshot(c)==before and schema_snapshot(c)==schema


def test_every_database_default_uses_canonical_clock(tmp_path):
    from backend.temporal import serialize_instant,parse_api_instant
    c=legacy_connection(tmp_path/'defaults.db',current=True)
    apply_migrations(c)
    defaults=[r[4] for (table,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall() for r in c.execute(f'PRAGMA table_info("{table}")') if r[4] and ('CURRENT_TIMESTAMP' in r[4] or 'strftime' in r[4])]
    assert len(defaults)==16
    for default in defaults:
        stamp=c.execute('SELECT '+default).fetchone()[0]
        assert stamp==serialize_instant(parse_api_instant(stamp))


def test_legacy_backup_restore_produces_canonical_instants(tmp_path):
    from database_restore import restore_database
    from backend.temporal import parse_api_instant,serialize_instant
    live=tmp_path/'live.db';upload=tmp_path/'upload.db'
    c=legacy_connection(live);apply_migrations(c);c.close()
    legacy_connection(upload).close()
    restore_database(upload,live,7)
    with sqlite3.connect(live) as c:
        for table,column in [('users','created_at'),('inventory','updated_at'),('movements','created_at'),('activity_logs','created_at'),('schema_migrations','applied_at')]:
            for (stamp,) in c.execute(f'SELECT {column} FROM {table}'):
                assert stamp==serialize_instant(parse_api_instant(stamp))

from regression_tests.test_auth_router import auth_api
from regression_tests.test_stock_safety import api
from regression_tests.test_session_write_routes import session_api
from regression_tests.test_superadmin_router import super_api


def canonical(value):
    from backend.temporal import serialize_instant,parse_api_instant
    assert value==serialize_instant(parse_api_instant(value))


def test_login_writes_canonical_expiry_and_last_login(auth_api):
    client,path,_=auth_api
    response=client.post('/api/auth/login',json={'email':'user1@example.com','password':'test-password'})
    assert response.status_code==200
    with sqlite3.connect(path) as c:
        canonical(c.execute('SELECT expires_at FROM sessions ORDER BY id DESC LIMIT 1').fetchone()[0])
        canonical(c.execute('SELECT last_login FROM users WHERE id=1').fetchone()[0])


def test_announcement_writes_canonical_json_and_update_clock(super_api):
    import json
    client,path,_=super_api
    for message in ('first','second'):
        existing=client.get('/api/superadmin/announcement/manage').json()['announcement']
        response=client.post('/api/superadmin/announcement',json={'message':message,'level':'info','expected_revision':existing['revision'] if existing else None})
        assert response.status_code==200,response.text
    with sqlite3.connect(path) as c:
        payload,updated=c.execute("SELECT setting_value,updated_at FROM system_settings WHERE setting_key='system_announcement'").fetchone()
        canonical(json.loads(payload)['set_at']);canonical(updated)


def test_inventory_quantity_update_uses_canonical_clock(tmp_path):
    from backend.services.inventory import add_inventory_quantity
    c=legacy_connection(tmp_path/'inventory.db');apply_migrations(c)
    add_inventory_quantity(c,1,1,2,None)
    canonical(c.execute('SELECT updated_at FROM inventory WHERE id=1').fetchone()[0])
    assert c.execute('SELECT quantity FROM inventory WHERE id=1').fetchone()[0]==21


def test_current_backup_rejects_noncanonical_instant_without_live_changes(tmp_path):
    import shutil
    from database_restore import restore_database
    live=tmp_path/'live.db';upload=tmp_path/'upload.db'
    c=legacy_connection(live);apply_migrations(c);c.close();shutil.copyfile(live,upload)
    with sqlite3.connect(upload) as c:c.execute("UPDATE movements SET created_at='2026-01-02 03:04:05'")
    before=live.read_bytes()
    with pytest.raises(MigrationError):restore_database(upload,live,7)
    assert live.read_bytes()==before


def test_superadmin_expiry_preserves_microsecond_boundary(super_api,monkeypatch):
    from datetime import datetime,timezone
    import backend.routes.superadmin as routes
    client,path,_=super_api
    monkeypatch.setattr(routes,'utc_now',lambda:datetime(2090,1,1,12,0,0,500001,tzinfo=timezone.utc))
    with sqlite3.connect(path) as c:
        c.execute('UPDATE sessions SET is_active=0 WHERE user_id!=2')
        c.execute("INSERT INTO sessions(user_id,session_token,expires_at) VALUES(3,'just-expired','2090-01-01T12:00:00.500000Z'),(3,'just-active','2090-01-01T12:00:00.500002Z')")
        c.execute("UPDATE users SET account_locked_until='2090-01-01T12:00:00.500000Z' WHERE id=1")
        c.execute("UPDATE users SET account_locked_until='2090-01-01T12:00:00.500002Z' WHERE id=3")
    result=client.get('/api/superadmin/sessions')
    assert result.status_code==200
    assert len(result.json())==2  # root and just-active
    result=client.get('/api/superadmin/locked-accounts')
    assert [row['id'] for row in result.json()]==[3]
    result=client.get('/api/superadmin/dashboard')
    assert result.json()['active_sessions']==2
    assert result.json()['locked_accounts']==1


@pytest.mark.parametrize('operation',['minimum','count'])
def test_count_and_minimum_writers_use_canonical_clock(session_api,operation):
    client,path,_=session_api
    if operation=='minimum':
        response=client.put('/api/inventory/minimum',json={'store_id':1,'part_id':1,'min_threshold':3,'expected_minimum':0})
    else:
        sheet=client.get('/api/inventory/count-sheet/1').json()
        preview=client.post('/api/inventory/count-preview',json={'sheet_token':sheet['sheet_token'],'rows':[{'inventory_id':1,'counted_quantity':8,'reason':'Physical count'}]}).json()
        response=client.post('/api/inventory/count-confirm',json={'preview_token':preview['preview_token'],'confirmed':True})
    assert response.status_code==200,response.text
    with sqlite3.connect(path) as c:canonical(c.execute('SELECT updated_at FROM inventory WHERE id=1').fetchone()[0])


@pytest.mark.parametrize('future_change',['new_field','changed_policy','validation_only'])
def test_historical_v5_inventory_survives_later_manifest_changes(tmp_path,monkeypatch,future_change):
    """Replay v5 itself before a later migration creates its own temporal fields."""
    import importlib
    from dataclasses import replace
    from backend.migrations import registry,v0005_canonical_instants as v5
    from backend import temporal_manifest as manifest
    c=legacy_connection(tmp_path/'version4.db')
    with monkeypatch.context() as patch:
        patch.setattr(registry,'MIGRATIONS',registry.MIGRATIONS[:4])
        apply_migrations(c)
    c.execute("UPDATE users SET created_at='2026-01-02 03:04:05.123456'")
    c.commit()
    try:
        with monkeypatch.context() as patch:
            future=manifest.TEMPORAL_FIELDS+(manifest.TemporalField('users','future_verified_at','instant','utc','Future v6 field'),)
            if future_change=='changed_policy':
                future=tuple(replace(f,naive_policy=None) if f.kind=='instant' else f for f in manifest.TEMPORAL_FIELDS)
            patch.setattr(manifest,'TEMPORAL_FIELDS',future)
            if future_change!='validation_only':
                importlib.reload(v5)  # Simulate an updated application's fresh import.
            c.execute('PRAGMA foreign_keys=OFF');c.execute('BEGIN IMMEDIATE')
            v5.upgrade(c);v5.validate(c)
            assert c.execute('SELECT created_at FROM users').fetchone()[0]=='2026-01-02T03:04:05.123456Z'
            assert not c.execute('PRAGMA foreign_key_check').fetchall()
    finally:
        c.rollback();c.execute('PRAGMA foreign_keys=ON')
        importlib.reload(v5)
        c.close()
