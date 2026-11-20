"""Equipment extraction and existing HTTP contracts."""
from datetime import date, timedelta
import os
from pathlib import Path
import subprocess
import sys
import psycopg
import pytest
from fastapi.routing import APIRoute
import main
from regression_tests.postgres_app import database_state, fail_inserts

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    ('GET', '/api/equipment'), ('POST', '/api/equipment'),
    ('GET', '/api/equipment/statistics'), ('PUT', '/api/equipment/{equipment_id}'),
    ('POST', '/api/equipment/{equipment_id}/transfer'),
    ('POST', '/api/equipment/{equipment_id}/calibrate'),
    ('POST', '/api/equipment/{equipment_id}/restore'),
    ('DELETE', '/api/equipment/{equipment_id}'), ('GET', '/api/equipment/{equipment_id}/history'),
    ('GET', '/api/settings/calibration-reminder-days'), ('PUT', '/api/settings/calibration-reminder-days'),
}


def test_equipment_registration_and_dependencies():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path.startswith('/api/equipment') or r.path == '/api/settings/calibration-reminder-days')]
    assert len(routes) == 11
    assert {(m, r.path) for r in routes for m in r.methods} == OPERATIONS
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.equipment'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods != {'GET'}:
            expected.add(main.verify_authenticated_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected


def test_equipment_schema_reexports():
    from backend.schemas import equipment
    for name in ('EquipmentResponse', 'CreateEquipmentRequest', 'UpdateEquipmentRequest',
                 'TransferEquipmentRequest', 'UpdateCalibrationRequest', 'EquipmentStatsResponse'):
        assert getattr(main, name) is getattr(equipment, name)
    assert equipment.TransferEquipmentRequest().model_dump() == {'to_user_id': None, 'notes': None}


def populate(api):
    db = api.db
    db.execute("UPDATE equipment SET next_calibration_date='2000-01-01' WHERE id=1")
    db.execute("""INSERT INTO equipment(id,organization_id,equipment_name,make,model,serial_number,assigned_user_id,next_calibration_date)
                  OVERRIDING SYSTEM VALUE VALUES(2,%s,'Second','Maker','M2','SECOND',4,%s)""",
               (api.org_a, (date.today() + timedelta(days=1)).isoformat()))
    db.execute("""INSERT INTO equipment(id,organization_id,equipment_name,make,model,serial_number,assigned_user_id,status)
                  OVERRIDING SYSTEM VALUE VALUES(3,%s,'Deleted','Maker','M3','DELETED',3,'deleted')""", (api.org_a,))
    # Another company's equipment must never be counted or listed.
    db.execute("""INSERT INTO equipment(id,organization_id,equipment_name,make,model,serial_number,next_calibration_date)
                  OVERRIDING SYSTEM VALUE VALUES(101,%s,'Other','Maker','M9','OTHER','2000-01-01')""", (api.org_b,))
    db.commit()


@pytest.mark.parametrize('actor,owned', [('admin', {1, 2}), ('owner', {1, 2}), ('engineer', {1}), ('manager', {2})])
@pytest.mark.parametrize('show_all', [False, True])
def test_equipment_listing_preserves_existing_visibility(tenant_api, actor, owned, show_all):
    populate(tenant_api)
    client = tenant_api.as_actor(actor)
    response = client.get('/api/equipment', params={'show_all': show_all})
    assert response.status_code == 200, response.text
    assert {r['id'] for r in response.json()} == ({1, 2} if show_all else owned)


@pytest.mark.parametrize('actor,my,due,overdue', [
    ('admin', 0, 1, 1), ('owner', 0, 1, 1),
    ('engineer', 1, 0, 1), ('manager', 1, 1, 0),
])
def test_equipment_statistics_preserves_role_and_date_rules(tenant_api, actor, my, due, overdue):
    populate(tenant_api)
    client = tenant_api.as_actor(actor)
    response = client.get('/api/equipment/statistics')
    assert response.status_code == 200, response.text
    assert response.json() == {'total_equipment': 2, 'my_equipment': my, 'due_soon': due, 'overdue': overdue}


@pytest.mark.parametrize('actor,status', [('admin', 200), ('owner', 200), ('engineer', 200), ('manager', 403)])
@pytest.mark.parametrize('action', ['transfer', 'calibrate'])
def test_equipment_owner_operations_preserve_permissions_and_history(tenant_api, actor, status, action):
    client = tenant_api.as_actor(actor)
    db = tenant_api.db
    payload = {'to_user_id': 4, 'notes': 'Moved'} if action == 'transfer' else {
        'calibration_cert_number': 'CERT', 'calibration_authority': 'Lab',
        'calibration_date': '2026-01-01', 'next_calibration_date': '2027-01-01', 'notes': 'Calibrated',
    }
    before = database_state(db)
    response = client.post(f'/api/equipment/1/{action}', json=payload)
    assert response.status_code == status, response.text
    if status == 403:
        assert database_state(db) == before
    else:
        row = db.execute('SELECT assigned_user_id,calibration_cert_number FROM equipment WHERE id=1').fetchone()
        assert row['assigned_user_id'] == 4 if action == 'transfer' else row['calibration_cert_number'] == 'CERT'
        history = db.execute('SELECT action, organization_id FROM equipment_history WHERE equipment_id=1').fetchone()
        assert history == {'action': 'transferred' if action == 'transfer' else 'calibrated', 'organization_id': tenant_api.org_a}
        assert db.execute('SELECT COUNT(*) AS n FROM activity_logs').fetchone()['n'] == 1


def test_equipment_nullable_assignment_and_soft_delete(tenant_api):
    client, db = tenant_api.client, tenant_api.db
    assert client.put('/api/equipment/1', json={'assigned_user_id': None, 'notes': None}).status_code == 200
    assert db.execute('SELECT assigned_user_id FROM equipment WHERE id=1').fetchone()['assigned_user_id'] is None
    assert db.execute('SELECT COUNT(*) AS n FROM equipment_history').fetchone()['n'] == 0
    db.commit()
    assert client.delete('/api/equipment/1').status_code == 200
    assert db.execute('SELECT status FROM equipment WHERE id=1').fetchone()['status'] == 'deleted'
    assert db.execute('SELECT action FROM equipment_history').fetchone()['action'] == 'deleted'
    db.commit()
    assert client.get('/api/equipment', params={'show_all': True}).json() == []
    tenant_api.as_actor('manager')
    history = client.get('/api/equipment/1/history')
    assert history.status_code == 200 and history.json()[0]['action'] == 'deleted'


def test_equipment_archive_listing_is_admin_only_and_restore_preserves_history(tenant_api):
    client = tenant_api.client
    client.delete('/api/equipment/1')

    # Deleted equipment is not exposed through ordinary lists.
    assert client.get('/api/equipment', params={'show_all': True}).json() == []
    assert client.delete('/api/equipment/1').status_code == 409
    assert client.put('/api/equipment/1', json={'notes': 'edit'}).status_code == 409
    assert client.post('/api/equipment/1/transfer', json={'to_user_id': 4, 'notes': 'move'}).status_code == 409
    assert client.post('/api/equipment/1/calibrate', json={
        'calibration_cert_number': 'CERT', 'calibration_authority': 'Lab',
        'calibration_date': '2026-01-01', 'next_calibration_date': '2027-01-01',
    }).status_code == 409

    # Only company admins can retrieve archived equipment for recovery.
    tenant_api.as_actor('engineer')
    assert client.get('/api/equipment', params={'include_archived': True}).status_code == 403
    tenant_api.as_actor('admin')
    archived = client.get('/api/equipment', params={'include_archived': True})
    assert archived.status_code == 200, archived.text
    assert [(row['id'], row['status']) for row in archived.json()] == [(1, 'deleted')]

    # Restore is admin-only, idempotency conflicts are explicit, and history remains.
    tenant_api.as_actor('engineer')
    assert client.post('/api/equipment/1/restore').status_code == 403
    tenant_api.as_actor('admin')
    restored = client.post('/api/equipment/1/restore')
    assert restored.status_code == 200, restored.text
    assert restored.json()['success'] is True
    assert client.post('/api/equipment/1/restore').status_code == 409
    assert [row['action'] for row in client.get('/api/equipment/1/history').json()] == ['restored', 'deleted']
    assert [row['id'] for row in client.get('/api/equipment', params={'show_all': True}).json()] == [1]


@pytest.mark.parametrize('days,status', [(0, 400), (366, 400), (1, 200), (365, 200)])
def test_equipment_reminder_bounds_and_readback(tenant_api, days, status):
    client = tenant_api.client
    before = database_state(tenant_api.db)
    response = client.put('/api/settings/calibration-reminder-days', params={'days': days})
    assert response.status_code == status, response.text
    if status == 200:
        assert client.get('/api/settings/calibration-reminder-days').json() == {'days': days}
    else:
        assert database_state(tenant_api.db) == before


def test_equipment_borrowed_guard_and_atomic_history_audit(tenant_api, monkeypatch):
    client = tenant_api.client
    guard = main.check_admin
    active = main.require_active_record
    audit = main._record_mutation_activity
    owners = []
    def in_transaction(conn):
        return conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
    def borrowed_guard(user_id, conn=None):
        assert conn is not None and in_transaction(conn)
        owners.append(conn)
        return guard(user_id, conn)
    def borrowed_active(conn, *args, **kwargs):
        assert in_transaction(conn)
        return active(conn, *args, **kwargs)
    def borrowed_audit(conn, *args, **kwargs):
        assert conn is owners[-1] and in_transaction(conn)
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'check_admin', borrowed_guard)
    monkeypatch.setattr(main, 'require_active_record', borrowed_active)
    monkeypatch.setattr(main, '_record_mutation_activity', borrowed_audit)
    payload = {'equipment_name': 'New', 'make': 'Maker', 'model': 'M2', 'serial_number': 'NEW', 'assigned_user_id': 3}
    assert client.post('/api/equipment', json=payload).status_code == 200
    fail_inserts(tenant_api.db, 'activity_logs', 'audit unavailable')
    before = database_state(tenant_api.db)
    payload['serial_number'] = 'ROLLBACK'
    with pytest.raises(psycopg.errors.RaiseException, match='audit unavailable'):
        client.post('/api/equipment', json=payload)
    assert database_state(tenant_api.db) == before


def test_other_company_equipment_cannot_be_read_or_changed(tenant_api):
    populate(tenant_api)
    client = tenant_api.as_actor('admin')
    before = database_state(tenant_api.db)
    for call in (lambda eid: client.put(f'/api/equipment/{eid}', json={'notes': 'taken'}),
                 lambda eid: client.post(f'/api/equipment/{eid}/transfer', json={'to_user_id': 3}),
                 lambda eid: client.delete(f'/api/equipment/{eid}'),
                 lambda eid: client.get(f'/api/equipment/{eid}/history')):
        other, missing = call(101), call(99999)
        assert other.status_code == missing.status_code
        assert other.json() == missing.json()
    after = database_state(tenant_api.db)
    assert after['equipment'] == before['equipment'] and after['equipment_history'] == before['equipment_history']


def test_equipment_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.equipment, backend.schemas.equipment; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr


def test_calibration_reminder_is_per_company(tenant_api):
    client = tenant_api.as_actor('admin')
    assert client.get('/api/settings/calibration-reminder-days').json() == {'days': 30}
    assert client.put('/api/settings/calibration-reminder-days', params={'days': 7}).status_code == 200
    assert client.get('/api/settings/calibration-reminder-days').json() == {'days': 7}

    other = tenant_api.as_actor('other')
    assert other.get('/api/settings/calibration-reminder-days').json() == {'days': 30}
    rows = tenant_api.db.execute(
        'SELECT organization_id, calibration_reminder_days, updated_by FROM organization_settings ORDER BY organization_id'
    ).fetchall()
    assert rows == [
        {'organization_id': tenant_api.org_a, 'calibration_reminder_days': 7, 'updated_by': 1},
        {'organization_id': tenant_api.org_b, 'calibration_reminder_days': 30, 'updated_by': None},
    ]
    assert tenant_api.db.execute(
        "SELECT count(*) AS n FROM system_settings WHERE setting_key='calibration_reminder_days'"
    ).fetchone()['n'] == 0


@pytest.mark.parametrize('actor', ['manager', 'engineer'])
def test_only_company_admins_change_the_calibration_reminder(tenant_api, actor):
    before = database_state(tenant_api.db)
    response = tenant_api.as_actor(actor).put('/api/settings/calibration-reminder-days', params={'days': 7})
    assert response.status_code == 403, response.text
    assert database_state(tenant_api.db) == before


def test_due_soon_uses_the_company_reminder_window(tenant_api):
    db = tenant_api.db
    db.execute("UPDATE equipment SET next_calibration_date=%s WHERE id=1", ((date.today() + timedelta(days=20)).isoformat(),))
    db.commit()
    client = tenant_api.as_actor('admin')
    assert client.get('/api/equipment/statistics').json()['due_soon'] == 1  # default 30 days
    assert client.put('/api/settings/calibration-reminder-days', params={'days': 10}).status_code == 200
    assert client.get('/api/equipment/statistics').json()['due_soon'] == 0
