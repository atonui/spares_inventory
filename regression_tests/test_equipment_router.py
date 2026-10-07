"""Equipment extraction and existing HTTP contracts."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import pytest
from fastapi.routing import APIRoute
import main
from backend.database import connect_database
from regression_tests.test_session_write_routes import session_api, database_state

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    ('GET', '/api/equipment'), ('POST', '/api/equipment'),
    ('GET', '/api/equipment/statistics'), ('PUT', '/api/equipment/{equipment_id}'),
    ('POST', '/api/equipment/{equipment_id}/transfer'),
    ('POST', '/api/equipment/{equipment_id}/calibrate'),
    ('DELETE', '/api/equipment/{equipment_id}'), ('GET', '/api/equipment/{equipment_id}/history'),
    ('GET', '/api/settings/calibration-reminder-days'), ('PUT', '/api/settings/calibration-reminder-days'),
}


def test_equipment_registration_and_dependencies():
    routes = [r for r in main.app.routes if isinstance(r, APIRoute)
              and (r.path.startswith('/api/equipment') or r.path == '/api/settings/calibration-reminder-days')]
    assert len(routes) == 10
    assert {(m, r.path) for r in routes for m in r.methods} == OPERATIONS
    for route in routes:
        assert route.endpoint.__module__ == 'backend.routes.equipment'
        assert route.tags == []
        expected = {main.get_current_user}
        if route.methods != {'GET'}:
            expected.add(main.verify_csrf)
        assert {d.call for d in route.dependant.dependencies} == expected


def test_equipment_schema_reexports():
    from backend.schemas import equipment
    for name in ('EquipmentResponse', 'CreateEquipmentRequest', 'UpdateEquipmentRequest',
                 'TransferEquipmentRequest', 'UpdateCalibrationRequest', 'EquipmentStatsResponse'):
        assert getattr(main, name) is getattr(equipment, name)
    assert equipment.TransferEquipmentRequest().model_dump() == {'to_user_id': None, 'notes': None}


def populate(path):
    with closing(connect_database(path)) as conn, conn:
        conn.execute("UPDATE equipment SET next_calibration_date='2000-01-01' WHERE id=1")
        conn.execute("INSERT INTO equipment(id,equipment_name,make,model,serial_number,assigned_user_id,next_calibration_date) VALUES(2,'Second','Maker','M2','SECOND',4,date('now','+1 day'))")
        conn.execute("INSERT INTO equipment(id,equipment_name,make,model,serial_number,assigned_user_id,status) VALUES(3,'Deleted','Maker','M3','DELETED',3,'deleted')")


@pytest.mark.parametrize('actor,owned', [('admin-token', {1, 2}), ('root-token', set()), ('engineer-token', {1}), ('manager-token', {2})])
@pytest.mark.parametrize('show_all', [False, True])
def test_equipment_listing_preserves_existing_visibility(session_api, actor, owned, show_all):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    response = client.get('/api/equipment', params={'show_all': show_all})
    assert response.status_code == 200, response.text
    assert {r['id'] for r in response.json()} == ({1, 2} if show_all else owned)


@pytest.mark.parametrize('actor,my,due,overdue', [
    ('admin-token', 0, 1, 1), ('root-token', 0, 1, 1),
    ('engineer-token', 1, 0, 1), ('manager-token', 1, 1, 0),
])
def test_equipment_statistics_preserves_role_and_date_rules(session_api, actor, my, due, overdue):
    client, path, _ = session_api
    populate(path)
    client.cookies.set('session_token', actor)
    response = client.get('/api/equipment/statistics')
    assert response.status_code == 200, response.text
    assert response.json() == {'total_equipment': 2, 'my_equipment': my, 'due_soon': due, 'overdue': overdue}


@pytest.mark.parametrize('actor,status', [('admin-token', 200), ('root-token', 200), ('engineer-token', 200), ('manager-token', 403)])
@pytest.mark.parametrize('action', ['transfer', 'calibrate'])
def test_equipment_owner_operations_preserve_permissions_and_history(session_api, actor, status, action):
    client, path, _ = session_api
    client.cookies.set('session_token', actor)
    payload = {'to_user_id': 4, 'notes': 'Moved'} if action == 'transfer' else {
        'calibration_cert_number': 'CERT', 'calibration_authority': 'Lab',
        'calibration_date': '2026-01-01', 'next_calibration_date': '2027-01-01', 'notes': 'Calibrated',
    }
    before = database_state(path)
    response = client.post(f'/api/equipment/1/{action}', json=payload)
    assert response.status_code == status, response.text
    if status == 403:
        assert database_state(path) == before
    else:
        with closing(connect_database(path)) as conn:
            row = conn.execute('SELECT assigned_user_id,calibration_cert_number FROM equipment WHERE id=1').fetchone()
            assert row[0] == 4 if action == 'transfer' else row[1] == 'CERT'
            assert conn.execute('SELECT action FROM equipment_history WHERE equipment_id=1').fetchone()[0] == ('transferred' if action == 'transfer' else 'calibrated')
            assert conn.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0] == 1


def test_equipment_nullable_assignment_and_soft_delete(session_api):
    client, path, _ = session_api
    assert client.put('/api/equipment/1', json={'assigned_user_id': None, 'notes': None}).status_code == 200
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT assigned_user_id FROM equipment WHERE id=1').fetchone()[0] is None
        assert conn.execute('SELECT COUNT(*) FROM equipment_history').fetchone()[0] == 0
    assert client.delete('/api/equipment/1').status_code == 200
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT status FROM equipment WHERE id=1').fetchone()[0] == 'deleted'
        assert conn.execute('SELECT action FROM equipment_history').fetchone()[0] == 'deleted'
    assert client.get('/api/equipment', params={'show_all': True}).json() == []
    client.cookies.set('session_token', 'manager-token')
    history = client.get('/api/equipment/1/history')
    assert history.status_code == 200 and history.json()[0]['action'] == 'deleted'


@pytest.mark.parametrize('days,status', [(0, 400), (366, 400), (1, 200), (365, 200)])
def test_equipment_reminder_bounds_and_readback(session_api, days, status):
    client, path, _ = session_api
    before = database_state(path)
    response = client.put('/api/settings/calibration-reminder-days', params={'days': days})
    assert response.status_code == status, response.text
    if status == 200:
        assert client.get('/api/settings/calibration-reminder-days').json() == {'days': days}
    else:
        assert database_state(path) == before


def test_equipment_borrowed_guard_and_atomic_history_audit(session_api, monkeypatch):
    client, path, _ = session_api
    guard = main.check_admin
    active = main.require_active_record
    audit = main._record_mutation_activity
    owners = []
    def borrowed_guard(user_id, conn=None):
        assert conn is not None and conn.in_transaction
        owners.append(conn)
        return guard(user_id, conn)
    def borrowed_active(conn, *args, **kwargs):
        assert conn.in_transaction
        return active(conn, *args, **kwargs)
    def borrowed_audit(conn, *args, **kwargs):
        assert conn is owners[-1] and conn.in_transaction
        return audit(conn, *args, **kwargs)
    monkeypatch.setattr(main, 'check_admin', borrowed_guard)
    monkeypatch.setattr(main, 'require_active_record', borrowed_active)
    monkeypatch.setattr(main, '_record_mutation_activity', borrowed_audit)
    payload = {'equipment_name': 'New', 'make': 'Maker', 'model': 'M2', 'serial_number': 'NEW', 'assigned_user_id': 3}
    assert client.post('/api/equipment', json=payload).status_code == 200
    with closing(connect_database(path)) as conn:
        conn.execute("CREATE TRIGGER reject_equipment_audit BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    before = database_state(path)
    payload['serial_number'] = 'ROLLBACK'
    with pytest.raises(sqlite3.IntegrityError, match='audit unavailable'):
        client.post('/api/equipment', json=payload)
    assert database_state(path) == before


def test_equipment_current_database_path(session_api, monkeypatch, tmp_path):
    client, path, _ = session_api
    target = tmp_path / 'equipment-switched.db'
    with closing(connect_database(path)) as source, closing(connect_database(target)) as destination:
        source.backup(destination)
    with closing(connect_database(target)) as conn, conn:
        conn.execute("UPDATE equipment SET equipment_name='Target' WHERE id=1")
    monkeypatch.setattr(main, 'DATABASE', str(target))
    assert client.get('/api/equipment', params={'show_all': True}).json()[0]['equipment_name'] == 'Target'
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT equipment_name FROM equipment WHERE id=1').fetchone()[0] == 'Meter'


def test_equipment_imports_are_inert(tmp_path):
    script = ('import pathlib,sys; cwd=pathlib.Path.cwd(); before=set(cwd.iterdir()); '
              'import backend.routes.equipment, backend.schemas.equipment; '
              'assert "main" not in sys.modules; assert pathlib.Path.cwd()==cwd; assert set(cwd.iterdir())==before')
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stderr
