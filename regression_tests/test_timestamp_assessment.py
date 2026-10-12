"""Read-only temporal discovery must not invent provenance or expose values."""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from backend.migrations.runner import apply_migrations
from backend.temporal_manifest import TEMPORAL_FIELDS, TemporalField
from scripts.assess_timestamps import AssessmentError, assess_database


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def database(tmp_path):
    path = tmp_path / 'snapshot.db'
    with sqlite3.connect(path) as conn:
        apply_migrations(conn)
    return path


def test_assessment_never_writes_or_creates_database(database, tmp_path):
    before = digest(database)
    files = sorted(p.name for p in tmp_path.iterdir())
    result = assess_database(database)
    assert result['blockers'] == 0
    assert result['sha256'] == before
    assert digest(database) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == files
    with pytest.raises(AssessmentError):
        assess_database(tmp_path / 'missing.db')
    assert not (tmp_path / 'missing.db').exists()


def test_manifest_covers_schema_temporal_fields(database):
    with sqlite3.connect(database) as conn:
        columns = {(table, row[1]) for (table,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            for row in conn.execute(f'PRAGMA table_info("{table}")')
            if row[1].endswith(('_at', '_date', '_expires')) or row[1] in ('last_login', 'last_activity')}
    covered = {(field.table, field.column) for field in TEMPORAL_FIELDS}
    assert columns <= covered
    assert all(field.provenance for field in TEMPORAL_FIELDS)


def test_unknown_naive_and_invalid_values_block_conversion(database):
    secret = 'DO-NOT-EXPOSE-password-token-or-email'
    with sqlite3.connect(database) as conn:
        for identifier, value in enumerate(['2026-10-12 09:00:00', secret, '2026-10-12T09:00:00Z'], 1):
            conn.execute('INSERT INTO system_logs(id,level,message,created_at) VALUES(?,?,?,?)',
                         (identifier, 'info', secret, value))
    report = assess_database(database)
    field = next(f for f in report['fields'] if f['table'] == 'system_logs')
    assert field['counts']['naive_unverified'] == 1
    assert field['counts']['invalid'] == 1
    assert field['counts']['aware'] == 1
    assert report['blockers'] == 2
    assert secret not in json.dumps(report)
    assert field['issues'] == [{'row_id': 1, 'reason': 'naive_unverified'}, {'row_id': 2, 'reason': 'invalid'}]


def test_approved_naive_policy_and_dates_remain_distinct(database, monkeypatch):
    import scripts.assess_timestamps as assessment
    fields = [TemporalField('system_logs', 'created_at', 'instant', 'utc', 'Test-only verified writer'),
              TemporalField('equipment', 'calibration_date', 'date', None, 'Calendar date')]
    monkeypatch.setattr(assessment, 'TEMPORAL_FIELDS', tuple(fields))
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO system_logs(level,message,created_at) VALUES('info','test','2026-10-12 09:00:00')")
        conn.execute("INSERT INTO equipment(equipment_name,make,model,serial_number,calibration_date) VALUES('e','m','m','s','2026-10-12')")
    report = assess_database(database)
    assert report['fields'][0]['counts']['naive_verified_utc'] == 1
    assert report['fields'][1]['counts']['date'] == 1
    assert report['fields'][1]['issues'] == []


def test_unknown_temporal_column_blocks_readiness(database):
    with sqlite3.connect(database) as conn:
        conn.execute('ALTER TABLE movements ADD COLUMN imported_at TEXT')
    report = assess_database(database)
    assert {'table': 'movements', 'column': 'imported_at'} in report['unclassified_columns']
    assert report['blockers'] > 0


def test_embedded_announcement_and_duration_settings_are_assessed(database):
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('system_announcement',?)",
                     (json.dumps({'message': 'private', 'set_at': '2026-10-12T09:00:00'}),))
        conn.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('session_duration_hours','24')")
    result = assess_database(database)
    embedded = next(f for f in result['fields'] if f.get('json_key') == 'set_at')
    duration = next(f for f in result['fields'] if f.get('setting_key') == 'session_duration_hours')
    assert embedded['counts']['naive_unverified'] == 1
    assert duration['counts']['duration'] == 1
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize('sidecar', ['-wal', '-journal'])
def test_live_or_uncheckpointed_files_are_rejected(database, sidecar):
    Path(str(database) + sidecar).write_bytes(b'pending transaction')
    with pytest.raises(AssessmentError, match='standalone'):
        assess_database(database)


def test_cli_status_codes_and_safe_errors(database, tmp_path):
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'scripts/assess_timestamps.py'), '--database']
    clean = subprocess.run(command + [str(database)], capture_output=True, text=True)
    assert clean.returncode == 0
    assert json.loads(clean.stdout)['blockers'] == 0
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO system_logs(level,message,created_at) VALUES('info','SECRET','bad')")
    blocked = subprocess.run(command + [str(database)], capture_output=True, text=True)
    assert blocked.returncode == 1
    assert 'SECRET' not in blocked.stdout + blocked.stderr
    missing = subprocess.run(command + [str(tmp_path / 'missing.db')], capture_output=True, text=True)
    assert missing.returncode == 2
    assert not (tmp_path / 'missing.db').exists()


def test_offset_instant_that_overflows_utc_is_invalid(database):
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO system_logs(level,message,created_at) VALUES('info','test','0001-01-01T00:00:00+01:00')")
    report = assess_database(database)
    field = next(f for f in report['fields'] if f['table'] == 'system_logs')
    assert field['counts']['invalid'] == 1


@pytest.mark.parametrize('offset', ['+01:99', '+00:60', '-02:99'])
def test_malformed_offset_minutes_are_not_normalised(database, offset):
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO system_logs(level,message,created_at) VALUES('info','test',?)",
                     ('2026-10-12T09:00:00' + offset,))
    report = assess_database(database)
    field = next(f for f in report['fields'] if f['table'] == 'system_logs')
    assert field['counts']['invalid'] == 1
    assert field['counts']['aware'] == 0


def test_encoded_path_and_non_sqlite_input_do_not_create_sidecars(database, tmp_path):
    renamed = tmp_path / 'snapshot ?#%.db'
    database.rename(renamed)
    assert assess_database(renamed)['blockers'] == 0
    invalid = tmp_path / 'invalid.db'
    invalid.write_bytes(b'SECRET invalid database contents')
    with pytest.raises(AssessmentError) as error:
        assess_database(invalid)
    assert 'SECRET' not in str(error.value)


def test_text_identity_in_integer_declared_column_is_never_exposed(database):
    secret = 'SECRET-text-id-that-must-not-be-logged'
    with sqlite3.connect(database) as conn:
        conn.execute('DROP TABLE system_logs')
        conn.execute('CREATE TABLE system_logs(id INTEGER PRIMARY KEY DESC,created_at TIMESTAMP)')
        conn.execute('INSERT INTO system_logs(id,created_at) VALUES(?,?)', (secret, 'bad'))
    with pytest.raises(AssessmentError) as error:
        assess_database(database)
    assert secret not in str(error.value)
