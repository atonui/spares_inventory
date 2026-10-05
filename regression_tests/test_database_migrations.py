import importlib
import sqlite3
import pytest
from regression_tests.migration_fixtures import legacy_connection,snapshot,schema_snapshot

def modules():
    return [importlib.import_module('backend.migrations.v000'+str(i)+'_'+n) for i,n in [(1,'core_schema'),(2,'transfer_lifecycle'),(3,'archiving_integrity')]]

def upgrade(conn):
    for m in modules():m.upgrade(conn);m.validate(conn)
    conn.commit()

def test_empty_database_is_supported(tmp_path):
    from backend.migrations.validation import validate_legacy
    with sqlite3.connect(tmp_path/'empty.db') as c:validate_legacy(c);upgrade(c);assert c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0

def test_legacy_recognition_preserves_rows(tmp_path):
    from backend.migrations.validation import validate_legacy
    c=legacy_connection(tmp_path/'legacy.db');before=snapshot(c);validate_legacy(c);assert snapshot(c)==before
    upgrade(c);assert tuple(c.execute('SELECT quantity,min_threshold FROM inventory').fetchone())==(19,2)

@pytest.mark.parametrize('table,columns',[('users',['session_expires','failed_login_attempts','account_locked_until','last_login','reset_token','reset_token_expires']),('movements',['notes'])])
def test_missing_supported_optional_columns_upgrade(tmp_path,table,columns):
    from backend.migrations.validation import validate_legacy
    c=legacy_connection(tmp_path/'old.db')
    for col in columns:c.execute(f'ALTER TABLE {table} DROP COLUMN {col}')
    validate_legacy(c);upgrade(c)
    assert set(columns)<=set(r[1] for r in c.execute('PRAGMA table_info('+table+')'))


def test_partial_known_additions_are_preserved(tmp_path):
    from backend.migrations.validation import validate_legacy
    c=legacy_connection(tmp_path/'partial.db');c.execute('ALTER TABLE users ADD COLUMN archived_at TEXT');c.execute("UPDATE users SET archived_at='2020-01-01'");c.commit()
    validate_legacy(c);upgrade(c);assert c.execute('SELECT archived_at FROM users').fetchone()[0]=='2020-01-01'

@pytest.mark.parametrize('conflict',['table','index'])
def test_conflicting_table_or_index_rejected(tmp_path,conflict):
    from backend.migrations.validation import validate_legacy,MigrationError
    c=legacy_connection(tmp_path/'bad.db')
    if conflict=='table':c.execute('ALTER TABLE inventory RENAME COLUMN quantity TO wrong_quantity')
    else:c.execute('CREATE INDEX idx_inventory_unallocated_unique ON inventory(quantity)')
    before=schema_snapshot(c)
    with pytest.raises(MigrationError):validate_legacy(c)
    assert schema_snapshot(c)==before

def test_unknown_nonempty_layout_rejected(tmp_path):
    from backend.migrations.validation import validate_legacy,MigrationError
    with sqlite3.connect(tmp_path/'bad.db') as c:
        c.execute('CREATE TABLE users(id INTEGER)')
        with pytest.raises(MigrationError):validate_legacy(c)

def test_duplicate_inventory_is_not_consolidated(tmp_path):
    from backend.migrations.validation import MigrationError
    c=legacy_connection(tmp_path/'bad.db');c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(1,1,10)');c.commit();before=snapshot(c)
    with pytest.raises(MigrationError):upgrade(c)
    assert [r[3] for r in snapshot(c)['inventory']]==[r[3] for r in before['inventory']]

def test_other_orphans_are_not_repaired(tmp_path):
    from backend.migrations.validation import MigrationError
    c=legacy_connection(tmp_path/'bad.db');c.execute('UPDATE inventory SET part_id=999');c.commit()
    with pytest.raises(MigrationError):upgrade(c)
    assert c.execute('SELECT part_id FROM inventory').fetchone()[0]==999

def test_legacy_audit_zero_is_normalized(tmp_path):
    c=legacy_connection(tmp_path/'old.db');c.execute("INSERT INTO activity_logs(user_id,username,action) VALUES(0,'Legacy','login')");c.commit();upgrade(c)
    assert tuple(c.execute('SELECT user_id,username FROM activity_logs').fetchone())==(None,'Legacy')

def test_historical_transfers_stay_completed(tmp_path):
    c=legacy_connection(tmp_path/'old.db');c.execute("INSERT INTO movements(from_store_id,to_store_id,part_id,quantity,movement_type,created_by) VALUES(1,1,1,4,'transfer',7)");c.commit();upgrade(c)
    assert c.execute('SELECT COUNT(*) FROM stock_transfers').fetchone()[0]==0


def runner():
    return importlib.import_module('backend.migrations.runner')

def test_fresh_database_records_versions_1_2_3(tmp_path):
    c=sqlite3.connect(tmp_path/'fresh.db');s=runner().apply_migrations(c)
    assert s.current_version==3 and s.pending==()
    assert c.execute('SELECT version FROM schema_migrations ORDER BY version').fetchall()==[(1,),(2,),(3,)]

def test_adoption_records_only_validated_versions(tmp_path):
    c=legacy_connection(tmp_path/'live.db',current=True);before=snapshot(c);runner().apply_migrations(c)
    assert snapshot(c,ledger=False)==before
    assert runner().migration_status(c).applied==(1,2,3)

def test_repeat_upgrade_preserves_rows_and_applied_at(tmp_path):
    c=legacy_connection(tmp_path/'live.db');runner().apply_migrations(c);before=snapshot(c);schema=schema_snapshot(c)
    runner().apply_migrations(c);assert snapshot(c)==before and schema_snapshot(c)==schema

@pytest.mark.parametrize('failure',['migration','bootstrap'])
def test_pending_failure_rolls_back_schema_data_and_ledger(tmp_path,monkeypatch,failure):
    from dataclasses import replace
    from backend.migrations import registry
    c=legacy_connection(tmp_path/'live.db');before=snapshot(c);schema=schema_snapshot(c)
    def fail(conn):
        conn.execute('UPDATE inventory SET quantity=999')
        conn.execute('CREATE TABLE half_upgrade(id INTEGER)')
        raise RuntimeError('injected migration failure')
    bootstrap=None
    if failure=='migration':monkeypatch.setattr(registry,'MIGRATIONS',(registry.MIGRATIONS[0],replace(registry.MIGRATIONS[1],upgrade=fail),registry.MIGRATIONS[2]))
    else:bootstrap=fail
    with pytest.raises(Exception,match='injected migration failure'):runner().apply_migrations(c,bootstrap=bootstrap)
    assert snapshot(c)==before and schema_snapshot(c)==schema

@pytest.mark.parametrize('damage',['unknown','checksum','gap','name','definition','constraints'])
def test_bad_ledger_is_rejected_without_writes(tmp_path,damage):
    from backend.migrations.validation import MigrationError
    c=legacy_connection(tmp_path/'live.db');runner().apply_migrations(c)
    if damage=='unknown':c.execute("INSERT INTO schema_migrations VALUES(99,'future','abc','now')")
    elif damage=='checksum':c.execute("UPDATE schema_migrations SET checksum='wrong' WHERE version=1")
    elif damage=='gap':c.execute('DELETE FROM schema_migrations WHERE version=2')
    elif damage=='name':c.execute("UPDATE schema_migrations SET name='wrong' WHERE version=1")
    elif damage=='definition':c.execute('ALTER TABLE schema_migrations RENAME COLUMN checksum TO wrong')
    else:
        rows=c.execute('SELECT * FROM schema_migrations').fetchall();c.execute('DROP TABLE schema_migrations')
        c.execute('CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,checksum TEXT NOT NULL,applied_at TEXT NOT NULL)')
        c.executemany('INSERT INTO schema_migrations VALUES(?,?,?,?)',rows)
    c.commit();before=snapshot(c);schema=schema_snapshot(c)
    with pytest.raises(MigrationError):runner().apply_migrations(c)
    assert snapshot(c)==before and schema_snapshot(c)==schema

def test_two_workers_apply_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    p=tmp_path/'live.db';legacy_connection(p).close()
    def run():
        with sqlite3.connect(p,timeout=10) as c:return runner().apply_migrations(c).current_version
    with ThreadPoolExecutor(2) as pool:assert list(pool.map(lambda _:run(),range(2)))==[3,3]
    with sqlite3.connect(p) as c:assert c.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0]==3

def test_write_lock_timeout_leaves_database_unchanged(tmp_path):
    from backend.migrations.validation import MigrationError
    p=tmp_path/'live.db';c=legacy_connection(p);before=snapshot(c);schema=schema_snapshot(c);c.execute('BEGIN IMMEDIATE')
    with sqlite3.connect(p,timeout=.1) as second:
        with pytest.raises(MigrationError,match='locked|busy'):runner().apply_migrations(second)
    c.rollback();assert snapshot(c)==before and schema_snapshot(c)==schema


def test_main_wrappers_respect_database_override(tmp_path,monkeypatch):
    import main
    p=tmp_path/'override.db';monkeypatch.setattr(main,'DATABASE',str(p));assert main.init_db() is None
    with main.get_db_connection() as c:
        assert c.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0]==3
        assert c.execute('PRAGMA foreign_keys').fetchone()[0]==1


def test_existing_settings_are_not_overwritten(tmp_path):
    from backend.database import initialize_database,DEFAULT_SETTINGS
    p=tmp_path/'settings.db';c=legacy_connection(p);c.execute("INSERT INTO system_settings(setting_key,setting_value) VALUES('session_duration_hours','48')");c.commit();c.close()
    initialize_database(p,defaults={**DEFAULT_SETTINGS,'session_duration_hours':'72'})
    with sqlite3.connect(p) as c:assert c.execute("SELECT setting_value FROM system_settings WHERE setting_key='session_duration_hours'").fetchone()[0]=='48'


def test_no_default_user_is_created(tmp_path):
    from backend.database import initialize_database,DEFAULT_SETTINGS
    p=tmp_path/'new.db';initialize_database(p,defaults=DEFAULT_SETTINGS)
    with sqlite3.connect(p) as c:
        assert c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM store_types').fetchone()[0]==6
        assert c.execute('SELECT COUNT(*) FROM system_settings').fetchone()[0]==5


def test_startup_does_not_write_system_event_before_migration(tmp_path,monkeypatch):
    import asyncio,main
    p=tmp_path/'startup.db';c=legacy_connection(p,current=True);before=snapshot(c);c.close();monkeypatch.setattr(main,'DATABASE',str(p))
    def fail():raise RuntimeError('upgrade failed')
    monkeypatch.setattr(main,'init_db',fail)
    async def enter():
        async with main.lifespan(main.app):pass
    with pytest.raises(RuntimeError,match='upgrade failed'):asyncio.run(enter())
    with sqlite3.connect(p) as c:assert snapshot(c)==before

@pytest.mark.parametrize('damage',['orphan','schema'])
def test_current_ledger_still_rejects_corruption(tmp_path,damage):
    from backend.migrations.validation import MigrationError
    p=tmp_path/'live.db';c=legacy_connection(p);runner().apply_migrations(c)
    c.execute('PRAGMA foreign_keys=OFF')
    if damage=='orphan':c.execute('UPDATE inventory SET part_id=999')
    else:c.execute('DROP INDEX idx_inventory_unallocated_unique')
    c.commit();before=snapshot(c)
    with pytest.raises(MigrationError):runner().apply_migrations(c)
    assert snapshot(c)==before


def test_readonly_connection_does_not_create_missing_database(tmp_path):
    from backend.database import connect_database
    p=tmp_path/'missing.db'
    with pytest.raises(sqlite3.OperationalError):connect_database(p,readonly=True)
    assert not p.exists()


def test_historical_auxiliary_indexes_are_supported(tmp_path):
    from backend.migrations.validation import validate_legacy
    c=legacy_connection(tmp_path/'indexed.db')
    c.execute('CREATE INDEX idx_equipment_assigned_user ON equipment(assigned_user_id)');c.commit()
    validate_legacy(c);runner().apply_migrations(c)
    assert c.execute("SELECT name FROM sqlite_master WHERE name='idx_equipment_assigned_user'").fetchone()

@pytest.mark.parametrize('change',['check','autoincrement','collation'])
def test_conflicting_core_constraints_are_rejected(tmp_path,change):
    from backend.migrations.validation import validate_legacy,MigrationError
    c=legacy_connection(tmp_path/'constraint.db')
    sql=c.execute("SELECT sql FROM sqlite_master WHERE name='users'").fetchone()[0]
    c.execute('DROP TABLE users')
    if change=='check':sql=sql.replace('name TEXT NOT NULL','name TEXT NOT NULL CHECK(length(name)<5)')
    elif change=='autoincrement':sql=sql.replace(' AUTOINCREMENT','')
    else:sql=sql.replace('email TEXT UNIQUE','email TEXT COLLATE NOCASE UNIQUE')
    c.execute(sql)
    with pytest.raises(MigrationError):validate_legacy(c)


def test_repeated_initialization_does_not_advance_autoincrement_or_change_file(tmp_path):
    import hashlib
    from backend.database import initialize_database,DEFAULT_SETTINGS
    p=tmp_path/'repeat.db';initialize_database(p,defaults=DEFAULT_SETTINGS)
    before=hashlib.sha256(p.read_bytes()).hexdigest()
    with sqlite3.connect(p) as c:sequence=c.execute('SELECT * FROM sqlite_sequence ORDER BY name').fetchall()
    initialize_database(p,defaults=DEFAULT_SETTINGS)
    with sqlite3.connect(p) as c:assert c.execute('SELECT * FROM sqlite_sequence ORDER BY name').fetchall()==sequence
    assert hashlib.sha256(p.read_bytes()).hexdigest()==before

@pytest.mark.parametrize('kind',['VIRTUAL','STORED'])
def test_generated_columns_are_rejected_on_current_database(tmp_path,kind):
    from backend.database import initialize_database
    from backend.migrations.validation import MigrationError
    p=tmp_path/'generated.db';initialize_database(p,defaults={})
    with sqlite3.connect(p) as c:
        c.execute(f'ALTER TABLE parts ADD COLUMN hidden_extra TEXT GENERATED ALWAYS AS (part_number) {kind}')
        with pytest.raises(MigrationError):runner().check_database(c)


def test_changed_conflict_algorithm_is_rejected_without_adoption(tmp_path):
    from backend.migrations.validation import MigrationError
    from regression_tests.migration_fixtures import FIXTURES
    c=sqlite3.connect(tmp_path/'conflict.db')
    sql=(FIXTURES/'legacy_inventory.sql').read_text()
    c.executescript(sql.replace('part_number TEXT UNIQUE NOT NULL','part_number TEXT UNIQUE ON CONFLICT REPLACE NOT NULL'))
    c.commit();before=schema_snapshot(c)
    with pytest.raises(MigrationError):runner().apply_migrations(c)
    assert schema_snapshot(c)==before
