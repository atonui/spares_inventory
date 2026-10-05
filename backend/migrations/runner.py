"""All pending schema changes and their ledger entries commit together."""
import sqlite3
from dataclasses import dataclass
from datetime import datetime,timezone
from . import registry
from .validation import MigrationError,validate_current,validate_legacy,objects,columns,normalized,validate_integrity

LEDGER_SQL='''CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
)'''

@dataclass(frozen=True)
class MigrationStatus:
    current_version: int
    target_version: int
    applied: tuple[int,...]
    pending: tuple[int,...]
    legacy: bool

def migration_status(conn):
    catalog=objects(conn)
    legacy='schema_migrations' not in catalog
    versions=()
    if not legacy:
        expected={'version':('INTEGER',0,None,1,0),'name':('TEXT',1,None,0,0),'checksum':('TEXT',1,None,0,0),'applied_at':('TEXT',1,None,0,0)}
        if (catalog['schema_migrations'][0]!='table' or columns(conn,'schema_migrations')!=expected
            or normalized(catalog['schema_migrations'][2])!=normalized(LEDGER_SQL)):
            raise MigrationError('Incompatible schema_migrations ledger definition')
        records=list(conn.execute('SELECT version,name,checksum FROM schema_migrations ORDER BY version'))
        versions=tuple(r[0] for r in records)
        known=registry.MIGRATIONS
        if versions!=tuple(m.version for m in known[:len(records)]):
            raise MigrationError('Unknown, newer or incomplete migration history')
        for row,m in zip(records,known):
            if row[1]!=m.name or row[2]!=m.checksum:raise MigrationError(f'Migration {m.version} name/checksum does not match this application')
    return MigrationStatus(versions[-1] if versions else 0,registry.MIGRATIONS[-1].version,versions,
                           tuple(m.version for m in registry.MIGRATIONS if m.version not in versions),legacy)

def check_database(conn):
    status=migration_status(conn)
    if status.pending:
        validate_legacy(conn)
        if objects(conn):validate_integrity(conn,allow_legacy_sentinel=status.legacy)
    else:validate_current(conn)
    return status

def apply_migrations(conn, *, bootstrap=None):
    if conn.in_transaction:raise MigrationError('Migration runner requires a connection without an active transaction')
    conn.execute('PRAGMA foreign_keys=ON')
    if conn.execute('PRAGMA foreign_keys').fetchone()[0]!=1:raise MigrationError('Foreign-key enforcement could not be enabled')
    step='startup validation'
    try:
        conn.execute('BEGIN IMMEDIATE')
        status=migration_status(conn)
        if status.pending:validate_legacy(conn)
        else:validate_current(conn)
        if status.legacy:conn.execute(LEDGER_SQL)
        for migration in registry.MIGRATIONS:
            if migration.version not in status.pending:continue
            step=f'migration {migration.version} ({migration.name})'
            migration.upgrade(conn)
            migration.validate(conn)
            conn.execute('INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)',
                         (migration.version,migration.name,migration.checksum,datetime.now(timezone.utc).isoformat()))
        step='bootstrap defaults'
        if bootstrap:bootstrap(conn)
        step='final schema validation'
        validate_current(conn)
        result=migration_status(conn)
        conn.commit()
        return result
    except Exception as error:
        conn.rollback()
        if isinstance(error,MigrationError):raise
        raise MigrationError(f'{step} failed: {error}') from error
