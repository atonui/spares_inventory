"""Read-only compatibility checks; never repair unknown database layouts."""
import re
import sqlite3
from functools import lru_cache

class MigrationError(ValueError, RuntimeError):
    """A database cannot safely be used or upgraded by this application."""

def normalized(sql):
    return re.sub(r'\s+',' ',(sql or '').strip()).replace('IF NOT EXISTS ','').rstrip(';')

def objects(conn):
    return {r[1]:(r[0],r[2],r[3]) for r in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}

def columns(conn,table):
    return {r[1]:(r[2].upper(),r[3],r[4],r[5],r[6]) for r in conn.execute(f'PRAGMA table_xinfo("{table}")')}

def foreign_keys(conn,table):
    return sorted(tuple(r)[2:] for r in conn.execute(f'PRAGMA foreign_key_list("{table}")'))

def unique_columns(conn,table):
    return sorted(tuple(r[2] for r in conn.execute(f'PRAGMA index_info("{index[1]}")')) for index in conn.execute(f'PRAGMA index_list("{table}")') if index[2] and index[3] in ('u','pk'))

def table_options(sql):
    text=(sql or '').upper()
    return tuple(bool(re.search(pattern,text)) for pattern in
                 (r'\bAUTOINCREMENT\b',r'\bCHECK\s*\(',r'\bCOLLATE\b',r'\bDEFERRABLE\b',r'\bWITHOUT\s+ROWID\b',r'\bSTRICT\s*$',r'\bON\s+CONFLICT\b'))

def schema_signature(conn):
    result=[]
    for name,(kind,table,sql) in sorted(objects(conn).items()):
        if kind=='table':
            result.append((kind,name,tuple(sorted(columns(conn,name).items())),tuple(foreign_keys(conn,name)),
                           tuple(unique_columns(conn,name)),table_options(sql)))
        else:result.append((kind,name,table,normalized(sql)))
    return tuple(result)

@lru_cache(maxsize=2)
def reference(canonical=False):
    from . import v0001_core_schema as core,v0002_transfer_lifecycle as transfers,v0003_archiving_integrity as archives,v0004_timezone_preferences as timezones
    with sqlite3.connect(':memory:') as c:
        for module in (core,transfers,archives,timezones):module.upgrade(c)
        if canonical:
            from .v0005_canonical_instants import canonical_schema
            # Empty reference tables have no child rows or CASCADE side effects.
            for name, obj in list(objects(c).items()):
                if obj[0]=='table' and 'DEFAULT CURRENT_TIMESTAMP' in obj[2]:
                    indexes=[o[2] for o in objects(c).values() if o[0]=='index' and o[1]==name]
                    c.execute(f'DROP TABLE "{name}"')
                    c.execute(canonical_schema(obj[2]))
                    for sql in indexes:c.execute(sql)
        from . import v0006_announcement_dismissals,v0007_mobile_pairing,v0008_mobile_device_sessions,v0009_mobile_stock_adjustments
        v0006_announcement_dismissals.upgrade(c)
        v0007_mobile_pairing.upgrade(c)
        v0008_mobile_device_sessions.upgrade(c)
        v0009_mobile_stock_adjustments.upgrade(c)
        tables={n:(columns(c,n),foreign_keys(c,n),unique_columns(c,n)) for n,o in objects(c).items() if o[0]=='table'}
        return tables,objects(c)

def validate_tables(conn, *, include_transfer=True, allow_archive=False, legacy=False, require_timezone=False, require_canonical=False, require_announcements=False, require_mobile_pairing=False, require_mobile_devices=False, require_mobile_stock_adjustments=False):
    from .v0001_core_schema import OPTIONAL_COLUMNS
    expected,expected_objects=reference(require_canonical);actual_objects=objects(conn)
    actual_tables={n for n,o in actual_objects.items() if o[0]=='table' and n!='schema_migrations'}
    if legacy and not actual_tables:
        if actual_objects:raise MigrationError('Unsupported nonempty database objects')
        return
    required=set(expected) if not legacy else {'users','stores','parts','inventory','movements','work_orders'}
    if not require_announcements:required.discard('announcement_dismissals')
    if not require_mobile_pairing:required.discard('mobile_pairing_requests')
    if not require_mobile_devices:required.discard('mobile_device_sessions')
    if not require_timezone:required.discard('organisation_settings')
    if not include_transfer:required.discard('stock_transfers')
    missing=required-actual_tables
    if missing:raise MigrationError('Missing required tables: '+', '.join(sorted(missing)))
    for name,(kind,table,sql) in actual_objects.items():
        if name=='schema_migrations':continue
        if name not in expected_objects or expected_objects[name][0]!=kind:
            raise MigrationError('Unsupported schema object: '+name)
        if name=='uq_movements_created_operation' and not require_mobile_stock_adjustments:
            raise MigrationError('Unexpected mobile stock-adjustment index')
        if kind=='index' and normalized(sql)!=normalized(expected_objects[name][2]):
            raise MigrationError('Conflicting index definition: '+name)
    for table in actual_tables:
        cols,fks,unique=expected[table];actual=columns(conn,table);allowed_missing=set()
        if table_options(actual_objects[table][2])!=table_options(expected_objects[table][2]):
            raise MigrationError('Incompatible table constraints in '+table)
        if legacy:allowed_missing.update(OPTIONAL_COLUMNS.get(table,{}))
        if table=='movements' and not require_mobile_stock_adjustments:
            allowed_missing.add('client_operation_id')
        if not require_timezone:allowed_missing.add('display_timezone')
        if legacy or allow_archive:allowed_missing.add('archived_at')
        if set(cols)-set(actual)-allowed_missing or set(actual)-set(cols):raise MigrationError('Incompatible columns in '+table)
        for name,definition in actual.items():
            if definition!=cols[name]:raise MigrationError('Incompatible column '+table+'.'+name)
        if foreign_keys(conn,table)!=fks or unique_columns(conn,table)!=unique:
            raise MigrationError('Incompatible key constraints in '+table)
        # Preserve the transfer status CHECK constraint, which PRAGMA columns does not expose.
        if table in ('stock_transfers','organisation_settings') and normalized(actual_objects[table][2])!=normalized(expected_objects[table][2]):
            raise MigrationError('Incompatible transfer lifecycle definition')
    if not legacy:
        for name,(kind,table,sql) in expected_objects.items():
            if kind!='index' or (not include_transfer and table=='stock_transfers') or (allow_archive and name.startswith('idx_inventory_')) or (not require_mobile_pairing and table=='mobile_pairing_requests') or (not require_mobile_devices and table=='mobile_device_sessions') or (not require_mobile_stock_adjustments and name=='uq_movements_created_operation'):continue
            if name not in actual_objects:raise MigrationError('Missing required index: '+name)

def validate_integrity(conn, *, allow_legacy_sentinel=False):
    for violation in conn.execute('PRAGMA foreign_key_check'):
        if allow_legacy_sentinel and violation[0]=='activity_logs' and violation[2]=='users':
            row=conn.execute('SELECT user_id FROM activity_logs WHERE rowid=?',(violation[1],)).fetchone()
            if row and row[0]==0 and not conn.execute('SELECT 1 FROM users WHERE id=0').fetchone():
                continue
        raise MigrationError('Invalid foreign reference in '+str(violation[0]))
    duplicate=conn.execute('SELECT store_id,part_id,CAST(work_order_id AS NUMERIC) FROM inventory GROUP BY store_id,part_id,CAST(work_order_id AS NUMERIC) HAVING COUNT(*)>1 LIMIT 1').fetchone()
    if duplicate:raise MigrationError('Database has duplicate inventory identities; reconcile explicitly before upgrading')

def validate_legacy(conn):
    validate_tables(conn,legacy=True)

def validate_current(conn, *, require_timezone=None, require_canonical=None, canonical_fields=None, require_announcements=None, require_mobile_pairing=None, require_mobile_devices=None, require_mobile_stock_adjustments=None, require_hashed_sessions=None):
    if require_timezone is None:
        require_timezone=('schema_migrations' in objects(conn) and
                          conn.execute('SELECT 1 FROM schema_migrations WHERE version=4').fetchone() is not None)
    if require_canonical is None:
        require_canonical=('schema_migrations' in objects(conn) and
                           conn.execute('SELECT 1 FROM schema_migrations WHERE version=5').fetchone() is not None)
    if require_announcements is None:
        require_announcements=('schema_migrations' in objects(conn) and conn.execute('SELECT 1 FROM schema_migrations WHERE version=6').fetchone() is not None)
    if require_mobile_pairing is None:
        require_mobile_pairing=('schema_migrations' in objects(conn) and conn.execute('SELECT 1 FROM schema_migrations WHERE version=7').fetchone() is not None)
    if require_mobile_devices is None:
        require_mobile_devices=('schema_migrations' in objects(conn) and conn.execute('SELECT 1 FROM schema_migrations WHERE version=8').fetchone() is not None)
    if require_mobile_stock_adjustments is None:
        require_mobile_stock_adjustments=('schema_migrations' in objects(conn) and conn.execute('SELECT 1 FROM schema_migrations WHERE version=9').fetchone() is not None)
    if require_hashed_sessions is None:
        require_hashed_sessions=('schema_migrations' in objects(conn) and conn.execute('SELECT 1 FROM schema_migrations WHERE version=10').fetchone() is not None)
    validate_integrity(conn)
    validate_tables(conn,require_timezone=require_timezone,require_canonical=require_canonical,require_announcements=require_announcements,require_mobile_pairing=require_mobile_pairing,require_mobile_devices=require_mobile_devices,require_mobile_stock_adjustments=require_mobile_stock_adjustments)
    if require_announcements:
        from backend.services.announcements import load_notice
        from backend.temporal import parse_api_instant,serialize_instant
        notice=load_notice(conn)
        for key in ('starts_at','expires_at'):
            if notice and notice[key] is not None and serialize_instant(parse_api_instant(notice[key]))!=notice[key]:raise MigrationError('Noncanonical announcement schedule')
        for (value,) in conn.execute('SELECT dismissed_at FROM announcement_dismissals'):
            if serialize_instant(parse_api_instant(value))!=value:raise MigrationError('Noncanonical dismissal timestamp')
    if require_canonical:validate_canonical_instants(conn,fields=canonical_fields)
    if require_hashed_sessions:
        from .v0010_hashed_sqlite_sessions import validate as validate_hashed_sessions
        validate_hashed_sessions(conn)
    if require_timezone or 'organisation_settings' in objects(conn):
        from .v0004_timezone_preferences import validate_settings
        validate_settings(conn)


def validate_canonical_instants(conn, *, fields=None):
    """A v5 database must never claim canonical storage while containing legacy text."""
    import json
    from backend.temporal import parse_api_instant,serialize_instant
    if fields is None:
        from backend.temporal_manifest import TEMPORAL_FIELDS
        fields=TEMPORAL_FIELDS
    for field in fields:
        if field.kind!='instant':continue
        if getattr(field,'optional',False) and field.table not in objects(conn):continue
        query=f'SELECT "{field.column}" FROM "{field.table}"'
        parameters=()
        if field.setting_key:
            query+=' WHERE setting_key=?'
            parameters=(field.setting_key,)
        for (value,) in conn.execute(query,parameters):
            try:
                if field.json_key:
                    payload=json.loads(value)
                    value=payload.get(field.json_key) if getattr(field,'optional',False) else payload[field.json_key]
                if value is not None and value!=serialize_instant(parse_api_instant(value)):
                    raise ValueError
            except (ValueError,TypeError,KeyError):
                raise MigrationError(f'Noncanonical instant in {field.table}.{field.column}') from None
