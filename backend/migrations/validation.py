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

@lru_cache(maxsize=1)
def reference():
    from . import v0001_core_schema as core,v0002_transfer_lifecycle as transfers,v0003_archiving_integrity as archives
    with sqlite3.connect(':memory:') as c:
        for module in (core,transfers,archives):module.upgrade(c)
        tables={n:(columns(c,n),foreign_keys(c,n),unique_columns(c,n)) for n,o in objects(c).items() if o[0]=='table'}
        return tables,objects(c)

def validate_tables(conn, *, include_transfer=True, allow_archive=False, legacy=False):
    from .v0001_core_schema import OPTIONAL_COLUMNS
    expected,expected_objects=reference();actual_objects=objects(conn)
    actual_tables={n for n,o in actual_objects.items() if o[0]=='table' and n!='schema_migrations'}
    if legacy and not actual_tables:
        if actual_objects:raise MigrationError('Unsupported nonempty database objects')
        return
    required=set(expected) if not legacy else {'users','stores','parts','inventory','movements','work_orders'}
    if not include_transfer:required.discard('stock_transfers')
    missing=required-actual_tables
    if missing:raise MigrationError('Missing required tables: '+', '.join(sorted(missing)))
    for name,(kind,table,sql) in actual_objects.items():
        if name=='schema_migrations':continue
        if name not in expected_objects or expected_objects[name][0]!=kind:
            raise MigrationError('Unsupported schema object: '+name)
        if kind=='index' and normalized(sql)!=normalized(expected_objects[name][2]):
            raise MigrationError('Conflicting index definition: '+name)
    for table in actual_tables:
        cols,fks,unique=expected[table];actual=columns(conn,table);allowed_missing=set()
        if table_options(actual_objects[table][2])!=table_options(expected_objects[table][2]):
            raise MigrationError('Incompatible table constraints in '+table)
        if legacy:allowed_missing.update(OPTIONAL_COLUMNS.get(table,{}))
        if legacy or allow_archive:allowed_missing.add('archived_at')
        if set(cols)-set(actual)-allowed_missing or set(actual)-set(cols):raise MigrationError('Incompatible columns in '+table)
        for name,definition in actual.items():
            if definition!=cols[name]:raise MigrationError('Incompatible column '+table+'.'+name)
        if foreign_keys(conn,table)!=fks or unique_columns(conn,table)!=unique:
            raise MigrationError('Incompatible key constraints in '+table)
        # Preserve the transfer status CHECK constraint, which PRAGMA columns does not expose.
        if table=='stock_transfers' and normalized(actual_objects[table][2])!=normalized(expected_objects[table][2]):
            raise MigrationError('Incompatible transfer lifecycle definition')
    if not legacy:
        for name,(kind,table,sql) in expected_objects.items():
            if kind!='index' or (not include_transfer and table=='stock_transfers') or (allow_archive and name.startswith('idx_inventory_')):continue
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

def validate_current(conn):
    validate_integrity(conn)
    validate_tables(conn)
