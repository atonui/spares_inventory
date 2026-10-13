"""Version 5: verified UTC instants and canonical SQLite clock defaults.

The runner owns the transaction and temporarily disables FK enforcement for
rebuilds. All foreign references are checked before commit; never run standalone.
"""
import json
from dataclasses import dataclass
from backend.temporal import parse_storage_instant, serialize_instant

VERSION = 5
NAME = 'canonical_instants'
# SQLite's clock supplies milliseconds; zero padding does not invent precision.
CLOCK_SQL = "strftime('%Y-%m-%dT%H:%M:%f000Z','now')"


@dataclass(frozen=True)
class HistoricalInstant:
    """Frozen storage-field protocol, independent of the evolving app manifest."""
    table: str
    column: str
    naive_policy: str | None
    provenance: str
    setting_key: str | None = None
    json_key: str | None = None
    kind: str = 'instant'


# Snapshot of the reviewed inventory/provenance at version 5. Future application
# fields or policy changes must not alter replay of this checksummed migration.
FROZEN_FIELDS = (
    HistoricalInstant('activity_logs', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('equipment', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('equipment', 'updated_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('equipment_history', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('inventory', 'updated_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('movements', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('parts', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('parts', 'archived_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('sessions', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('sessions', 'last_activity', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('store_types', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('store_types', 'updated_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('stores', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('stores', 'archived_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('system_logs', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('system_settings', 'updated_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('users', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('users', 'last_login', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('users', 'archived_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('work_orders', 'created_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('stock_transfers', 'completed_at', 'utc',
        'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.'),
    HistoricalInstant('sessions', 'expires_at', 'utc',
        'backend/routes/auth.py: UTC-aware clock stripped to naive UTC before isoformat; Historical auth 75af1ae UTC clocks; owner confirmed app-generated values only.'),
    HistoricalInstant('users', 'session_expires', None,
        'Legacy authentication column; archiving clears it, no current expiry writer; No historical writer found; retain unverified policy and block non-null naive values at cutover.'),
    HistoricalInstant('users', 'account_locked_until', 'utc',
        'backend/routes/auth.py: naive UTC clock plus lockout duration; Historical auth 75af1ae UTC clocks; owner confirmed app-generated values only.'),
    HistoricalInstant('users', 'reset_token_expires', 'utc',
        'backend/routes/auth.py: naive UTC clock plus one hour; Historical auth 75af1ae UTC clocks; owner confirmed app-generated values only.'),
    HistoricalInstant('schema_migrations', 'applied_at', 'utc',
        'backend/migrations/runner.py: datetime.now(timezone.utc).isoformat; explicit-offset writer.'),
    HistoricalInstant('organisation_settings', 'updated_at', 'utc',
        'Migration 4 and timezone settings route use serialize_instant(utc_now()); explicit UTC Z writer.'),
    HistoricalInstant('system_settings', 'setting_value', 'utc',
        'backend/routes/superadmin.py: announcement JSON set_at from naive UTC isoformat.', setting_key='system_announcement', json_key='set_at'),
)


def canonical_schema(sql):
    return sql.replace('DEFAULT CURRENT_TIMESTAMP', 'DEFAULT (' + CLOCK_SQL + ')')


def upgrade(conn):
    from .validation import MigrationError, validate_integrity
    if not conn.in_transaction or conn.execute('PRAGMA foreign_keys').fetchone()[0]:
        raise MigrationError('Canonical rebuild requires the migration runner transaction')
    validate_integrity(conn)
    for field in FROZEN_FIELDS:
        if field.kind != 'instant':
            continue
        key = next(r[1] for r in conn.execute(f'PRAGMA table_info("{field.table}")') if r[5])
        query = f'SELECT "{key}","{field.column}" FROM "{field.table}"'
        parameters = ()
        if field.setting_key:
            query += ' WHERE setting_key=?'
            parameters = (field.setting_key,)
        for identifier, value in conn.execute(query, parameters).fetchall():
            original = value
            try:
                if field.json_key:
                    payload = json.loads(value)
                    value = payload[field.json_key]
                if value is None:
                    continue
                canonical = serialize_instant(parse_storage_instant(value, field=field))
                if field.json_key:
                    payload[field.json_key] = canonical
                    canonical = json.dumps(payload)
            except (ValueError, TypeError, KeyError):
                raise MigrationError(f'Cannot convert instant in {field.table}.{field.column}') from None
            if canonical != original:
                conn.execute(f'UPDATE "{field.table}" SET "{field.column}"=? WHERE "{key}"=?', (canonical, identifier))

    # Use the validated existing schema so supported column order is preserved.
    # No renaming parents (which would rewrite child REFERENCES clauses).
    tables = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND sql LIKE '%DEFAULT CURRENT_TIMESTAMP%'").fetchall()
    sequences = conn.execute('SELECT name,seq FROM sqlite_sequence').fetchall()
    for table, sql in tables:
        indexes = conn.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (table,)).fetchall()
        conn.execute(f'CREATE TEMP TABLE canonical_rows AS SELECT * FROM "{table}"')
        conn.execute(f'DROP TABLE "{table}"')
        conn.execute(canonical_schema(sql))
        conn.execute(f'INSERT INTO "{table}" SELECT * FROM temp.canonical_rows')
        conn.execute('DROP TABLE temp.canonical_rows')
        for (index_sql,) in indexes:
            conn.execute(index_sql)
    conn.execute('DELETE FROM sqlite_sequence')
    conn.executemany('INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)', sequences)
    validate_integrity(conn)


def validate(conn):
    from .validation import validate_current
    validate_current(conn, require_timezone=True, require_canonical=True, canonical_fields=FROZEN_FIELDS)
