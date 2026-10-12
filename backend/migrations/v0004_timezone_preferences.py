"""Version 4: additive business timezone and personal display preferences."""
VERSION = 4
NAME = 'timezone_preferences'
SQL = """CREATE TABLE organisation_settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    business_timezone TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1),
    updated_at TEXT NOT NULL,
    updated_by INTEGER,
    FOREIGN KEY(updated_by) REFERENCES users(id)
)"""


def upgrade(conn):
    from backend.temporal import serialize_instant, utc_now
    if 'display_timezone' not in {r[1] for r in conn.execute('PRAGMA table_info(users)')}:
        conn.execute('ALTER TABLE users ADD COLUMN display_timezone TEXT NULL')
    conn.execute(SQL.replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', 1))
    conn.execute('''INSERT INTO organisation_settings(id,business_timezone,revision,updated_at)
        SELECT 1,'Africa/Nairobi',1,? WHERE NOT EXISTS(SELECT 1 FROM organisation_settings WHERE id=1)''',
        (serialize_instant(utc_now()),))


def validate(conn):
    from .validation import validate_current
    validate_current(conn, require_timezone=True)


def validate_settings(conn):
    from .validation import MigrationError
    from backend.temporal import validate_zone, parse_api_instant
    rows = conn.execute('SELECT id,business_timezone,revision,updated_at FROM organisation_settings').fetchall()
    if len(rows)!=1 or rows[0][0]!=1 or not isinstance(rows[0][2],int) or rows[0][2]<1:
        raise MigrationError('Invalid organisation timezone settings.')
    try:
        validate_zone(rows[0][1])
        parse_api_instant(rows[0][3])
        for (zone,) in conn.execute('SELECT display_timezone FROM users WHERE display_timezone IS NOT NULL'):
            validate_zone(zone)
    except ValueError:
        raise MigrationError('Invalid saved timezone configuration.') from None
