"""Path-based connections and bootstrap data, without application imports."""
import sqlite3
from contextlib import closing
from pathlib import Path
from .migrations import apply_migrations

DEFAULT_SETTINGS={'calibration_reminder_days':'30','max_login_attempts':'5','lockout_duration_minutes':'15',
                  'session_duration_hours':'24','remember_me_duration_days':'30'}
SETTING_DESCRIPTIONS={'calibration_reminder_days':'Days before calibration due to send reminders',
    'max_login_attempts':'Max failed logins before lockout','lockout_duration_minutes':'Minutes account stays locked',
    'session_duration_hours':'Session lifetime in hours','remember_me_duration_days':'Remember-me lifetime in days'}
STORE_TYPES=(('office','Office/Warehouse','Main office or warehouse location',1,1),
    ('customer_site','Customer Site','Equipment at customer location',1,2),
    ('engineer','Engineer Personal','Parts assigned to field engineer',1,3),
    ('fe_consignment','FE Consignment','Field engineer consignment stock',1,4),
    ('admin','Administration','Administrative storage',1,5),('warehouse','Warehouse','General warehouse storage',1,6))

def connect_database(path, *, readonly=False, timeout=10.0):
    conn=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=timeout) if readonly else sqlite3.connect(str(path),timeout=timeout)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def bootstrap_defaults(conn,defaults):
    if conn.execute('SELECT COUNT(*) FROM store_types').fetchone()[0]==0:
        conn.executemany('INSERT INTO store_types(type_code,type_name,description,is_active,display_order) VALUES(?,?,?,?,?)',STORE_TYPES)
    values={**DEFAULT_SETTINGS,**defaults}
    existing={row[0] for row in conn.execute('SELECT setting_key FROM system_settings')}
    conn.executemany('INSERT INTO system_settings(setting_key,setting_value,description) VALUES(?,?,?)',
                     [(key,str(values[key]),SETTING_DESCRIPTIONS[key]) for key in DEFAULT_SETTINGS if key not in existing])

def initialize_database(path, *, defaults):
    with closing(connect_database(path)) as conn:
        return apply_migrations(conn,bootstrap=lambda c:bootstrap_defaults(c,defaults))
