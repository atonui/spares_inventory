"""Version 1: existing core schema and supported additive legacy columns. Immutable once deployed."""
VERSION = 1
NAME = "core_schema"
SQL = (
    """CREATE TABLE activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'success',
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )""",
    """CREATE TABLE equipment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipment_name TEXT NOT NULL,
            make TEXT NOT NULL,
            model TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            assigned_user_id INTEGER,
            calibration_cert_number TEXT,
            calibration_authority TEXT,
            calibration_date TEXT,
            next_calibration_date TEXT,
            status TEXT DEFAULT 'active',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_user_id) REFERENCES users (id)
        )""",
    """CREATE TABLE equipment_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipment_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            from_user_id INTEGER,
            to_user_id INTEGER,
            calibration_date TEXT,
            notes TEXT,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (equipment_id) REFERENCES equipment (id),
            FOREIGN KEY (from_user_id) REFERENCES users (id),
            FOREIGN KEY (to_user_id) REFERENCES users (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )""",
    """CREATE TABLE inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER NOT NULL,
            part_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            min_threshold INTEGER DEFAULT 0,
            work_order_id TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (store_id) REFERENCES stores (id),
            FOREIGN KEY (part_id) REFERENCES parts (id),
            FOREIGN KEY (work_order_id) REFERENCES work_orders (id),
            UNIQUE(store_id, part_id, work_order_id)
        )""",
    """CREATE TABLE movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_store_id INTEGER,
            to_store_id INTEGER,
            part_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            movement_type TEXT NOT NULL,
            work_order_id INTEGER,
            created_by INTEGER NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_store_id) REFERENCES stores (id),
            FOREIGN KEY (to_store_id) REFERENCES stores (id),
            FOREIGN KEY (part_id) REFERENCES parts (id),
            FOREIGN KEY (work_order_id) REFERENCES work_orders (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )""",
    """CREATE TABLE parts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            part_number TEXT UNIQUE NOT NULL,
            description TEXT,
            category TEXT,
            unit_cost REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
    """CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )""",
    """CREATE TABLE store_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type_code TEXT UNIQUE NOT NULL,
            type_name TEXT NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
    """CREATE TABLE stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            location TEXT,
            assigned_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_user_id) REFERENCES users (id)
        )""",
    """CREATE TABLE system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            component TEXT,
            message TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
    """CREATE TABLE system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT NOT NULL,
            description TEXT,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (updated_by) REFERENCES users (id)
        )""",
    """CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'engineer',
            territory TEXT,
            session_token TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            session_expires TIMESTAMP NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until TIMESTAMP NULL,
            last_login TIMESTAMP NULL
        , reset_token TEXT, reset_token_expires TEXT)""",
    """CREATE TABLE work_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            work_order_number TEXT UNIQUE NOT NULL,
            customer_name TEXT,
            description TEXT,
            status TEXT DEFAULT 'open',
            assigned_engineer_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_engineer_id) REFERENCES users (id)
        )""",
    """CREATE INDEX idx_activity_action
        ON activity_logs(action)""",
    """CREATE INDEX idx_activity_created
        ON activity_logs(created_at)""",
    """CREATE INDEX idx_activity_user
        ON activity_logs(user_id)""",
    """CREATE INDEX idx_sessions_token
        ON sessions(session_token)""",
    """CREATE INDEX idx_sessions_user
        ON sessions(user_id, is_active)""",
    'CREATE INDEX idx_equipment_assigned_user ON equipment(assigned_user_id)',
    'CREATE INDEX idx_equipment_next_calibration ON equipment(next_calibration_date)',
    'CREATE INDEX idx_equipment_status ON equipment(status)',
    'CREATE INDEX idx_equipment_history_equipment ON equipment_history(equipment_id)',
    'CREATE INDEX idx_store_types_active ON store_types(is_active, display_order)',

)
OPTIONAL_COLUMNS = {
    'users': {'session_expires':'TIMESTAMP NULL', 'failed_login_attempts':'INTEGER DEFAULT 0',
              'account_locked_until':'TIMESTAMP NULL','last_login':'TIMESTAMP NULL',
              'reset_token':'TEXT','reset_token_expires':'TEXT'},
    'movements': {'notes':'TEXT'},
}

def upgrade(conn):
    for statement in SQL:
        conn.execute(statement.replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ',1).replace('CREATE INDEX ', 'CREATE INDEX IF NOT EXISTS ',1))
    for table, columns in OPTIONAL_COLUMNS.items():
        existing={r[1] for r in conn.execute('PRAGMA table_info('+table+')')}
        for name, definition in columns.items():
            if name not in existing:conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')

def validate(conn):
    from .validation import validate_tables
    validate_tables(conn, include_transfer=False, allow_archive=True)
