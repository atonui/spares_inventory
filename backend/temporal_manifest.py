"""Temporal inventory. Current writer evidence is not historical row provenance."""
from dataclasses import dataclass


@dataclass(frozen=True)
class TemporalField:
    table: str
    column: str
    kind: str
    naive_policy: str | None
    provenance: str
    setting_key: str | None = None
    json_key: str | None = None


# All naive instant policies intentionally remain unverified until snapshot review.
_SQL_INSTANTS = {
    'activity_logs': ('created_at',),
    'equipment': ('created_at', 'updated_at'),
    'equipment_history': ('created_at',),
    'inventory': ('updated_at',),
    'movements': ('created_at',),
    'parts': ('created_at', 'archived_at'),
    'sessions': ('created_at', 'last_activity'),
    'store_types': ('created_at', 'updated_at'),
    'stores': ('created_at', 'archived_at'),
    'system_logs': ('created_at',),
    'system_settings': ('updated_at',),
    'users': ('created_at', 'last_login', 'archived_at'),
    'work_orders': ('created_at',),
    'stock_transfers': ('completed_at',),
}
TEMPORAL_FIELDS = tuple(
    TemporalField(table, column, 'instant', None,
                  'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Historical imports not verified.')
    for table, columns in _SQL_INSTANTS.items() for column in columns
) + (
    TemporalField('sessions', 'expires_at', 'instant', None,
                  'backend/routes/auth.py: UTC-aware clock stripped to naive UTC before isoformat; historical rows unverified.'),
    TemporalField('users', 'session_expires', 'instant', None,
                  'Legacy authentication column; archiving clears it, no current expiry writer; provenance unresolved.'),
    TemporalField('users', 'account_locked_until', 'instant', None,
                  'backend/routes/auth.py: naive UTC clock plus lockout duration; historical rows unverified.'),
    TemporalField('users', 'reset_token_expires', 'instant', None,
                  'backend/routes/auth.py: naive UTC clock plus one hour; historical rows unverified.'),
    TemporalField('schema_migrations', 'applied_at', 'instant', None,
                  'backend/migrations/runner.py: datetime.now(timezone.utc).isoformat; explicit-offset writer.'),
    TemporalField('organisation_settings', 'updated_at', 'instant', None,
                  'Migration 4 and timezone settings route use serialize_instant(utc_now()); explicit UTC Z writer.'),
    TemporalField('equipment', 'calibration_date', 'date', None,
                  'backend/routes/equipment.py and backend/schemas/equipment.py: request calendar date.'),
    TemporalField('equipment', 'next_calibration_date', 'date', None,
                  'Equipment request calendar date; due checks currently mix host local date and SQLite UTC date.'),
    TemporalField('equipment_history', 'calibration_date', 'date', None,
                  'backend/routes/equipment.py: copies request calendar date without zone conversion.'),
    TemporalField('system_settings', 'setting_value', 'instant', None,
                  'backend/routes/superadmin.py: announcement JSON set_at from naive UTC isoformat.',
                  setting_key='system_announcement', json_key='set_at'),
) + tuple(
    TemporalField('system_settings', 'setting_value', 'duration', None,
                  'backend/services/security_settings.py and bootstrap settings; numeric duration, not an instant.',
                  setting_key=key)
    for key in ('lockout_duration_minutes', 'session_duration_hours', 'remember_me_duration_days', 'calibration_reminder_days')
)
