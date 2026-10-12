"""Temporal inventory. Field policies verified against app history and owner provenance confirmation."""
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


# Owner confirmed app-generated timestamps only (2026-10-12). Initial schema
# b6d0531 uses UTC CURRENT_TIMESTAMP; historical auth 75af1ae uses utcnow.
# Current routes preserve those clocks. Calendar values are excluded.
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
    TemporalField(table, column, 'instant', 'utc',
                  'Current SQLite CURRENT_TIMESTAMP writer/default; migrations v0001-v0003 and route/service SQL. Owner confirmed app-generated values only; initial schema b6d0531 UTC defaults.')
    for table, columns in _SQL_INSTANTS.items() for column in columns
) + (
    TemporalField('sessions', 'expires_at', 'instant', 'utc',
                  'backend/routes/auth.py: UTC-aware clock stripped to naive UTC before isoformat; Historical auth 75af1ae UTC clocks; owner confirmed app-generated values only.'),
    TemporalField('users', 'session_expires', 'instant', None,
                  'Legacy authentication column; archiving clears it, no current expiry writer; No historical writer found; retain unverified policy and block non-null naive values at cutover.'),
    TemporalField('users', 'account_locked_until', 'instant', 'utc',
                  'backend/routes/auth.py: naive UTC clock plus lockout duration; Historical auth 75af1ae UTC clocks; owner confirmed app-generated values only.'),
    TemporalField('users', 'reset_token_expires', 'instant', 'utc',
                  'backend/routes/auth.py: naive UTC clock plus one hour; Historical auth 75af1ae UTC clocks; owner confirmed app-generated values only.'),
    TemporalField('schema_migrations', 'applied_at', 'instant', 'utc',
                  'backend/migrations/runner.py: datetime.now(timezone.utc).isoformat; explicit-offset writer.'),
    TemporalField('organisation_settings', 'updated_at', 'instant', 'utc',
                  'Migration 4 and timezone settings route use serialize_instant(utc_now()); explicit UTC Z writer.'),
    TemporalField('equipment', 'calibration_date', 'date', None,
                  'backend/routes/equipment.py and backend/schemas/equipment.py: request calendar date.'),
    TemporalField('equipment', 'next_calibration_date', 'date', None,
                  'Equipment request calendar date; due checks currently mix host local date and SQLite UTC date.'),
    TemporalField('equipment_history', 'calibration_date', 'date', None,
                  'backend/routes/equipment.py: copies request calendar date without zone conversion.'),
    TemporalField('system_settings', 'setting_value', 'instant', 'utc',
                  'backend/routes/superadmin.py: announcement JSON set_at from naive UTC isoformat.',
                  setting_key='system_announcement', json_key='set_at'),
) + tuple(
    TemporalField('system_settings', 'setting_value', 'duration', None,
                  'backend/services/security_settings.py and bootstrap settings; numeric duration, not an instant.',
                  setting_key=key)
    for key in ('lockout_duration_minutes', 'session_duration_hours', 'remember_me_duration_days', 'calibration_reminder_days')
)
