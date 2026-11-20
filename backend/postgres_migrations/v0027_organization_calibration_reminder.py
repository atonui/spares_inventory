"""Version 27: calibration reminder window is a per-company setting.

The reminder window used to be one platform-wide system_settings row, which any
company admin could change for every company. Each company now owns its value.
Existing companies keep the current platform-wide value (default 30 days).
"""

VERSION = 27
NAME = "organization_calibration_reminder"

SQL = (
    """ALTER TABLE organization_settings
       ADD COLUMN calibration_reminder_days INTEGER NOT NULL DEFAULT 30
       CHECK (calibration_reminder_days BETWEEN 1 AND 365)""",
    """UPDATE organization_settings
       SET calibration_reminder_days = legacy.days
       FROM (
           SELECT setting_value::integer AS days FROM system_settings
           WHERE setting_key = 'calibration_reminder_days'
             AND setting_value ~ '^[0-9]{1,3}$'
             AND setting_value::integer BETWEEN 1 AND 365
       ) AS legacy""",
    "DELETE FROM system_settings WHERE setting_key = 'calibration_reminder_days'",
)
