"""Version 19: persist configurable native mobile-session lifetime policy."""

VERSION = 19
NAME = "mobile_session_policy"

SQL = (
    """ALTER TABLE organization_settings
       ADD COLUMN mobile_session_duration_hours INTEGER NOT NULL DEFAULT 720
       CHECK (mobile_session_duration_hours BETWEEN 1 AND 720)""",
    """INSERT INTO system_settings(setting_key, setting_value, description)
       VALUES ('mobile_session_max_duration_hours', '720', 'Maximum mobile session lifetime in hours')
       ON CONFLICT (setting_key) DO NOTHING""",
    "ALTER TABLE sessions ADD COLUMN is_mobile BOOLEAN NOT NULL DEFAULT FALSE",
    """UPDATE sessions SET is_mobile = TRUE
       WHERE id IN (SELECT session_id FROM mobile_device_sessions)""",
    """WITH ranked AS (
           SELECT s.id, row_number() OVER (PARTITION BY s.user_id ORDER BY s.created_at DESC, s.id DESC) AS position
           FROM sessions AS s WHERE s.is_mobile = TRUE AND s.is_active = TRUE
       )
       UPDATE sessions AS s SET is_active = FALSE FROM ranked
       WHERE ranked.id = s.id AND ranked.position > 1""",
    "CREATE UNIQUE INDEX uq_sessions_one_active_mobile_per_user ON sessions(user_id) WHERE is_mobile = TRUE AND is_active = TRUE",
    "DROP POLICY mobile_device_account_scope ON mobile_device_sessions",
    """CREATE POLICY mobile_device_account_scope ON mobile_device_sessions
       USING (
           user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), '')
           OR EXISTS (
               SELECT 1 FROM organization_memberships AS om
               WHERE om.user_id = mobile_device_sessions.user_id
                 AND om.organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
                 AND om.is_active = TRUE AND om.company_role IN ('owner', 'admin')
           )
           OR (
               NULLIF(current_setting('app.platform_admin_user_id', true), '') IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM platform_admins AS pa
                   WHERE pa.user_id::TEXT = NULLIF(current_setting('app.platform_admin_user_id', true), '')
               )
           )
       )
       WITH CHECK (
           user_id::TEXT = NULLIF(current_setting('app.mobile_pairing_user_id', true), '')
           OR EXISTS (
               SELECT 1 FROM organization_memberships AS om
               WHERE om.user_id = mobile_device_sessions.user_id
                 AND om.organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
                 AND om.is_active = TRUE AND om.company_role IN ('owner', 'admin')
           )
           OR (
               NULLIF(current_setting('app.platform_admin_user_id', true), '') IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM platform_admins AS pa
                   WHERE pa.user_id::TEXT = NULLIF(current_setting('app.platform_admin_user_id', true), '')
               )
           )
       )""",
)
