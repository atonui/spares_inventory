"""PostgreSQL platform announcements and supported global security settings."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from backend.database_sql import is_postgres
from backend.schemas.superadmin import SystemAnnouncementRequest, SystemSettingUpdate
from backend.services import announcements
from backend.services.platform_audit import record_platform_audit_event
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.session_credentials import get_request_credential
from backend.temporal import serialize_instant, utc_now


SECURITY_SETTING_LIMITS = {
    "max_login_attempts": 100,
    "lockout_duration_minutes": 1440,
    "session_duration_hours": 720,
    "remember_me_duration_days": 365,
    "mobile_session_max_duration_hours": 720,
}


def create_platform_settings_router(
    *, get_connection, current_user, csrf_dependency, security_event=None,
) -> APIRouter:
    router = APIRouter(prefix="/api/platform", tags=["platform"])
    log_security_event = security_event or (lambda **_event: None)

    def require_postgres():
        conn = get_connection()
        try:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Platform administration requires PostgreSQL")
        finally:
            conn.close()

    @router.get("/announcement/manage")
    async def manage_platform_announcement(
        request: Request, response: Response, actor=Depends(current_user),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection,
            session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
            readonly=True,
        ) as (conn, _principal):
            notice = announcements.load_notice(conn)
            response.headers["Cache-Control"] = "no-store"
            return {
                "announcement": notice,
                "status": announcements.notice_status(notice, now=announcements.utc_now()) if notice else "none",
                "business_timezone": "UTC",
                "timezone_revision": 0,
            }

    @router.post("/announcement")
    async def save_platform_announcement(
        body: SystemAnnouncementRequest,
        request: Request,
        actor=Depends(current_user),
        csrf_valid=Depends(csrf_dependency),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection,
            session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            if body.timezone_revision != 0:
                raise HTTPException(409, "Platform schedule timezone changed. Reload before saving.")
            notice = announcements.notice_from_request(body, timezone="UTC")
            saved = announcements.save_notice(
                conn, notice, actor_id=principal.user_id, expected_revision=body.expected_revision,
            )
            record_platform_audit_event(
                conn, principal.user_id, "platform_announcement_saved", "success",
                details={"revision": saved["revision"], "audience": saved["audience"]},
            )
            return {"success": True, "revision": saved["revision"]}

    @router.delete("/announcement")
    async def remove_platform_announcement(
        request: Request,
        expected_revision: str | None = None,
        actor=Depends(current_user),
        csrf_valid=Depends(csrf_dependency),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection,
            session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            removed = announcements.remove_notice(conn, expected_revision=expected_revision)
            if removed is not None:
                record_platform_audit_event(
                    conn, principal.user_id, "platform_announcement_removed", "success",
                    details={"revision": removed["revision"]},
                )
            return {"success": True}

    @router.get("/security-config")
    async def get_platform_security_config(
        request: Request, response: Response, actor=Depends(current_user),
    ):
        require_postgres()
        keys = tuple(SECURITY_SETTING_LIMITS)
        placeholders = ", ".join("%s" for _ in keys)
        with authenticated_platform_transaction(
            get_connection,
            session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
            readonly=True,
        ) as (conn, _principal):
            rows = conn.execute(
                f"""SELECT setting_key, setting_value, description, updated_at
                    FROM system_settings WHERE setting_key IN ({placeholders})""",
                keys,
            ).fetchall()
            response.headers["Cache-Control"] = "no-store"
            settings = {row["setting_key"]: dict(row) for row in rows}
            settings.setdefault("mobile_session_max_duration_hours", {
                "setting_key": "mobile_session_max_duration_hours",
                "setting_value": "720",
                "description": "Maximum mobile session lifetime in hours",
                "updated_at": None,
            })
            return settings

    @router.put("/security-config/{key}")
    async def update_platform_security_config(
        key: str,
        body: SystemSettingUpdate,
        request: Request,
        actor=Depends(current_user),
        csrf_valid=Depends(csrf_dependency),
    ):
        limit = SECURITY_SETTING_LIMITS.get(key)
        if limit is None:
            raise HTTPException(status_code=400, detail=f"Unknown config key: {key}")
        try:
            value = int(body.value)
            if value < 1 or value > limit:
                raise ValueError
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail=f"Value must be an integer between 1 and {limit}") from None
        require_postgres()
        revoked_session_count = 0
        with authenticated_platform_transaction(
            get_connection,
            session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            if key == "mobile_session_max_duration_hours":
                conn.execute("SELECT set_config('app.platform_admin_user_id', %s, true)", (str(principal.user_id),))
            conn.execute(
                """INSERT INTO system_settings(setting_key, setting_value, updated_by, updated_at)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (setting_key) DO UPDATE
                   SET setting_value = EXCLUDED.setting_value,
                       updated_by = EXCLUDED.updated_by,
                       updated_at = EXCLUDED.updated_at""",
                (key, str(value), principal.user_id, serialize_instant(utc_now())),
            )
            if key == "mobile_session_max_duration_hours":
                now = serialize_instant(utc_now())
                organizations = conn.execute("SELECT id FROM organizations WHERE is_active = TRUE").fetchall()
                for organization in organizations:
                    conn.execute("SELECT set_config('app.organization_id', %s, true)", (str(organization["id"]),))
                    conn.execute(
                        """UPDATE organization_settings
                           SET mobile_session_duration_hours = LEAST(mobile_session_duration_hours, %s),
                               revision = revision + 1, updated_at = %s, updated_by = %s
                           WHERE organization_id = %s AND mobile_session_duration_hours > %s""",
                        (value, now, principal.user_id, organization["id"], value),
                    )
                conn.execute("SELECT set_config('app.organization_id', '', true)")
                sessions_to_revoke = conn.execute(
                    """SELECT s.id
                       FROM sessions AS s
                       CROSS JOIN LATERAL (
                           SELECT LEAST(
                               s.created_at::timestamptz + (%s * INTERVAL '1 hour'),
                               s.absolute_expires_at::timestamptz
                           ) AS deadline
                       ) AS d
                       WHERE s.is_mobile = TRUE AND s.is_active = TRUE
                         AND d.deadline <= %s::timestamptz
                         AND (s.absolute_expires_at::timestamptz > d.deadline
                              OR s.expires_at::timestamptz > d.deadline)
                       FOR UPDATE OF s""",
                    (value, now),
                ).fetchall()
                revoked_session_count = len(sessions_to_revoke)
                conn.execute(
                    """UPDATE sessions AS s SET absolute_expires_at = to_char(LEAST(s.absolute_expires_at::timestamptz, d.deadline) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                              expires_at = to_char(LEAST(s.expires_at::timestamptz, d.deadline) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                              is_active = CASE WHEN d.deadline <= %s THEN FALSE ELSE s.is_active END
                       FROM (
                           SELECT s.id AS session_id,
                                  LEAST(s.created_at::timestamptz + (%s * INTERVAL '1 hour'), s.absolute_expires_at::timestamptz) AS deadline
                           FROM sessions AS s WHERE s.is_mobile = TRUE
                       ) AS d
                       WHERE s.id = d.session_id AND (s.absolute_expires_at::timestamptz > d.deadline OR s.expires_at::timestamptz > d.deadline)""",
                    (now, value),
                )
                conn.execute(
                    """UPDATE session_refresh_credentials AS r SET expires_at = to_char(LEAST(r.expires_at::timestamptz, d.deadline) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
                       FROM (
                           SELECT s.id AS session_id,
                                  LEAST(s.created_at::timestamptz + (%s * INTERVAL '1 hour'), s.absolute_expires_at::timestamptz) AS deadline
                           FROM sessions AS s WHERE s.is_mobile = TRUE AND s.is_active = TRUE
                       ) AS d
                       WHERE r.session_id = d.session_id AND r.expires_at::timestamptz > d.deadline""",
                    (value,),
                )
                conn.execute(
                    """UPDATE mobile_device_sessions AS m SET revoked_at = COALESCE(m.revoked_at, %s)
                       FROM sessions AS s WHERE s.id = m.session_id AND s.is_active = FALSE
                         AND m.revoked_at IS NULL""",
                    (now,),
                )
            record_platform_audit_event(
                conn, principal.user_id, "global_security_setting_changed", "success",
                details={"key": key, "value": value},
            )
            result = {"success": True, "key": key, "value": value}

        if revoked_session_count:
            log_security_event(
                event="session_revoked",
                outcome="success",
                actor_user_id=principal.user_id,
                details={
                    "is_mobile": True,
                    "reason": "mobile_duration_policy",
                    "session_count": revoked_session_count,
                },
            )
        return result

    return router
