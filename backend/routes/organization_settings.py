"""Tenant-scoped company settings and ownership administration."""
from backend.services.session_credentials import get_request_credential

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.database_sql import execute, is_postgres
from backend.schemas.organization_settings import MobileSessionPolicyUpdate, OrganizationSettingsUpdate, OwnerTransferRequest
from backend.services.activity import record_activity
from backend.services.authorization import require_company_admin, require_company_owner
from backend.services.principals import AuthenticatedPrincipal
from backend.services.tenant_context import authenticated_database_transaction
from backend.temporal import serialize_instant, utc_now


def create_organization_settings_router(
    *, get_connection, authenticated_writer, current_user, csrf_dependency
) -> APIRouter:
    router = APIRouter()

    def require_saas_postgres(conn):
        if not is_postgres(conn):
            raise HTTPException(status_code=503, detail="Organization administration requires PostgreSQL")

    def settings_row(conn, organization_id):
        row = execute(
            conn,
            """SELECT o.name, s.business_timezone, s.revision
               FROM organizations AS o
               JOIN organization_settings AS s ON s.organization_id = o.id
               WHERE o.id = ? AND o.is_active = TRUE""",
            (organization_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Organization settings not found")
        return {
            "name": row["name"],
            "business_timezone": row["business_timezone"],
            "revision": row["revision"],
        }

    def mobile_session_limit(conn):
        row = execute(
            conn,
            "SELECT setting_value FROM system_settings WHERE setting_key = 'mobile_session_max_duration_hours'",
        ).fetchone()
        try:
            return max(1, min(720, int(row["setting_value"]))) if row else 720
        except (TypeError, ValueError):
            return 720

    def mobile_session_policy_row(conn, organization_id):
        row = execute(
            conn,
            "SELECT mobile_session_duration_hours FROM organization_settings WHERE organization_id = ?",
            (organization_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Organization settings not found")
        return {"duration_hours": row["mobile_session_duration_hours"], "max_duration_hours": mobile_session_limit(conn)}

    @router.get("/api/organization/mobile-session-policy")
    async def get_mobile_session_policy(user_id=Depends(current_user), request: Request = None):
        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            require_saas_postgres(conn)
            principal = require_company_admin(principal, conn)
            return mobile_session_policy_row(conn, principal.organization_id)

    @router.put("/api/organization/mobile-session-policy")
    async def update_mobile_session_policy(
        body: MobileSessionPolicyUpdate,
        request: Request,
        user_id=Depends(current_user),
        csrf_valid: bool = Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, get_request_credential(request).value) as conn:
            require_saas_postgres(conn)
            principal = require_company_admin(user_id, conn)
            maximum = mobile_session_limit(conn)
            if body.duration_hours > maximum:
                raise HTTPException(status_code=400, detail=f"Duration cannot exceed the platform limit of {maximum} hours")
            execute(
                conn,
                "SELECT organization_id FROM organization_settings WHERE organization_id = ? FOR UPDATE",
                (principal.organization_id,),
            )
            execute(
                conn,
                "UPDATE organization_settings SET mobile_session_duration_hours = ?, revision = revision + 1, updated_at = ?, updated_by = ? WHERE organization_id = ?",
                (body.duration_hours, serialize_instant(utc_now()), principal.user_id, principal.organization_id),
            )
            now = serialize_instant(utc_now())
            execute(
                conn,
                """UPDATE sessions AS s SET absolute_expires_at = to_char(LEAST(s.absolute_expires_at::timestamptz, d.deadline) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                          expires_at = to_char(LEAST(s.expires_at::timestamptz, d.deadline) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                          is_active = CASE WHEN d.deadline <= ? THEN FALSE ELSE s.is_active END
                   FROM (
                       SELECT s.id AS session_id,
                              LEAST(s.created_at::timestamptz + (? * INTERVAL '1 hour'), s.absolute_expires_at::timestamptz) AS deadline
                       FROM sessions AS s
                       JOIN organization_memberships AS om ON om.user_id = s.user_id
                       WHERE om.organization_id = ? AND om.is_active = TRUE AND s.is_mobile = TRUE AND s.is_active = TRUE
                   ) AS d
                   WHERE s.id = d.session_id AND (s.absolute_expires_at::timestamptz > d.deadline OR s.expires_at::timestamptz > d.deadline)""",
                (now, body.duration_hours, principal.organization_id),
            )
            execute(
                conn,
                """UPDATE mobile_device_sessions AS m SET revoked_at = COALESCE(m.revoked_at, ?)
                   FROM sessions AS s WHERE s.id = m.session_id AND s.user_id = m.user_id
                     AND s.is_active = FALSE AND m.revoked_at IS NULL
                     AND m.user_id IN (SELECT user_id FROM organization_memberships WHERE organization_id = ?)""",
                (now, principal.organization_id),
            )
            execute(
                conn,
                """UPDATE session_refresh_credentials AS r SET expires_at = to_char(LEAST(r.expires_at::timestamptz, d.deadline) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
                   FROM (
                       SELECT s.id AS session_id,
                              LEAST(s.created_at::timestamptz + (? * INTERVAL '1 hour'), s.absolute_expires_at::timestamptz) AS deadline
                       FROM sessions AS s JOIN organization_memberships AS om ON om.user_id = s.user_id
                           WHERE om.organization_id = ? AND om.is_active = TRUE AND s.is_mobile = TRUE
                   ) AS d
                   WHERE r.session_id = d.session_id AND r.expires_at::timestamptz > d.deadline""",
                (body.duration_hours, principal.organization_id),
            )
            return mobile_session_policy_row(conn, principal.organization_id)

    @router.get("/api/organization/settings")
    async def get_organization_settings(
        user_id=Depends(current_user), request: Request = None
    ):
        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            require_saas_postgres(conn)
            principal = require_company_admin(principal, conn)
            return settings_row(conn, principal.organization_id)

    @router.put("/api/organization/settings")
    async def update_organization_settings(
        body: OrganizationSettingsUpdate,
        request: Request,
        user_id=Depends(current_user),
        csrf_valid: bool = Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, get_request_credential(request).value) as conn:
            require_saas_postgres(conn)
            principal = require_company_admin(user_id, conn)
            old = settings_row(conn, principal.organization_id)
            changed = execute(
                conn,
                """UPDATE organization_settings
                   SET business_timezone = ?, revision = revision + 1,
                       updated_at = ?, updated_by = ?
                   WHERE organization_id = ? AND revision = ?""",
                (
                    body.business_timezone,
                    serialize_instant(utc_now()),
                    principal.user_id,
                    principal.organization_id,
                    body.expected_revision,
                ),
            ).rowcount
            if changed != 1:
                raise HTTPException(status_code=409, detail="Organization settings changed. Refresh before saving.")
            execute(
                conn,
                "UPDATE organizations SET name = ? WHERE id = ? AND is_active = TRUE",
                (body.name, principal.organization_id),
            )
            record_activity(
                conn,
                user_id=principal,
                username=execute(conn, "SELECT name FROM users WHERE id = ?", (principal.user_id,)).fetchone()["name"],
                action="update_organization_settings",
                resource_type="organization",
                resource_id=1,
                details={
                    "organization_id": str(principal.organization_id),
                    "previous_name": old["name"],
                    "name": body.name,
                    "previous_business_timezone": old["business_timezone"],
                    "business_timezone": body.business_timezone,
                    "old_revision": body.expected_revision,
                    "new_revision": body.expected_revision + 1,
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            return settings_row(conn, principal.organization_id)

    @router.post("/api/organization/owner-transfer")
    async def transfer_organization_ownership(
        body: OwnerTransferRequest,
        request: Request,
        user_id=Depends(current_user),
        csrf_valid: bool = Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, get_request_credential(request).value) as conn:
            require_saas_postgres(conn)
            principal: AuthenticatedPrincipal = require_company_owner(user_id, conn)
            if body.target_user_id == principal.user_id:
                raise HTTPException(status_code=400, detail="Choose another active company member")

            execute(
                conn,
                "SELECT id FROM organizations WHERE id = ? AND is_active = TRUE FOR UPDATE",
                (principal.organization_id,),
            )
            owners = execute(
                conn,
                """SELECT user_id FROM organization_memberships
                   WHERE organization_id = ? AND company_role = 'owner' AND is_active = TRUE
                   FOR UPDATE""",
                (principal.organization_id,),
            ).fetchall()
            if len(owners) != 1 or owners[0]["user_id"] != principal.user_id:
                raise HTTPException(status_code=409, detail="Organization ownership state is inconsistent")
            target = execute(
                conn,
                """SELECT user_id FROM organization_memberships
                   WHERE organization_id = ? AND user_id = ? AND is_active = TRUE
                   FOR UPDATE""",
                (principal.organization_id, body.target_user_id),
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="Active company member not found")
            execute(
                conn,
                """UPDATE organization_memberships SET company_role = 'admin'
                   WHERE organization_id = ? AND user_id = ? AND company_role = 'owner' AND is_active = TRUE""",
                (principal.organization_id, principal.user_id),
            )
            execute(
                conn,
                """UPDATE organization_memberships SET company_role = 'owner'
                   WHERE organization_id = ? AND user_id = ? AND is_active = TRUE""",
                (principal.organization_id, body.target_user_id),
            )
            actor_name = execute(
                conn, "SELECT name FROM users WHERE id = ?", (principal.user_id,)
            ).fetchone()["name"]
            record_activity(
                conn,
                user_id=principal,
                username=actor_name,
                action="transfer_organization_ownership",
                resource_type="organization",
                resource_id=1,
                details={
                    "organization_id": str(principal.organization_id),
                    "previous_owner_user_id": principal.user_id,
                    "new_owner_user_id": body.target_user_id,
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            return {"success": True, "owner_user_id": body.target_user_id}

    return router
