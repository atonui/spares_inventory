"""Platform-level tenant provisioning and global administrator management."""
from backend.services.session_credentials import get_request_credential

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.database_sql import is_postgres
from backend.schemas.invitations import CompanyRoleUpdateRequest, OrganizationCreateRequest
from backend.schemas.platform_organizations import PlatformOrganizationStatusRequest
from backend.services.invitations import create_organization_with_owner_invitation
from backend.services.mail_payloads import validate_mail_encryption_key
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.platform_audit import record_platform_audit_event


def create_platform_organizations_router(
    *, get_connection, current_user, csrf_dependency,
    encryption_key, frontend_url,
) -> APIRouter:
    router = APIRouter(prefix="/api/platform", tags=["platform"])

    def require_postgres():
        conn = get_connection()
        try:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Platform administration requires PostgreSQL")
        finally:
            conn.close()

    @router.get("/dashboard")
    async def platform_dashboard(
        request: Request, actor=Depends(current_user),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor), readonly=True,
        ) as (conn, _principal):
            organizations = conn.execute(
                "SELECT count(*) AS total, count(*) FILTER (WHERE is_active) AS active FROM organizations"
            ).fetchone()
            identities = conn.execute(
                "SELECT count(*) AS total FROM users WHERE archived_at IS NULL"
            ).fetchone()["total"]
            admins = conn.execute("SELECT count(*) AS total FROM platform_admins").fetchone()["total"]
            mail = conn.execute(
                "SELECT pending, failed FROM platform_mail_outbox_counts"
            ).fetchone()
            return {
                "organizations_total": organizations["total"],
                "organizations_active": organizations["active"],
                "identities_active": identities,
                "platform_admins": admins,
                "mail_pending": mail["pending"],
                "mail_failed": mail["failed"],
            }

    @router.get("/organizations")
    async def list_organizations(
        request: Request, actor=Depends(current_user),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor), readonly=True,
        ) as (conn, _principal):
            rows = conn.execute(
                "SELECT id, name, slug, is_active, created_at FROM organizations ORDER BY name, id"
            ).fetchall()
            return [dict(row) for row in rows]

    @router.get("/admins")
    async def list_platform_admins(
        request: Request, actor=Depends(current_user),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor), readonly=True,
        ) as (conn, _principal):
            rows = conn.execute(
                """SELECT u.id, u.email, u.name FROM platform_admins pa
                   JOIN users u ON u.id = pa.user_id WHERE u.archived_at IS NULL
                   ORDER BY u.name, u.id"""
            ).fetchall()
            return [dict(row) for row in rows]

    @router.post("/organizations")
    async def provision_organization(
        body: OrganizationCreateRequest,
        request: Request,
        user_id=Depends(current_user),
        csrf_valid=Depends(csrf_dependency),
    ):
        require_postgres()
        try:
            with authenticated_platform_transaction(
                get_connection, session_token=get_request_credential(request).value,
                expected_user_id=getattr(user_id, "user_id", user_id),
            ) as (conn, principal):
                try:
                    validate_mail_encryption_key(encryption_key)
                except ValueError:
                    raise HTTPException(status_code=503, detail="Invitation delivery is not configured")
                return {"success": True, "organization": create_organization_with_owner_invitation(
                    conn, name=body.name, slug=body.slug, owner_email=str(body.owner_email),
                    actor_user_id=principal.user_id, frontend_url=frontend_url,
                    encryption_key=encryption_key,
                )}
        except HTTPException:
            raise
        except Exception as exc:
            # Avoid exposing uniqueness/database/provider details in platform APIs.
            from psycopg import IntegrityError
            if isinstance(exc, IntegrityError):
                raise HTTPException(status_code=409, detail="Organization name or slug is already in use") from None
            raise

    @router.put("/organizations/{organization_id}/members/{user_id}/role")
    async def change_company_role(
        organization_id: str, user_id: int, body: CompanyRoleUpdateRequest,
        request: Request, actor=Depends(current_user), csrf_valid=Depends(csrf_dependency),
    ):
        from uuid import UUID
        try:
            org_id = UUID(organization_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=404, detail="Organization member not found") from None
        require_postgres()
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            membership = conn.execute(
                """SELECT company_role FROM organization_memberships
                   WHERE organization_id = %s AND user_id = %s FOR UPDATE""",
                (org_id, user_id),
            ).fetchone()
            if membership is None:
                raise HTTPException(status_code=404, detail="Organization member not found")
            if membership["company_role"] == "owner":
                raise HTTPException(status_code=409, detail="Transfer ownership in company settings first")
            conn.execute(
                "UPDATE organization_memberships SET company_role = %s WHERE organization_id = %s AND user_id = %s",
                (body.role, org_id, user_id),
            )
            record_platform_audit_event(
                conn, principal.user_id, "company_role_changed", "success", org_id,
                {"target_user_id": user_id, "role": body.role},
            )
            return {"success": True}

    @router.put("/organizations/{organization_id}/status")
    async def set_organization_status(
        organization_id: str, body: PlatformOrganizationStatusRequest,
        request: Request, actor=Depends(current_user), csrf_valid=Depends(csrf_dependency),
    ):
        from uuid import UUID
        try:
            org_id = UUID(organization_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=404, detail="Organization not found") from None
        require_postgres()
        desired_active = body.action == "reactivate"
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            organization = conn.execute(
                "SELECT is_active FROM organizations WHERE id = %s FOR UPDATE", (org_id,)
            ).fetchone()
            if organization is None:
                raise HTTPException(status_code=404, detail="Organization not found")
            current_active = bool(organization["is_active"])
            if current_active == desired_active:
                return {"success": True, "is_active": current_active, "changed": False}
            conn.execute(
                "UPDATE organizations SET is_active = %s WHERE id = %s",
                (desired_active, org_id),
            )
            event = "organization_reactivated" if desired_active else "organization_suspended"
            record_platform_audit_event(
                conn, principal.user_id, event, "success", org_id, {"reason": body.reason},
            )
            return {"success": True, "is_active": desired_active, "changed": True}

    @router.put("/admins/{target_user_id}")
    async def grant_platform_admin(
        target_user_id: int, request: Request,
        actor=Depends(current_user), csrf_valid=Depends(csrf_dependency),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            target = conn.execute(
                "SELECT id FROM users WHERE id = %s AND archived_at IS NULL", (target_user_id,)
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="User not found")
            conn.execute(
                "INSERT INTO platform_admins (user_id) VALUES (%s) ON CONFLICT (user_id) DO NOTHING",
                (target_user_id,),
            )
            record_platform_audit_event(
                conn, principal.user_id, "platform_admin_granted", "success",
                details={"target_user_id": target_user_id},
            )
            return {"success": True}

    @router.delete("/admins/{target_user_id}")
    async def revoke_platform_admin(
        target_user_id: int, request: Request,
        actor=Depends(current_user), csrf_valid=Depends(csrf_dependency),
    ):
        require_postgres()
        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
        ) as (conn, principal):
            conn.execute("LOCK TABLE platform_admins IN EXCLUSIVE MODE")
            active_admins = conn.execute(
                """SELECT count(*) AS n FROM platform_admins pa JOIN users u ON u.id = pa.user_id
                   WHERE u.archived_at IS NULL"""
            ).fetchone()["n"]
            target = conn.execute(
                "SELECT 1 FROM platform_admins WHERE user_id = %s FOR UPDATE", (target_user_id,)
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="Platform administrator not found")
            if active_admins <= 1:
                raise HTTPException(status_code=409, detail="The last platform administrator cannot be removed")
            conn.execute("DELETE FROM platform_admins WHERE user_id = %s", (target_user_id,))
            record_platform_audit_event(
                conn, principal.user_id, "platform_admin_revoked", "success",
                details={"target_user_id": target_user_id},
            )
            return {"success": True}

    return router
