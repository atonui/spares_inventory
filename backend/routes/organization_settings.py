"""Tenant-scoped company settings and ownership administration."""

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.database_sql import execute, is_postgres
from backend.schemas.organization_settings import OrganizationSettingsUpdate, OwnerTransferRequest
from backend.services.activity import record_activity
from backend.services.authorization import require_company_admin
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

    @router.get("/api/organization/settings")
    async def get_organization_settings(
        user_id=Depends(current_user), request: Request = None
    ):
        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=request.cookies.get("session_token") if request else None,
            readonly=True,
        ) as (conn, principal):
            require_saas_postgres(conn)
            require_company_admin(principal)
            return settings_row(conn, principal.organization_id)

    @router.put("/api/organization/settings")
    async def update_organization_settings(
        body: OrganizationSettingsUpdate,
        request: Request,
        user_id=Depends(current_user),
        csrf_valid: bool = Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, request.cookies.get("session_token")) as conn:
            require_saas_postgres(conn)
            principal = user_id
            require_company_admin(principal)
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
        with authenticated_writer(user_id, request.cookies.get("session_token")) as conn:
            require_saas_postgres(conn)
            principal: AuthenticatedPrincipal = user_id
            require_company_admin(principal)
            if principal.company_role != "owner":
                raise HTTPException(status_code=403, detail="Only the company owner can transfer ownership")
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
