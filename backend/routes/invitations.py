"""Company-managed invitations and public token acceptance."""

import hashlib
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.database_sql import is_postgres
from backend.database_sql import execute
from backend.schemas.invitations import InvitationAcceptRequest, InvitationCreateRequest
from backend.services.authorization import require_company_admin
from backend.services.invitations import (
    accept_invitation,
    cancel_invitation,
    create_invitation,
)
from backend.services.mail_payloads import validate_mail_encryption_key
from backend.services.tenant_context import set_tenant_context


def create_invitation_router(
    *, get_connection, authenticated_writer, current_user, csrf_dependency,
    password_hash, password_verify, encryption_key, frontend_url, limiter=None,
) -> APIRouter:
    router = APIRouter(tags=["invitations"])

    def invitation_actor_key(request: Request) -> str:
        token = request.cookies.get("session_token")
        if not token:
            return "invitation-unauthenticated"
        conn = get_connection()
        try:
            row = execute(
                conn,
                "SELECT user_id FROM sessions WHERE session_token = ? AND is_active = TRUE",
                (token,),
            ).fetchone()
            if row:
                return "invitation-actor:" + str(row["user_id"])
        except Exception:
            pass
        finally:
            conn.close()
        return "invitation-session:" + hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def create_company_invitation(
        body: InvitationCreateRequest,
        request: Request,
        user_id=Depends(current_user),
        csrf_valid=Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, request.cookies.get("session_token")) as conn:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Invitations require PostgreSQL")
            principal = user_id
            require_company_admin(principal)
            if body.role == "admin" and principal.company_role != "owner":
                raise HTTPException(status_code=403, detail="Only the owner can invite an admin")
            try:
                validate_mail_encryption_key(encryption_key)
            except ValueError:
                raise HTTPException(status_code=503, detail="Invitation delivery is not configured") from None
            result = create_invitation(
                conn, organization_id=principal.organization_id,
                invited_by=principal.user_id, email=str(body.email), company_role=body.role,
                frontend_url=frontend_url, encryption_key=encryption_key,
            )
            return {"success": True, "invitation": result}

    if limiter:
        create_company_invitation = limiter.limit(
            "10/hour", key_func=invitation_actor_key
        )(create_company_invitation)
    router.add_api_route("/api/users/invitations", create_company_invitation, methods=["POST"])

    @router.get("/api/users/invitations")
    async def list_company_invitations(
        request: Request, user_id=Depends(current_user),
    ):
        with authenticated_writer(user_id, request.cookies.get("session_token")) as conn:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Invitations require PostgreSQL")
            require_company_admin(user_id)
            rows = conn.execute(
                """SELECT id, email_normalized AS email, company_role AS role,
                          created_at, expires_at, accepted_at, canceled_at
                   FROM organization_invitations ORDER BY id DESC"""
            ).fetchall()
            return [dict(row) for row in rows]

    @router.delete("/api/users/invitations/{invitation_id}")
    async def cancel_company_invitation(
        invitation_id: int, request: Request,
        user_id=Depends(current_user), csrf_valid=Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, request.cookies.get("session_token")) as conn:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Invitations require PostgreSQL")
            require_company_admin(user_id)
            cancel_invitation(conn, organization_id=user_id.organization_id, invitation_id=invitation_id)
            return {"success": True}

    async def resend_company_invitation(
        invitation_id: int, request: Request,
        user_id=Depends(current_user), csrf_valid=Depends(csrf_dependency),
    ):
        with authenticated_writer(user_id, request.cookies.get("session_token")) as conn:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Invitations require PostgreSQL")
            require_company_admin(user_id)
            prior = conn.execute(
                """SELECT email_normalized, company_role FROM organization_invitations
                   WHERE id = %s AND organization_id = %s AND accepted_at IS NULL
                     AND canceled_at IS NULL FOR UPDATE""",
                (invitation_id, user_id.organization_id),
            ).fetchone()
            if prior is None:
                raise HTTPException(status_code=404, detail="Invitation not found")
            if prior["company_role"] == "admin" and user_id.company_role != "owner":
                raise HTTPException(status_code=403, detail="Only the owner can resend an admin invitation")
            cancel_invitation(conn, organization_id=user_id.organization_id, invitation_id=invitation_id)
            try:
                validate_mail_encryption_key(encryption_key)
            except ValueError:
                raise HTTPException(status_code=503, detail="Invitation delivery is not configured") from None
            invitation = create_invitation(
                conn, organization_id=user_id.organization_id, invited_by=user_id.user_id,
                email=prior["email_normalized"], company_role=prior["company_role"],
                frontend_url=frontend_url, encryption_key=encryption_key,
            )
            return {"success": True, "invitation": invitation}

    if limiter:
        resend_company_invitation = limiter.limit(
            "10/hour", key_func=invitation_actor_key
        )(resend_company_invitation)
    router.add_api_route(
        "/api/users/invitations/{invitation_id}/resend", resend_company_invitation, methods=["POST"]
    )

    async def accept_company_invitation(
        body: InvitationAcceptRequest, request: Request,
    ):
        try:
            organization_id = UUID(body.organization_id)
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(status_code=400, detail="Invitation is invalid or expired") from None
        conn = get_connection()
        try:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Invitations require PostgreSQL")
            with conn.transaction():
                set_tenant_context(conn, organization_id)
                return accept_invitation(
                    conn, organization_id=organization_id, token=body.token,
                    name=body.name, password=body.password,
                    password_hash=password_hash, password_verify=password_verify,
                )
        finally:
            conn.close()

    if limiter:
        accept_company_invitation = limiter.limit("5/minute")(accept_company_invitation)
    router.add_api_route("/api/invitations/accept", accept_company_invitation, methods=["POST"])
    return router
