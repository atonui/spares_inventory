"""User administration routes with explicit application dependencies."""
from backend.services.session_credentials import get_request_credential
from backend.temporal_contract import instant_response
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.auth import UserResponse
from backend.schemas.users import CreateUserRequest, UpdateUserRequest
from backend.services.principals import AuthenticatedPrincipal
from backend.services.tenant_context import authenticated_database_transaction
from backend.services.authorization import require_company_admin
from backend.database_sql import execute, is_postgres
from backend.schemas.email_change import EmailChangeRequest, EmailChangeStatus, EmailChangeRequestResponse, EmailChangeCancelResponse
from fastapi.responses import JSONResponse


def create_users_router(*, get_connection, authenticated_writer, current_user,
                        csrf_dependency, user_management_guard, archive_admin_guard,
                        archive_service, password_hash, endpoint_log,
                        mutation_activity, mail_payload_encryption_key=None,
                        frontend_url="", limiter=None, security_event=None) -> APIRouter:
    """Register existing flows without owning database or audit infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    require_user_management = user_management_guard
    require_archive_admin = archive_admin_guard
    archive_record = archive_service
    hash_password = password_hash
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity
    limiter = limiter or type("NoLimiter", (), {"limit": lambda self, _rule: lambda function: function})()

    log_security_event = security_event or (lambda **_event: None)

    def log_member_revocation(actor_id, target_user_id, count, reason, request):
        if count <= 0:
            return
        log_security_event(
            event="session_revoked", outcome="success", actor_user_id=actor_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:200],
            details={"reason": reason, "target_user_id": target_user_id, "session_count": count},
        )

    def email_change_scope(conn, actor, target_user_id):
        principal = require_company_admin(actor, conn)
        target = execute(
            conn,
            """SELECT om.company_role, om.is_active, u.archived_at
               FROM organization_memberships AS om JOIN users AS u ON u.id=om.user_id
               WHERE om.organization_id=? AND om.user_id=? FOR UPDATE OF om,u""",
            (principal.organization_id, target_user_id),
        ).fetchone()
        if target is None or target["archived_at"] is not None:
            raise HTTPException(status_code=404, detail="Company member not found")
        if target["company_role"] == "owner":
            raise HTTPException(status_code=403, detail="Contact Spares Tracker support to change the company owner email")
        if principal.user_id == target_user_id:
            raise HTTPException(status_code=403, detail="Ask another company administrator to change your email address")
        if target["company_role"] == "admin" and principal.company_role != "owner":
            raise HTTPException(status_code=403, detail="Only the owner can change an administrator email")
        if not target["is_active"]:
            raise HTTPException(status_code=409, detail="Company member is inactive")
        return principal

    @router.post("/api/users/{target_user_id}/email-change-requests", status_code=202,
                 response_model=EmailChangeRequestResponse)
    @limiter.limit("3/hour")
    async def request_member_email_change(target_user_id: int, data: EmailChangeRequest,
                                          request: Request, user_id: int = Depends(get_current_user),
                                          csrf_valid: bool = Depends(verify_csrf)):
        from backend.services.email_change import EmailChangeFailure, request_email_change
        try:
            with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
                if not is_postgres(conn):
                    raise HTTPException(status_code=404, detail="Company email changes are available in SaaS mode")
                principal = email_change_scope(conn, user_id, target_user_id)
                execute(conn, "SELECT set_config('app.email_change_user_id', ?, true)", (str(target_user_id),))
                request_email_change(conn, user_id=target_user_id, proposed_email=str(data.email),
                                     frontend_url=frontend_url, encryption_key=mail_payload_encryption_key)
                _record_mutation_activity(conn, principal, "request_member_email_change", "user", {"id": target_user_id}, request)
        except EmailChangeFailure as exc:
            messages = {
                "same_email": (422, "The new email must differ from the current email."),
                "email_change_unavailable": (409, "That email address is unavailable."),
                "account_unavailable": (404, "The account is unavailable."),
            }
            status, detail = messages.get(exc.code, (400, "The email change could not be completed."))
            raise HTTPException(status_code=status, detail=detail) from None
        except ValueError:
            raise HTTPException(status_code=503, detail="Email change is unavailable") from None
        return JSONResponse(status_code=202, content={"success": True,
            "message": "If the address can be used, a confirmation email has been sent."},
            headers={"Cache-Control": "no-store"})

    @router.get("/api/users/{target_user_id}/email-change-request", response_model=EmailChangeStatus)
    async def get_member_email_change(target_user_id: int, request: Request,
                                     user_id: int = Depends(get_current_user)):
        from backend.services.email_change import get_pending_email_change
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if not is_postgres(conn):
                raise HTTPException(status_code=404, detail="Company email changes are available in SaaS mode")
            email_change_scope(conn, user_id, target_user_id)
            execute(conn, "SELECT set_config('app.email_change_user_id', ?, true)", (str(target_user_id),))
            result = get_pending_email_change(conn, user_id=target_user_id)
        return JSONResponse(content=result or {"status": "none"}, headers={"Cache-Control": "no-store"})

    @router.delete("/api/users/{target_user_id}/email-change-request", response_model=EmailChangeCancelResponse)
    @limiter.limit("10/hour")
    async def cancel_member_email_change(target_user_id: int, request: Request,
                                        user_id: int = Depends(get_current_user),
                                        csrf_valid: bool = Depends(verify_csrf)):
        from backend.services.email_change import cancel_email_change
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if not is_postgres(conn):
                raise HTTPException(status_code=404, detail="Company email changes are available in SaaS mode")
            principal = email_change_scope(conn, user_id, target_user_id)
            execute(conn, "SELECT set_config('app.email_change_user_id', ?, true)", (str(target_user_id),))
            cancel_email_change(conn, user_id=target_user_id)
            _record_mutation_activity(conn, principal, "cancel_member_email_change", "user", {"id": target_user_id}, request)
        return JSONResponse(content={"success": True, "message": "Pending email change canceled."},
                            headers={"Cache-Control": "no-store"})

    @router.post('/api/users/{target_user_id}/restore')
    async def restore_users(target_user_id: int, user_id: int = Depends(get_current_user), csrf_valid: bool = Depends(verify_csrf), request: Request = None):
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if is_postgres(conn):
                user_id = require_company_admin(user_id, conn)
                target = execute(
                    conn,
                    """SELECT company_role, is_active FROM organization_memberships
                       WHERE organization_id = ? AND user_id = ?""",
                    (user_id.organization_id, target_user_id),
                ).fetchone()
                if not target:
                    raise HTTPException(status_code=404, detail="Company member not found")
                if target["company_role"] == "owner":
                    raise HTTPException(status_code=403, detail="Transfer ownership before changing the owner")
                if target["company_role"] == "admin" and user_id.company_role != "owner":
                    raise HTTPException(status_code=403, detail="Only the owner can restore an admin")
                if target["is_active"]:
                    raise HTTPException(status_code=409, detail="Company member is already active")
                execute(
                    conn,
                    """UPDATE organization_memberships SET is_active = TRUE
                       WHERE organization_id = ? AND user_id = ? AND is_active = FALSE""",
                    (user_id.organization_id, target_user_id),
                )
                result = {"success": True, "message": "Company membership restored; sign in again to regain access"}
                _record_mutation_activity(conn, user_id, "restore_user", "user", result, request)
                return result
        return archive_record('users',target_user_id,user_id,restore=True,session_token=get_request_credential(request).value)


    @router.get("/api/users", response_model=List[UserResponse])
    @instant_response
    @log_endpoint(action="view_users", resource_type="user")
    async def get_users(include_archived: bool = False, user_id: int = Depends(get_current_user), request: Request = None):
        with authenticated_database_transaction(
            get_db_connection, principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None, readonly=True,
        ) as (conn, principal):
            if is_postgres(conn):
                principal = require_company_admin(principal, conn)
                where = "om.organization_id = ?"
                if not include_archived:
                    where += " AND om.is_active = TRUE AND u.archived_at IS NULL"
                rows = execute(conn,
                    """SELECT u.id,u.email,u.name,om.company_role AS role,u.territory,u.archived_at
                       FROM users AS u JOIN organization_memberships AS om ON om.user_id=u.id
                       WHERE """ + where + " ORDER BY u.name,u.id",
                    (principal.organization_id,),
                ).fetchall()
            else:
                require_archive_admin(conn, principal)
                where='' if include_archived else ' WHERE archived_at IS NULL'
                rows=execute(conn,'SELECT id, email, name, role, territory, archived_at FROM users'+where+' ORDER BY name').fetchall()
            return [dict(row) for row in rows]


    @router.post("/api/users")
    @log_endpoint(action="create_user", resource_type="user", transactional=True)
    async def create_user(
        request_data: CreateUserRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Create new user (admin only)"""
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if is_postgres(conn):
                user_id = require_company_admin(user_id, conn)
                raise HTTPException(status_code=410, detail="Create users with an invitation instead")
            password_hash = hash_password(request_data.password)
            cursor = conn.cursor()

            # Check if current user is admin
            try:
                require_user_management(user_id, requested_role=request_data.role, conn=conn)
            except HTTPException:
                raise

            # Check if email already exists
            cursor.execute("SELECT id FROM users WHERE email = ?", (request_data.email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Email already exists")

            # Create user
            cursor.execute(
                """
                INSERT INTO users (email, name, password_hash, role, territory)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    request_data.email,
                    request_data.name,
                    password_hash,
                    request_data.role,
                    request_data.territory,
                ),
            )


            _result = {
                "success": True,
                "message": f"User {request_data.name} created successfully",
            }

            _record_mutation_activity(conn, user_id, 'create_user', 'user', _result, request)
            return _result



    @router.put("/api/users/{target_user_id}")
    @log_endpoint(action="update_user", resource_type="user", transactional=True)
    async def update_user(
        target_user_id: int,
        request_data: UpdateUserRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update user (admin only)"""
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if is_postgres(conn):
                principal = user_id
                principal = require_company_admin(principal, conn)
                if request_data.password is not None:
                    raise HTTPException(status_code=400, detail="Password changes use the account recovery flow")
                target = execute(
                    conn,
                    """SELECT om.company_role, om.is_active
                       FROM organization_memberships AS om
                       JOIN users AS u ON u.id = om.user_id
                       WHERE om.organization_id = ? AND om.user_id = ?
                         AND u.archived_at IS NULL FOR UPDATE OF om, u""",
                    (principal.organization_id, target_user_id),
                ).fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Company member not found")
                if not target["is_active"]:
                    raise HTTPException(status_code=409, detail="Company member is inactive")
                if target["company_role"] == "owner":
                    raise HTTPException(status_code=403, detail="Use the ownership transfer operation")
                if target["company_role"] == "admin" and principal.company_role != "owner":
                    raise HTTPException(status_code=403, detail="Only the owner can manage an admin")
                if request_data.role in {"owner", "superadmin"}:
                    raise HTTPException(status_code=400, detail="This role cannot be assigned through user management")
                if request_data.role == "admin" and principal.company_role != "owner":
                    raise HTTPException(status_code=403, detail="Only the owner can assign the admin role")

                user_updates = []
                values = []
                if request_data.name is not None:
                    user_updates.append("name = ?")
                    values.append(request_data.name)
                if request_data.territory is not None:
                    user_updates.append("territory = ?")
                    values.append(request_data.territory)
                if user_updates:
                    values.append(target_user_id)
                    execute(conn, f"UPDATE users SET {', '.join(user_updates)} WHERE id = ?", values)
                if request_data.role is not None:
                    execute(
                        conn,
                        """UPDATE organization_memberships SET company_role = ?
                           WHERE organization_id = ? AND user_id = ? AND is_active = TRUE""",
                        (request_data.role, principal.organization_id, target_user_id),
                    )
                if not user_updates and request_data.role is None:
                    raise HTTPException(status_code=400, detail="No updates provided")
                result = {"success": True, "message": "Company member updated successfully"}
                _record_mutation_activity(conn, principal, "update_user", "user", result, request)
                return result

            password_hash = hash_password(request_data.password) if request_data.password is not None else None
            cursor = conn.cursor()

            # Check if current user is admin
            try:
                require_user_management(user_id, requested_role=request_data.role, target_user_id=target_user_id, conn=conn)
            except HTTPException:
                raise

            # Check if target user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (target_user_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            # Build update query dynamically
            updates = []
            values = []

            if request_data.name is not None:
                updates.append("name = ?")
                values.append(request_data.name)

            if request_data.role is not None:
                updates.append("role = ?")
                values.append(request_data.role)

            if request_data.territory is not None:
                updates.append("territory = ?")
                values.append(request_data.territory)

            if request_data.password is not None:
                updates.append("password_hash = ?")
                values.append(password_hash)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            values.append(target_user_id)

            cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)

            if request_data.password is not None:
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (target_user_id,))


            _result = {"success": True, "message": "User updated successfully"}

            _record_mutation_activity(conn, user_id, 'update_user', 'user', _result, request)
            return _result


    @router.post("/api/users/{target_user_id}/remove")
    @log_endpoint(action="remove_user", resource_type="user", transactional=True)
    async def remove_user(
        target_user_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Remove a company membership while retaining the global identity and history."""
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if is_postgres(conn):
                user_id = require_company_admin(user_id, conn)
                organization = execute(
                    conn,
                    "SELECT id FROM organizations WHERE id = ? AND is_active = TRUE FOR UPDATE",
                    (user_id.organization_id,),
                ).fetchone()
                if organization is None:
                    raise HTTPException(status_code=403, detail="Active company membership required")
                actor_membership = execute(
                    conn,
                    """SELECT company_role FROM organization_memberships
                       WHERE organization_id = ? AND user_id = ? AND is_active = TRUE FOR UPDATE""",
                    (user_id.organization_id, user_id.user_id),
                ).fetchone()
                if actor_membership is None or actor_membership["company_role"] not in {"owner", "admin"}:
                    raise HTTPException(status_code=403, detail="Company administrator access required")
                current_actor = AuthenticatedPrincipal(
                    user_id.user_id,
                    user_id.organization_id,
                    actor_membership["company_role"],
                    user_id.is_platform_admin,
                )
                target = execute(
                    conn,
                    """SELECT company_role FROM organization_memberships
                       WHERE organization_id = ? AND user_id = ? FOR UPDATE""",
                    (current_actor.organization_id, target_user_id),
                ).fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Company member not found")
                if target["company_role"] == "owner":
                    raise HTTPException(status_code=403, detail="Transfer ownership before removing the owner")
                if target["company_role"] == "admin" and current_actor.company_role != "owner":
                    raise HTTPException(status_code=403, detail="Only the owner can remove an admin")
                revoked_count = execute(conn, "UPDATE sessions SET is_active = FALSE WHERE user_id = ? AND is_active = TRUE", (target_user_id,)).rowcount
                from backend.services.platform_support import end_support_sessions
                end_support_sessions(conn, actor_user_id=current_actor.user_id, target_user_id=target_user_id,
                                     end_reason="membership_removed")
                execute(
                    conn,
                    "DELETE FROM organization_memberships WHERE organization_id = ? AND user_id = ?",
                    (current_actor.organization_id, target_user_id),
                )
                result = {"success": True, "message": "Company membership removed"}
                _record_mutation_activity(conn, current_actor, "remove_user", "user", result, request)
            else:
                raise HTTPException(status_code=501, detail="Company member removal is available in SaaS mode")
        log_member_revocation(current_actor.user_id, target_user_id, revoked_count,
                              "membership_removed", request)
        return result


    @router.delete("/api/users/{target_user_id}")
    @log_endpoint(action="archive_user", resource_type="user", transactional=True)
    async def delete_user(
        target_user_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            postgres = is_postgres(conn)
            if postgres:
                user_id = require_company_admin(user_id, conn)
                target = execute(
                    conn,
                    """SELECT company_role, is_active FROM organization_memberships
                       WHERE organization_id = ? AND user_id = ? FOR UPDATE""",
                    (user_id.organization_id, target_user_id),
                ).fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Company member not found")
                if target["company_role"] == "owner":
                    raise HTTPException(status_code=403, detail="Transfer ownership before deactivating the owner")
                if target["company_role"] == "admin" and user_id.company_role != "owner":
                    raise HTTPException(status_code=403, detail="Only the owner can deactivate an admin")
                if not target["is_active"]:
                    raise HTTPException(status_code=409, detail="Company member is already inactive")
                execute(
                    conn,
                    """UPDATE organization_memberships SET is_active = FALSE
                       WHERE organization_id = ? AND user_id = ? AND is_active = TRUE""",
                    (user_id.organization_id, target_user_id),
                )
                revoked_count = execute(conn, "UPDATE sessions SET is_active = FALSE WHERE user_id = ? AND is_active = TRUE", (target_user_id,)).rowcount
                from backend.services.platform_support import end_support_sessions
                end_support_sessions(conn, actor_user_id=user_id.user_id, target_user_id=target_user_id,
                                     end_reason="membership_deactivated")
                result = {"success": True, "message": "Company membership deactivated"}
                _record_mutation_activity(conn, user_id, "deactivate_user", "user", result, request)
        if postgres:
            log_member_revocation(user_id.user_id, target_user_id, revoked_count,
                                  "membership_deactivated", request)
            return result
        return archive_record("users", target_user_id, user_id, session_token=get_request_credential(request).value)

    return router
