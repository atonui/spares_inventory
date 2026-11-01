"""Authentication routes composed with explicit application dependencies."""
from contextlib import contextmanager
from backend.services.session_credentials import get_optional_request_credential, get_request_credential
from backend.temporal_contract import register_instant_comparison
from backend.temporal_contract import instant_response
from datetime import timedelta
from backend.temporal import utc_now, serialize_instant
from backend.temporal_contract import stored_instant
import secrets
import re
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from backend.schemas.auth import (
    UserProfileUpdate, PasswordChange, ForgotPasswordRequest, ResetPasswordRequest,
    UserLogin, UserResponse, NativeLoginResponse,
    NativeRefreshRequest, NativeRefreshResponse,
)
from backend.schemas.api_v1 import CsrfTokenResponse, SuccessResponse
from backend.schemas.mobile_pairing import (
    MobilePairingClaim, MobilePairingClaimResponse, MobilePairingComplete,
    MobilePairingCompleteResponse, MobilePairingCreated, MobilePairingDesktopStatus,
    MobileDeviceResponse,
)
from backend.schemas.email_change import (
    EmailChangeCancelResponse,
    EmailChangeConfirmation,
    EmailChangeConfirmationResponse,
    EmailChangeRequest,
    EmailChangeRequestResponse,
    EmailChangeStatus,
)
from backend.services.session_credentials import hash_session_credential
from backend.database_sql import execute, execute_cursor, is_postgres
from backend.security import password_needs_rehash


def register_sqlite_instant_comparison(conn):
    if not is_postgres(conn):
        register_instant_comparison(conn)


def create_auth_router(*, get_connection, authenticated_writer, stock_writer, current_user,
                       csrf_dependency, authenticated_csrf_dependency, csrf_token_factory, password_hash,
                       password_verify, security_config, reset_email,
                       queue_reset_email,
                       activity_log, endpoint_log, mutation_activity,
                       limiter, logger, cookie_secure,
                       native_refresh_encryption_key=None,
                       mail_payload_encryption_key=None, frontend_url=None,
                       authenticated_account_writer=None, security_event=None) -> APIRouter:
    """Register existing HTTP flows without owning application infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    authenticated_account_write_transaction = authenticated_account_writer or authenticated_writer
    stock_write_transaction = stock_writer
    get_current_user = current_user
    verify_csrf = authenticated_csrf_dependency
    verify_public_csrf = csrf_dependency
    generate_csrf_token = csrf_token_factory
    hash_password = password_hash
    verify_password = password_verify
    get_security_config = security_config
    send_reset_email = reset_email
    log_activity = activity_log
    log_security_event = security_event or (lambda **_event: None)
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    def authenticated_user_id(user):
        return getattr(user, "user_id", user)

    @contextmanager
    def authenticated_account_write(user, token):
        """Account lifecycle writes must work for platform-only identities too."""
        with authenticated_account_write_transaction(user, token) as scope:
            yield scope[0] if isinstance(scope, tuple) else scope

    def email_change_account_key(request: Request) -> str:
        user_id = getattr(request.state, "email_change_user_id", None)
        if user_id is not None:
            return f"email-change-user:{user_id}"
        return request.client.host if request.client else "unknown"

    def account_rate_limit(rule):
        # SlowAPI supports a route-level key function; small test limiters may not.
        try:
            return limiter.limit(rule, key_func=email_change_account_key)
        except TypeError:
            return limiter.limit(rule)

    async def email_change_user(
        request: Request, user=Depends(get_current_user),
    ):
        request.state.email_change_user_id = authenticated_user_id(user)
        return user

    def require_postgres(conn):
        if not is_postgres(conn):
            raise HTTPException(status_code=503, detail="Email change is unavailable")

    def require_mobile_pairing_postgres(conn):
        if not is_postgres(conn):
            raise HTTPException(status_code=503, detail="Mobile pairing requires the SaaS account service")

    def set_email_change_user_scope(conn, user_id):
        conn.execute(
            "SELECT set_config('app.email_change_user_id', %s, true)",
            (str(user_id),),
        )

    def set_mobile_pairing_user_scope(conn, user_id):
        if is_postgres(conn):
            conn.execute(
                "SELECT set_config('app.mobile_pairing_user_id', %s, true)",
                (str(user_id),),
            )

    def set_mobile_pairing_token_scope(conn, setting, token_hash):
        if setting not in {'app.mobile_pairing_qr_token_hash', 'app.mobile_pairing_code_hash', 'app.mobile_pairing_claim_token_hash'}:
            raise ValueError('Invalid mobile pairing scope')
        conn.execute(f"SELECT set_config('{setting}', %s, true)", (token_hash,))

    def email_change_http_error(exc):
        messages = {
            "same_email": (422, "The new email must differ from the current email."),
            "email_change_unavailable": (409, "That email address is unavailable."),
            "invalid_email_change_token": (400, "The confirmation link is invalid or expired."),
            "account_unavailable": (404, "The account is unavailable."),
        }
        status, message = messages.get(exc.code, (400, "The email change could not be completed."))
        return HTTPException(status_code=status, detail=message)

    @router.get("/api/csrf-token")
    @instant_response
    async def get_csrf_token(request: Request):
        """Get CSRF token for forms"""
        credential = get_optional_request_credential(request)
        token = generate_csrf_token(credential.value if credential else None)
        return JSONResponse(content={"csrf_token": token}, headers={"Cache-Control": "no-store"})


    @router.get("/api/profile")
    @instant_response
    async def get_profile(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get current user's profile"""
        conn = get_db_connection()
        register_sqlite_instant_comparison(conn)
        cursor = conn.cursor()

        if is_postgres(conn):
            principal = user_id
            cursor = conn.cursor()
            execute_cursor(conn, cursor,
                "SELECT id, email, name, territory, created_at, display_timezone FROM users WHERE id = %s",
                (principal.user_id,),
            )
            user = cursor.fetchone()
            conn.close()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            return dict(user) | {
                "role": principal.company_role or "platform_admin",
                "saas_mode": True,
            }
        execute_cursor(conn, cursor,
            "SELECT id, email, name, role, territory, created_at, display_timezone FROM users WHERE id = ?",
            (user_id,),
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return dict(user)


    @router.put("/api/profile")
    async def update_profile(
        profile_update: UserProfileUpdate,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update user profile (email)"""
        actor_id = authenticated_user_id(user_id)
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            # Check if user exists
            execute_cursor(conn, cursor, "SELECT id FROM users WHERE id = ?", (actor_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            if profile_update.email:
                if is_postgres(conn):
                    raise HTTPException(
                        status_code=403,
                        detail="Ask your company owner or administrator to change your email address.",
                    )
                # Check if email already exists
                execute_cursor(conn, cursor,
                    "SELECT id FROM users WHERE email = ? AND id != ?",
                    (profile_update.email, actor_id),
                )
                if cursor.fetchone():
                    raise HTTPException(status_code=400, detail="Email already in use")

                execute_cursor(conn, cursor,
                    "UPDATE users SET email = ? WHERE id = ?", (profile_update.email, actor_id)
                )


            if 'display_timezone' in profile_update.model_fields_set:
                execute_cursor(conn, cursor, 'UPDATE users SET display_timezone=? WHERE id=?',
                               (profile_update.display_timezone,actor_id))

            # Get updated user info
            execute_cursor(conn, cursor, "SELECT email,display_timezone FROM users WHERE id = ?", (actor_id,))
            user = cursor.fetchone()

            return {"message": "Profile updated successfully", "email": user["email"],
                    "display_timezone":user['display_timezone']}


    @router.post(
        "/api/profile/email-change-requests",
        status_code=202,
        response_model=EmailChangeRequestResponse,
        responses={409: {"description": "Email address is unavailable"}, 422: {"description": "Invalid request"}},
    )
    @account_rate_limit("3/hour")
    async def request_profile_email_change(
        data: EmailChangeRequest,
        request: Request,
        user=Depends(email_change_user),
        _csrf=Depends(verify_csrf),
    ):
        raise HTTPException(status_code=403, detail="Ask your company owner or administrator to change your email address.")


    @router.get(
        "/api/profile/email-change-request",
        response_model=EmailChangeStatus,
    )
    @instant_response
    async def get_profile_email_change(
        request: Request,
        user=Depends(email_change_user),
    ):
        raise HTTPException(status_code=403, detail="Ask your company owner or administrator to manage email changes.")


    @router.delete(
        "/api/profile/email-change-request",
        response_model=EmailChangeCancelResponse,
    )
    @account_rate_limit("10/hour")
    async def cancel_profile_email_change(
        request: Request,
        user=Depends(email_change_user),
        _csrf=Depends(verify_csrf),
    ):
        raise HTTPException(status_code=403, detail="Ask your company owner or administrator to cancel the pending email change.")


    @router.post(
        "/api/auth/email-change/confirm",
        response_model=EmailChangeConfirmationResponse,
        responses={400: {"description": "Invalid or expired confirmation"}, 409: {"description": "Email address unavailable"}},
    )
    @limiter.limit("5/minute")
    async def confirm_profile_email_change(
        data: EmailChangeConfirmation,
        request: Request,
        _csrf=Depends(verify_public_csrf),
    ):
        from backend.services.email_change import EmailChangeFailure, confirm_email_change
        from backend.postgres_database import postgres_transaction
        import psycopg

        conn = get_db_connection()
        try:
            require_postgres(conn)
            with postgres_transaction(conn):
                result = confirm_email_change(
                    conn,
                    token=data.token,
                    encryption_key=mail_payload_encryption_key,
                )
                from backend.services.principals import AuthenticatedPrincipal
                from backend.services.tenant_context import set_tenant_context
                set_tenant_context(conn, result["organization_id"])
                principal = AuthenticatedPrincipal(
                    result["user_id"], result["organization_id"], result["company_role"], False
                )
                _record_mutation_activity(
                    conn, principal, "confirm_email_change", "user", {"id": result["user_id"]}, request
                )
        except EmailChangeFailure as exc:
            raise email_change_http_error(exc) from None
        except psycopg.errors.UniqueViolation:
            raise HTTPException(status_code=409, detail="That email address is unavailable.") from None
        finally:
            conn.close()
        return JSONResponse(
            content={
                "success": True,
                "message": "Email address updated. A notice will be sent to the previous address.",
            },
            headers={"Cache-Control": "no-store"},
        )


    @router.post("/api/profile/change-password")
    async def change_password(
        password_data: PasswordChange,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Change user password"""
        actor_id = authenticated_user_id(user_id)
        with authenticated_account_write(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            # Get current user
            execute_cursor(conn, cursor, "SELECT password_hash FROM users WHERE id = ?", (actor_id,))
            user = cursor.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            # Verify current password using bcrypt
            if not verify_password(password_data.current_password, user["password_hash"]):
                logger.error(f"Password verification failed for user {actor_id}")
                raise HTTPException(status_code=400, detail="Current password is incorrect")

            # Validate new password
            if len(password_data.new_password) < 8:
                raise HTTPException(
                    status_code=400, detail="Password must be at least 8 characters long"
                )

            # Update password and invalidate session token
            new_hash = hash_password(password_data.new_password)

            execute_cursor(conn, cursor,
                "UPDATE users SET password_hash = ?, session_token = NULL, session_expires = NULL WHERE id = ?",
                (new_hash, actor_id),
            )

            # Deactivate all sessions for this user i.e. force logout from all devices
            execute_cursor(conn, cursor, "UPDATE sessions SET is_active = FALSE WHERE user_id = ?", (actor_id,))
            if is_postgres(conn):
                from backend.services.platform_support import end_support_sessions
                end_support_sessions(conn, actor_user_id=actor_id, end_reason="password_changed")

        log_security_event(
            event="password_changed", outcome="success", actor_user_id=actor_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:200], details={},
        )
        logger.info("Password changed successfully for user %s", actor_id)
        return {"message": "Password changed successfully. Please login again."}


    @router.post("/api/auth/revoke-other-sessions")
    async def revoke_other_sessions(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        # Revoke all sessions except the current one
        actor_id = authenticated_user_id(user_id)
        with authenticated_account_write(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            current_token = get_request_credential(request).value
            from backend.database_sql import execute, is_postgres
            current_key = hash_session_credential(current_token)
            token_column = "session_token_hash" if is_postgres(conn) else "session_token"

            if is_postgres(conn):
                revoked = conn.execute(
                    f"UPDATE sessions SET is_active = FALSE WHERE user_id = %s AND {token_column} != %s AND is_active = TRUE RETURNING id",
                    (actor_id, current_key),
                ).fetchall()
                from backend.services.platform_support import end_support_sessions
                end_support_sessions(conn, actor_user_id=actor_id, end_reason="sessions_revoked",
                                     auth_session_ids=[row["id"] for row in revoked])
                revoked_count = len(revoked)
            else:
                cursor = execute(
                    conn,
                    f"UPDATE sessions SET is_active = 0 WHERE user_id = ? AND {token_column} != ? AND is_active = 1",
                    (actor_id, current_key),
                )
                revoked_count = cursor.rowcount


            return {
                "success": True,
                "message": f"Logged out from {revoked_count} other device(s)",
            }


    @router.post("/api/forgot-password")
    @limiter.limit("3/hour")  # 3 password reset requests per hour
    async def forgot_password(
        request_data: ForgotPasswordRequest,
        csrf_valid: bool = Depends(verify_public_csrf),
        request: Request = None,
    ):
        """Initiate password reset process"""
        ip_address = request.client.host if hasattr(request, "client") else None
        user_agent = request.headers.get("user-agent", "")[:200]

        conn = get_db_connection()
        register_sqlite_instant_comparison(conn)
        cursor = conn.cursor()

        # Find user by email
        execute_cursor(conn, cursor, "SELECT id, name FROM users WHERE email = ? AND archived_at IS NULL", (request_data.email,))
        user = cursor.fetchone()

        log_security_event(
            event="password_reset_requested", outcome="success",
            actor_user_id=user["id"] if user else None,
            details={"account_match": bool(user)},
            ip_address=ip_address, user_agent=user_agent,
        )

        # Always return success to prevent email enumeration
        if not user:
            conn.close()
            return {"message": "If the email exists, a reset link has been sent"}

        user_id = user["id"]

        # Generate reset token
        token = secrets.token_urlsafe(32)
        expires_at = utc_now() + timedelta(hours=1)

        # Store token in users table
        execute_cursor(conn, cursor,
            """UPDATE users
               SET reset_token = ?, reset_token_expires = ?
               WHERE id = ? AND archived_at IS NULL""",
            (token, serialize_instant(expires_at), user_id),
        )

        if is_postgres(conn):
            try:
                queue_reset_email(conn, request_data.email, token, expires_at)
                conn.commit()
                logger.info("Password reset email queued")
            except Exception:
                conn.rollback()
                logger.error("Failed to queue password reset email")
            finally:
                conn.close()
        else:
            conn.commit()
            conn.close()
            try:
                send_reset_email(request_data.email, token)
                logger.info("Password reset email sent")
            except Exception:
                logger.error("Failed to send password reset email")
                # Don't reveal email send failure to prevent information disclosure

        return {"message": "If the email exists, a reset link has been sent"}


    @router.post("/api/reset-password")
    @limiter.limit("5/hour")  # 5 password reset attempts per hour
    async def reset_password(
        request_data: ResetPasswordRequest,
        csrf_valid: bool = Depends(verify_public_csrf),
        request: Request = None,
    ):
        """Reset password using token"""
        ip_address = request.client.host if hasattr(request, "client") else None
        user_agent = request.headers.get("user-agent", "")[:200]

        conn = get_db_connection()
        register_sqlite_instant_comparison(conn)
        cursor = conn.cursor()

        # Validate token
        execute_cursor(conn, cursor,
            """SELECT id, reset_token_expires
               FROM users
               WHERE reset_token = ? AND archived_at IS NULL""",
            (request_data.token,),
        )
        user = cursor.fetchone()

        if not user:
            # Log failed attempt
            log_security_event(
                event="password_reset_failed", outcome="failure",
                actor_user_id=None, details={"reason": "invalid_token"},
                ip_address=ip_address, user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        # Check if token expired
        expires_at = stored_instant(user["reset_token_expires"], "reset_token_expires")
        if utc_now() > expires_at:
            log_security_event(
                event="password_reset_failed", outcome="failure",
                actor_user_id=user["id"], details={"reason": "token_expired"},
                ip_address=ip_address, user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=400, detail="Token has expired")

        # Validate new password
        if len(request_data.new_password) < 8:
            log_security_event(
                event="password_reset_failed", outcome="failure",
                actor_user_id=user["id"], details={"reason": "weak_password"},
                ip_address=ip_address, user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(
                status_code=400, detail="Password must be at least 8 characters long"
            )

        # Hash before taking the write lock, then reject revoked tokens atomically.
        new_hash = hash_password(request_data.new_password)
        if utc_now() > expires_at:
            log_security_event(
                event="password_reset_failed", outcome="failure",
                actor_user_id=user["id"], details={"reason": "token_expired"},
                ip_address=ip_address, user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=400,detail='Token has expired')
        # Update password and clear token
        execute_cursor(conn, cursor,
            """UPDATE users
               SET password_hash = ?,
                   reset_token = NULL,
                   reset_token_expires = NULL,
                   session_token = NULL,
                   session_expires = NULL
               WHERE id = ? AND reset_token = ? AND archived_at IS NULL""",
            (new_hash, user["id"], request_data.token),
        )

        if cursor.rowcount != 1:
            conn.rollback()
            conn.close()
            log_security_event(
                event="password_reset_failed", outcome="failure",
                actor_user_id=user["id"], details={"reason": "invalid_token"},
                ip_address=ip_address, user_agent=user_agent,
            )
            raise HTTPException(status_code=400,detail='Invalid or expired token')

        execute_cursor(conn, cursor, "UPDATE sessions SET is_active = FALSE WHERE user_id = ?", (user["id"],))
        if is_postgres(conn):
            from backend.services.platform_support import end_support_sessions
            end_support_sessions(conn, actor_user_id=user["id"], end_reason="password_changed")

        conn.commit()
        conn.close()

        log_security_event(
            event="password_reset_completed", outcome="success",
            actor_user_id=user["id"], details={},
            ip_address=ip_address, user_agent=user_agent,
        )
        logger.info("Password reset completed")

        return {"message": "Password reset successfully"}


    @router.get("/api/verify-reset-token/{token}")
    @instant_response
    async def verify_reset_token(token: str, request: Request = None):
        """Verify if a reset token is valid"""
        ip_address = request.client.host if hasattr(request, "client") else None

        conn = get_db_connection()
        register_sqlite_instant_comparison(conn)
        cursor = conn.cursor()

        execute_cursor(conn, cursor,
            """SELECT id, name, reset_token_expires
               FROM users
               WHERE reset_token = ? AND archived_at IS NULL""",
            (token,),
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            log_activity(
                user_id=0,
                username="unknown",
                action="verify_reset_token_failed",
                details={"reason": "invalid_token"},
                status="error",
                ip_address=ip_address,
            )
            raise HTTPException(status_code=400, detail="Invalid token")

        expires_at = stored_instant(user["reset_token_expires"], "reset_token_expires")
        if utc_now() > expires_at:
            log_activity(
                user_id=user["id"],
                username=user["name"],
                action="verify_reset_token_failed",
                details={"reason": "token_expired"},
                status="error",
                ip_address=ip_address,
            )
            raise HTTPException(status_code=400, detail="Token has expired")

        return {"valid": True}


    def perform_login(user_login: UserLogin, request: Request, *, native: bool):
        from backend.database_sql import execute, is_postgres
        from backend.postgres_database import postgres_transaction

        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent", "")[:200]
        cfg = get_security_config()
        conn = get_db_connection()
        postgres = is_postgres(conn)
        if native and not postgres:
            conn.close()
            raise HTTPException(status_code=503, detail="Native login requires PostgreSQL")
        if native:
            from backend.services.native_refresh import encrypt_retry_response
            try:
                encrypt_retry_response(native_refresh_encryption_key, {}, "validation")
            except (ValueError, TypeError):
                conn.close()
                raise HTTPException(status_code=503, detail="Native refresh is unavailable") from None
        if not postgres:
            register_sqlite_instant_comparison(conn)

        if postgres:
            query = """SELECT u.id, u.email, u.name,
                              COALESCE(om.company_role, CASE WHEN pa.user_id IS NOT NULL THEN 'platform_admin' END) AS role,
                              u.territory, u.password_hash, u.failed_login_attempts,
                              u.account_locked_until
                       FROM users AS u
                       LEFT JOIN organization_memberships AS om ON om.user_id = u.id AND om.is_active = TRUE
                       LEFT JOIN platform_admins AS pa ON pa.user_id = u.id
                       WHERE u.email = ? AND u.archived_at IS NULL"""
        else:
            query = """SELECT id, email, name, role, territory, password_hash,
                              failed_login_attempts, account_locked_until
                       FROM users WHERE email = ? AND archived_at IS NULL"""
        user = execute(conn, query, (user_login.email,)).fetchone()

        if user and user["account_locked_until"]:
            lockout_time = stored_instant(user["account_locked_until"], "account_locked_until")
            if utc_now() < lockout_time:
                remaining_minutes = int((lockout_time - utc_now()).total_seconds() / 60)

                log_security_event(event="login_blocked", outcome="blocked", actor_user_id=user["id"], ip_address=ip_address, user_agent=user_agent, details={"account_match": True})
                conn.close()
                raise HTTPException(
                    status_code=423,
                    detail=f"Account locked. Try again in {remaining_minutes} minutes.",
                )

        if not user or not verify_password(user_login.password, user["password_hash"]):
            if user:
                failed_attempts = user["failed_login_attempts"] + 1
                if failed_attempts >= cfg["max_login_attempts"]:
                    lockout_until = utc_now() + timedelta(minutes=cfg["lockout_duration_minutes"])
                    execute(
                        conn,
                        "UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?",
                        (failed_attempts, serialize_instant(lockout_until), user["id"]),
                    )
                    conn.commit()
                    log_security_event(
                        event="account_locked", outcome="blocked", actor_user_id=user["id"],
                        ip_address=ip_address, user_agent=user_agent,
                        details={"account_match": True},
                    )
                    conn.close()
                    raise HTTPException(
                        status_code=423,
                        detail=("Account locked due to too many failed attempts. "
                                f"Try again in {cfg['lockout_duration_minutes']} minutes."),
                    )
                execute(
                    conn, "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
                    (failed_attempts, user["id"]),
                )
                conn.commit()

            log_security_event(event="login_failed", outcome="failure", actor_user_id=user["id"] if user else None, ip_address=ip_address, user_agent=user_agent, details={"account_match": bool(user), "reason": "invalid_credentials"})
            conn.close()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Upgrade legacy bcrypt hashes only after validating the submitted password.
        # The new format uses a SHA-256 prehash so bcrypt's 72-byte truncation no
        # longer causes different long passwords to authenticate as the same value.
        if password_needs_rehash(user["password_hash"]):
            execute(
                conn,
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(user_login.password), user["id"]),
            )
            conn.commit()

        raw_credential = secrets.token_urlsafe(32)
        raw_refresh_credential = secrets.token_urlsafe(32) if native else None
        if user_login.remember_me:
            expires = utc_now() + timedelta(days=cfg["remember_me_duration_days"])
            max_age = cfg["remember_me_duration_days"] * 24 * 60 * 60
        else:
            expires = utc_now() + timedelta(hours=cfg["session_duration_hours"])
            max_age = cfg["session_duration_hours"] * 60 * 60
        absolute_expires = expires
        if native:
            absolute_expires = expires
            if user_login.remember_me:
                absolute_expires = utc_now() + timedelta(days=cfg["remember_me_duration_days"])
            else:
                absolute_expires = utc_now() + timedelta(hours=cfg["session_duration_hours"])
            expires = min(utc_now() + timedelta(minutes=15), absolute_expires)
        conn.close()

        if postgres:
            session_conn = get_db_connection()
            try:
                with postgres_transaction(session_conn):
                    active = session_conn.execute(
                        "SELECT id FROM users WHERE id = %s AND archived_at IS NULL FOR UPDATE",
                        (user["id"],),
                    ).fetchone()
                    if active is None:
                        raise HTTPException(status_code=401, detail="Invalid credentials")
                    if native:
                        set_mobile_pairing_user_scope(session_conn, user["id"])
                        session_conn.execute(
                            "UPDATE sessions SET is_active = FALSE WHERE user_id = %s AND is_mobile = TRUE AND is_active = TRUE",
                            (user["id"],),
                        )
                        revoked_at = serialize_instant(utc_now())
                        session_conn.execute(
                            """UPDATE session_refresh_credentials AS r SET expires_at = %s,
                                      consumed_at = COALESCE(r.consumed_at, %s)
                               FROM sessions AS s WHERE s.id = r.session_id AND s.user_id = %s
                                 AND s.is_mobile = TRUE AND s.is_active = FALSE""",
                            (revoked_at, revoked_at, user["id"]),
                        )
                        session_conn.execute(
                            "UPDATE mobile_device_sessions SET revoked_at = %s WHERE user_id = %s AND revoked_at IS NULL",
                            (revoked_at, user["id"]),
                        )
                    session_id = session_conn.execute(
                        """INSERT INTO sessions (user_id, session_token_hash, expires_at,
                                                  absolute_expires_at, ip_address, user_agent, is_mobile)
                           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                        (user["id"], hash_session_credential(raw_credential),
                         serialize_instant(expires), serialize_instant(absolute_expires),
                         ip_address, user_agent, native),
                    ).fetchone()["id"]
                    session_conn.execute(
                        """UPDATE users SET failed_login_attempts = 0,
                                  account_locked_until = NULL, last_login = %s
                           WHERE id = %s""",
                        (serialize_instant(utc_now()), user["id"]),
                    )
                    from backend.services.principals import resolve_principal
                    principal = resolve_principal(session_conn, raw_credential)
                    if (principal.company_role is not None and not principal.organization_is_active
                            and not principal.is_platform_admin):
                        raise HTTPException(status_code=403, detail="Organization is suspended")
                    if native:
                        now = utc_now()
                        set_mobile_pairing_user_scope(session_conn, user["id"])
                        from backend.services.mobile_session_policy import effective_mobile_session_duration_hours
                        absolute_expires = now + timedelta(hours=effective_mobile_session_duration_hours(session_conn, principal.organization_id))
                        expires = min(now + timedelta(minutes=15), absolute_expires)
                        session_conn.execute(
                            "UPDATE sessions SET expires_at = %s, absolute_expires_at = %s WHERE id = %s",
                            (serialize_instant(expires), serialize_instant(absolute_expires), session_id),
                        )
                        session_conn.execute(
                            """INSERT INTO session_refresh_credentials
                               (session_id, token_hash, issued_at, expires_at)
                               VALUES (%s, %s, %s, %s)""",
                            (session_id, hash_session_credential(raw_refresh_credential),
                             serialize_instant(now), serialize_instant(absolute_expires)),
                        )
                    user_role = (
                        principal.company_role
                        if principal.company_role is not None and principal.organization_is_active
                        else "platform_admin"
                    )
            finally:
                session_conn.close()
        else:
            with stock_write_transaction() as session_conn:
                active = execute(
                    session_conn,
                    "SELECT 1 FROM users WHERE id = ? AND archived_at IS NULL",
                    (user["id"],),
                ).fetchone()
                if not active:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                execute(
                    session_conn,
                    """INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
                       VALUES (?, ?, ?, ?, ?)""",
                    (user["id"], hash_session_credential(raw_credential), serialize_instant(expires), ip_address, user_agent),
                )
                execute(
                    session_conn,
                    """UPDATE users SET failed_login_attempts = 0,
                              account_locked_until = NULL,
                              last_login = strftime('%Y-%m-%dT%H:%M:%f000Z','now')
                       WHERE id = ?""",
                    (user["id"],),
                )
            user_role = user["role"]

        log_security_event(event="login_succeeded", outcome="success", actor_user_id=user["id"], ip_address=ip_address, user_agent=user_agent, details={"is_mobile": native, "remember_me": user_login.remember_me})
        logger.info("Login completed for user %s", user["id"])

        response_data = {
            "success": True,
            "user": {
                "id": user["id"], "email": user["email"], "name": user["name"],
                "role": user_role, "territory": user["territory"],
            },
        }
        if native:
            response_data.update({
                "token_type": "Bearer",
                "access_token": raw_credential,
                "expires_at": serialize_instant(expires),
                "refresh_token": raw_refresh_credential,
            })
            return JSONResponse(content=response_data, headers={"Cache-Control": "no-store"})

        response = JSONResponse(content=response_data)
        response.set_cookie(
            key="session_token", value=raw_credential, httponly=True,
            secure=cookie_secure(), samesite="lax", max_age=max_age,
        )
        return response


    @router.post("/api/auth/login")
    @limiter.limit("5/minute")
    async def login(user_login: UserLogin, request: Request, csrf_valid: bool = Depends(verify_public_csrf)):
        """Authenticate a browser and set its existing HTTP-only session cookie."""
        return perform_login(user_login, request, native=False)


    @router.post(
        "/api/auth/native/login",
        response_model=NativeLoginResponse,
        responses={
            401: {"description": "Invalid credentials or inactive account"},
            403: {"description": "No active company membership or platform-admin access"},
            423: {"description": "Account temporarily locked"},
            503: {"description": "Native login requires PostgreSQL"},
        },
    )
    @limiter.limit("5/minute")
    async def native_login(user_login: UserLogin, request: Request, csrf_valid: bool = Depends(verify_public_csrf)):
        """Issue an opaque bearer session. Requires the normal CSRF token; tenant context is server-derived."""
        return perform_login(user_login, request, native=True)


    @limiter.limit("5/minute")
    async def native_refresh(
        payload: NativeRefreshRequest,
        request: Request,
        request_id: str = Header(..., alias="X-Request-ID", min_length=1, max_length=64),
    ):
        """Rotate a native credential pair with a bounded exact-request retry."""
        from backend.database_sql import is_postgres
        from backend.postgres_database import postgres_transaction
        from backend.services.native_refresh import (
            encrypt_retry_response, decrypt_retry_response, parse_native_refresh_instant,
        )

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request_id):
            raise HTTPException(status_code=422, detail="Invalid X-Request-ID")
        try:
            # Validate configuration before locking or consuming any refresh credential.
            encrypt_retry_response(native_refresh_encryption_key, {}, "validation")
        except (ValueError, TypeError):
            raise HTTPException(status_code=503, detail="Native refresh is unavailable") from None

        conn = get_db_connection()
        if not is_postgres(conn):
            conn.close()
            raise HTTPException(status_code=503, detail="Native refresh requires PostgreSQL")

        now = utc_now()
        now_text = serialize_instant(now)
        refresh_hash = hash_session_credential(payload.refresh_token)
        result = None
        error_status = None
        error_detail = "Invalid or expired refresh credential"
        try:
            with postgres_transaction(conn):
                credential = conn.execute(
                    """SELECT id, session_id, token_hash, expires_at, consumed_at, retry_request_id,
                              retry_response_ciphertext, retry_response_expires_at
                       FROM session_refresh_credentials WHERE token_hash = %s FOR UPDATE""",
                    (refresh_hash,),
                ).fetchone()
                if credential is None:
                    error_status = 401
                else:
                    session = conn.execute(
                        """SELECT id, user_id, is_active, absolute_expires_at
                           FROM sessions WHERE id = %s FOR UPDATE""",
                        (credential["session_id"],),
                    ).fetchone()
                    if session is None or not session["is_active"]:
                        error_status = 401
                    elif (now >= parse_native_refresh_instant(session["absolute_expires_at"], "absolute_expires_at")
                          or now >= parse_native_refresh_instant(credential["expires_at"], "refresh_expires_at")):
                        conn.execute("UPDATE sessions SET is_active = FALSE WHERE id = %s", (session["id"],))
                        error_status = 401
                    else:
                        account = conn.execute(
                            """SELECT u.archived_at,
                                      EXISTS (SELECT 1 FROM organization_memberships om
                                              WHERE om.user_id = u.id AND om.is_active = TRUE) AS has_membership,
                                      EXISTS (SELECT 1 FROM organization_memberships om
                                              JOIN organizations o ON o.id = om.organization_id
                                              WHERE om.user_id = u.id AND om.is_active = TRUE
                                                AND o.is_active = TRUE) AS organization_active,
                                      EXISTS (SELECT 1 FROM platform_admins pa WHERE pa.user_id = u.id) AS is_platform_admin
                               FROM users u WHERE u.id = %s""",
                            (session["user_id"],),
                        ).fetchone()
                        if (account is None or account["archived_at"] is not None
                                or not (account["has_membership"] or account["is_platform_admin"])):
                            conn.execute("UPDATE sessions SET is_active = FALSE WHERE id = %s", (session["id"],))
                            error_status = 401
                        elif account["has_membership"] and not account["organization_active"] and not account["is_platform_admin"]:
                            error_status = 403
                            error_detail = "Organization is suspended"
                        elif credential["consumed_at"] is not None:
                            retry_expires = (
                                parse_native_refresh_instant(credential["retry_response_expires_at"], "retry_response_expires_at")
                                if credential["retry_response_expires_at"] else None
                            )
                            if (credential["retry_request_id"] == request_id
                                    and retry_expires is not None and now < retry_expires
                                    and credential["retry_response_ciphertext"]):
                                try:
                                    result = decrypt_retry_response(
                                        native_refresh_encryption_key,
                                        credential["retry_response_ciphertext"], refresh_hash,
                                    )
                                except Exception:
                                    error_status = 503
                            else:
                                conn.execute("UPDATE sessions SET is_active = FALSE WHERE id = %s", (session["id"],))
                                error_status = 401
                        else:
                            absolute_expires = parse_native_refresh_instant(session["absolute_expires_at"], "absolute_expires_at")
                            access = secrets.token_urlsafe(32)
                            refresh = secrets.token_urlsafe(32)
                            access_expires = min(now + timedelta(minutes=15), absolute_expires)
                            body = {
                                "success": True,
                                "token_type": "Bearer",
                                "access_token": access,
                                "refresh_token": refresh,
                                "expires_at": serialize_instant(access_expires),
                            }
                            encrypted = encrypt_retry_response(
                                native_refresh_encryption_key, body, refresh_hash,
                            )
                            conn.execute(
                                """UPDATE session_refresh_credentials
                                   SET consumed_at = %s, retry_request_id = %s,
                                       retry_response_ciphertext = %s, retry_response_expires_at = %s
                                   WHERE id = %s""",
                                (now_text, request_id, encrypted,
                                 serialize_instant(now + timedelta(seconds=60)), credential["id"]),
                            )
                            conn.execute(
                                """INSERT INTO session_refresh_credentials
                                   (session_id, token_hash, issued_at, expires_at)
                                   VALUES (%s, %s, %s, %s)""",
                                (session["id"], hash_session_credential(refresh), now_text,
                                 serialize_instant(absolute_expires)),
                            )
                            conn.execute(
                                "UPDATE sessions SET session_token_hash = %s, expires_at = %s WHERE id = %s",
                                (hash_session_credential(access), serialize_instant(access_expires), session["id"]),
                            )
                            result = body
        finally:
            conn.close()

        if error_status:
            raise HTTPException(status_code=error_status, detail=error_detail)
        return JSONResponse(content=result, headers={"Cache-Control": "no-store", "X-Request-ID": request_id})


    router.add_api_route(
        "/api/auth/native/refresh", native_refresh, methods=["POST"],
        response_model=NativeRefreshResponse,
        responses={401: {"description": "Invalid, expired, or replayed refresh credential"},
                   403: {"description": "Organization is suspended"},
                   422: {"description": "Invalid request or missing request ID"},
                   503: {"description": "Native refresh is unavailable"}},
    )


    @router.post("/api/profile/mobile-pairings", status_code=201, response_model=MobilePairingCreated)
    @account_rate_limit("5/hour")
    async def create_mobile_pairing(
        request: Request,
        user=Depends(email_change_user),
        _csrf=Depends(verify_csrf),
    ):
        """Create a short-lived QR capability; it does not grant a mobile session."""
        from io import BytesIO
        from urllib.parse import quote

        import qrcode
        from qrcode.image.svg import SvgPathImage

        token = secrets.token_urlsafe(32)
        token_hash = hash_session_credential(token)
        code_alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        raw_pairing_code = ''.join(secrets.choice(code_alphabet) for _ in range(10))
        pairing_code = f'{raw_pairing_code[:5]}-{raw_pairing_code[5:]}'
        pairing_code_hash = hash_session_credential(raw_pairing_code)
        request_id = secrets.token_urlsafe(18)
        created_at = utc_now()
        expires_at = created_at + timedelta(minutes=2)
        qr_data = f"sparesflow://pair?token={quote(token, safe='')}"
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=7, border=3)
        qr.add_data(qr_data)
        qr.make(fit=True)
        output = BytesIO()
        qr.make_image(image_factory=SvgPathImage).save(output)
        qr_svg = output.getvalue().decode("utf-8")

        with authenticated_account_write_transaction(
            user, get_request_credential(request).value
        ) as (conn, _principal):
            require_mobile_pairing_postgres(conn)
            user_id = authenticated_user_id(user)
            set_mobile_pairing_user_scope(conn, user_id)
            conn.execute(
                """UPDATE mobile_pairing_requests SET status = 'cancelled'
                   WHERE user_id = %s AND status IN ('created', 'pending', 'approved')""",
                (user_id,),
            )
            conn.execute(
                """INSERT INTO mobile_pairing_requests
                   (request_id, user_id, qr_token_hash, pairing_code_hash, status, created_at, expires_at)
                   VALUES (%s, %s, %s, %s, 'created', %s, %s)""",
                (request_id, user_id, token_hash, pairing_code_hash,
                 serialize_instant(created_at), serialize_instant(expires_at)),
            )
        return JSONResponse(
            status_code=201,
            content={
                "request_id": request_id,
                "qr_data": qr_data,
                "qr_svg": qr_svg,
                "pairing_code": pairing_code,
                "expires_at": serialize_instant(expires_at),
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"},
        )


    @router.get("/api/profile/mobile-devices", response_model=list[MobileDeviceResponse])
    async def list_mobile_devices(request: Request, user=Depends(email_change_user)):
        with authenticated_account_write_transaction(user, get_request_credential(request).value) as (conn, _principal):
            require_mobile_pairing_postgres(conn)
            user_id = authenticated_user_id(user)
            set_mobile_pairing_user_scope(conn, user_id)
            rows = conn.execute(
                """SELECT s.id::text AS device_id, COALESCE(d.device_name, 'Mobile app') AS device_name,
                          s.created_at AS paired_at, s.last_activity
                   FROM sessions AS s
                   LEFT JOIN mobile_device_sessions AS d ON d.session_id = s.id AND d.user_id = s.user_id
                   WHERE s.user_id = %s AND s.is_mobile = TRUE AND s.is_active = TRUE
                   ORDER BY s.created_at DESC""",
                (user_id,),
            ).fetchall()
        return JSONResponse(
            content=[dict(row) for row in rows],
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )


    @router.delete("/api/profile/mobile-devices/{request_id}")
    async def revoke_mobile_device(
        request_id: str, request: Request, user=Depends(email_change_user), _csrf=Depends(verify_csrf),
    ):
        with authenticated_account_write_transaction(user, get_request_credential(request).value) as (conn, _principal):
            require_mobile_pairing_postgres(conn)
            user_id = authenticated_user_id(user)
            set_mobile_pairing_user_scope(conn, user_id)
            if not request_id.isdecimal():
                raise HTTPException(status_code=404, detail="Paired device not found")
            device = conn.execute(
                """SELECT id FROM sessions WHERE id = %s AND user_id = %s
                   AND is_mobile = TRUE AND is_active = TRUE FOR UPDATE""",
                (int(request_id), user_id),
            ).fetchone()
            if device is None:
                raise HTTPException(status_code=404, detail="Paired device not found")
            conn.execute(
                "UPDATE sessions SET is_active = FALSE WHERE id = %s AND user_id = %s",
                (device["id"], user_id),
            )
            revoked_at = serialize_instant(utc_now())
            conn.execute(
                "UPDATE session_refresh_credentials SET expires_at = %s, consumed_at = COALESCE(consumed_at, %s) WHERE session_id = %s",
                (revoked_at, revoked_at, device["id"]),
            )
            conn.execute(
                "UPDATE mobile_device_sessions SET revoked_at = %s WHERE session_id = %s AND user_id = %s AND revoked_at IS NULL",
                (revoked_at, device["id"], user_id),
            )
        return JSONResponse(content={"success": True}, headers={"Cache-Control": "no-store"})


    @router.get("/api/profile/mobile-pairings/{request_id}", response_model=MobilePairingDesktopStatus)
    @instant_response
    async def get_mobile_pairing_status(
        request_id: str,
        request: Request,
        user=Depends(email_change_user),
    ):
        with authenticated_account_write_transaction(
            user, get_request_credential(request).value
        ) as (conn, _principal):
            require_mobile_pairing_postgres(conn)
            set_mobile_pairing_user_scope(conn, authenticated_user_id(user))
            row = conn.execute(
                """SELECT status, device_name, expires_at FROM mobile_pairing_requests
                   WHERE request_id = %s AND user_id = %s""",
                (request_id, authenticated_user_id(user)),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Pairing request not found")
            status = row["status"]
            if status in {"created", "pending"} and utc_now() >= stored_instant(row["expires_at"], "expires_at"):
                status = "expired"
            return JSONResponse(
                content={"status": status, "device_name": row["device_name"], "expires_at": row["expires_at"]},
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )


    @router.post("/api/profile/mobile-pairings/{request_id}/approve")
    async def approve_mobile_pairing(
        request_id: str,
        request: Request,
        user=Depends(email_change_user),
        _csrf=Depends(verify_csrf),
    ):
        with authenticated_account_write_transaction(
            user, get_request_credential(request).value
        ) as (conn, _principal):
            require_mobile_pairing_postgres(conn)
            set_mobile_pairing_user_scope(conn, authenticated_user_id(user))
            row = conn.execute(
                """SELECT status, expires_at FROM mobile_pairing_requests
                   WHERE request_id = %s AND user_id = %s FOR UPDATE""",
                (request_id, authenticated_user_id(user)),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Pairing request not found")
            if row["status"] != "pending" or utc_now() >= stored_instant(row["expires_at"], "expires_at"):
                raise HTTPException(status_code=409, detail="This pairing request is no longer waiting for approval")
            conn.execute(
                """UPDATE mobile_pairing_requests SET status = 'approved', approved_at = %s
                   WHERE request_id = %s""",
                (serialize_instant(utc_now()), request_id),
            )
        return JSONResponse(content={"success": True}, headers={"Cache-Control": "no-store"})


    @router.post("/api/profile/mobile-pairings/{request_id}/cancel")
    async def cancel_mobile_pairing(
        request_id: str,
        request: Request,
        user=Depends(email_change_user),
        _csrf=Depends(verify_csrf),
    ):
        with authenticated_account_write_transaction(
            user, get_request_credential(request).value
        ) as (conn, _principal):
            require_mobile_pairing_postgres(conn)
            set_mobile_pairing_user_scope(conn, authenticated_user_id(user))
            result = conn.execute(
                """UPDATE mobile_pairing_requests SET status = 'cancelled'
                   WHERE request_id = %s AND user_id = %s AND status IN ('created', 'pending', 'approved')""",
                (request_id, authenticated_user_id(user)),
            )
            if result.rowcount != 1:
                raise HTTPException(status_code=409, detail="This pairing request can no longer be canceled")
        return JSONResponse(content={"success": True}, headers={"Cache-Control": "no-store"})


    @router.post("/api/v1/auth/mobile-pairing/claim", response_model=MobilePairingClaimResponse)
    @limiter.limit("10/minute")
    async def claim_mobile_pairing(payload: MobilePairingClaim, request: Request):
        from urllib.parse import parse_qs, urlsplit
        from backend.database_sql import is_postgres
        from backend.postgres_database import postgres_transaction

        if payload.pairing_code is not None:
            challenge_hash = hash_session_credential(payload.pairing_code)
            challenge_column = "pairing_code_hash"
            challenge_scope = "app.mobile_pairing_code_hash"
            invalid_detail = "This pairing code is invalid or has expired"
        else:
            try:
                parsed = urlsplit(payload.qr_data or "")
                values = parse_qs(parsed.query, strict_parsing=True)
            except ValueError:
                raise HTTPException(status_code=400, detail="This QR code is invalid or has expired") from None
            token_values = values.get("token", [])
            if (parsed.scheme != "sparesflow" or parsed.netloc != "pair" or parsed.path or parsed.fragment
                    or set(values) != {"token"} or len(token_values) != 1 or not token_values[0]):
                raise HTTPException(status_code=400, detail="This QR code is invalid or has expired")
            challenge_hash = hash_session_credential(token_values[0])
            challenge_column = "qr_token_hash"
            challenge_scope = "app.mobile_pairing_qr_token_hash"
            invalid_detail = "This QR code is invalid or has expired"
        claim_token = secrets.token_urlsafe(32)
        claim_hash = hash_session_credential(claim_token)
        now = utc_now()
        conn = get_db_connection()
        if not is_postgres(conn):
            conn.close()
            raise HTTPException(status_code=503, detail="Mobile pairing requires the SaaS account service")
        try:
            with postgres_transaction(conn):
                conn.execute("SELECT set_config('app.organization_id', '', true)")
                conn.execute("SELECT set_config('app.email_change_user_id', '', true)")
                set_mobile_pairing_token_scope(conn, challenge_scope, challenge_hash)
                row = conn.execute(
                    f"""SELECT request_id, status, expires_at FROM mobile_pairing_requests
                       WHERE {challenge_column} = %s FOR UPDATE""",
                    (challenge_hash,),
                ).fetchone()
                if (row is None or row["status"] != "created"
                        or now >= stored_instant(row["expires_at"], "expires_at")):
                    raise HTTPException(status_code=410, detail=invalid_detail)
                conn.execute(
                    """UPDATE mobile_pairing_requests
                       SET status = 'pending', device_name = %s, claimed_at = %s, claim_token_hash = %s
                       WHERE request_id = %s""",
                    (payload.device_name.strip(), serialize_instant(now), claim_hash, row["request_id"]),
                )
                expires_at = row["expires_at"]
        finally:
            conn.close()
        return JSONResponse(
            content={"claim_token": claim_token, "expires_at": expires_at},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )


    @router.post("/api/v1/auth/mobile-pairing/complete", response_model=MobilePairingCompleteResponse)
    @limiter.limit("10/minute")
    async def complete_mobile_pairing(payload: MobilePairingComplete, request: Request):
        from backend.database_sql import is_postgres
        from backend.postgres_database import postgres_transaction
        claim_hash = hash_session_credential(payload.claim_token)
        now = utc_now()
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        conn = get_db_connection()
        if not is_postgres(conn):
            conn.close()
            raise HTTPException(status_code=503, detail="Mobile pairing requires the SaaS account service")
        try:
            with postgres_transaction(conn):
                conn.execute("SELECT set_config('app.organization_id', '', true)")
                conn.execute("SELECT set_config('app.email_change_user_id', '', true)")
                set_mobile_pairing_token_scope(conn, 'app.mobile_pairing_claim_token_hash', claim_hash)
                pairing = conn.execute(
                    """SELECT request_id, user_id, status, expires_at, device_name FROM mobile_pairing_requests
                       WHERE claim_token_hash = %s FOR UPDATE""",
                    (claim_hash,),
                ).fetchone()
                if pairing is None or now >= stored_instant(pairing["expires_at"], "expires_at"):
                    raise HTTPException(status_code=410, detail="This pairing request is invalid or has expired")
                if pairing["status"] == "pending":
                    return JSONResponse(content={"status": "pending"}, headers={"Cache-Control": "no-store"})
                if pairing["status"] != "approved":
                    raise HTTPException(status_code=410, detail="This pairing request is no longer available")

                user = conn.execute(
                    "SELECT id, email, name, territory, archived_at FROM users WHERE id = %s FOR UPDATE",
                    (pairing["user_id"],),
                ).fetchone()
                if user is None or user["archived_at"] is not None:
                    raise HTTPException(status_code=401, detail="The account is unavailable")
                # The users row lock serializes native sign-in and pair completion.
                # Revoke the prior mobile session before inserting its replacement.
                set_mobile_pairing_user_scope(conn, user["id"])
                conn.execute(
                    "UPDATE sessions SET is_active = FALSE WHERE user_id = %s AND is_mobile = TRUE AND is_active = TRUE",
                    (user["id"],),
                )
                conn.execute(
                    """UPDATE session_refresh_credentials AS r SET expires_at = %s,
                              consumed_at = COALESCE(r.consumed_at, %s)
                       FROM sessions AS s WHERE s.id = r.session_id AND s.user_id = %s
                         AND s.is_mobile = TRUE AND s.is_active = FALSE""",
                    (serialize_instant(now), serialize_instant(now), user["id"]),
                )
                conn.execute(
                    "UPDATE mobile_device_sessions SET revoked_at = %s WHERE user_id = %s AND revoked_at IS NULL",
                    (serialize_instant(now), user["id"]),
                )
                session_id = conn.execute(
                    """INSERT INTO sessions (user_id, session_token_hash, expires_at,
                                              absolute_expires_at, ip_address, user_agent, is_mobile)
                       VALUES (%s, %s, %s, %s, %s, %s, TRUE) RETURNING id""",
                    (user["id"], hash_session_credential(access_token),
                     serialize_instant(now + timedelta(minutes=15)), serialize_instant(now + timedelta(hours=720)),
                     request.client.host if request.client else None,
                     request.headers.get("user-agent", "")[:512]),
                ).fetchone()["id"]
                from backend.services.principals import resolve_principal
                principal = resolve_principal(conn, access_token)
                has_active_company = principal.company_role is not None and principal.organization_is_active
                if principal.user_id != user["id"] or not (has_active_company or principal.is_platform_admin):
                    raise HTTPException(status_code=403, detail="The account has no active company access")
                from backend.services.mobile_session_policy import effective_mobile_session_duration_hours
                absolute_expires = now + timedelta(hours=effective_mobile_session_duration_hours(conn, principal.organization_id))
                access_expires = min(now + timedelta(minutes=15), absolute_expires)
                conn.execute(
                    "UPDATE sessions SET expires_at = %s, absolute_expires_at = %s WHERE id = %s",
                    (serialize_instant(access_expires), serialize_instant(absolute_expires), session_id),
                )
                conn.execute(
                    """INSERT INTO session_refresh_credentials (session_id, token_hash, issued_at, expires_at)
                       VALUES (%s, %s, %s, %s)""",
                    (session_id, hash_session_credential(refresh_token), serialize_instant(now), serialize_instant(absolute_expires)),
                )
                set_mobile_pairing_user_scope(conn, user["id"])
                conn.execute(
                    """INSERT INTO mobile_device_sessions
                       (request_id, user_id, session_id, device_name, paired_at)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (pairing["request_id"], user["id"], session_id,
                     pairing["device_name"] or "Mobile device", serialize_instant(now)),
                )
                conn.execute(
                    "UPDATE mobile_pairing_requests SET status = 'consumed', consumed_at = %s WHERE request_id = %s",
                    (serialize_instant(now), pairing["request_id"]),
                )
                conn.execute(
                    "UPDATE users SET last_login = %s WHERE id = %s",
                    (serialize_instant(now), user["id"]),
                )
                response_data = {
                    "status": "approved",
                    "success": True,
                    "token_type": "Bearer",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": serialize_instant(access_expires),
                    "user": {
                        "id": user["id"], "email": user["email"], "name": user["name"],
                        "role": principal.company_role or "platform_admin", "territory": user["territory"],
                    },
                }
        finally:
            conn.close()
        return JSONResponse(content=response_data, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


    @router.get("/api/auth/sessions")
    @instant_response
    async def get_active_sessions(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get user's active sessions"""
        from backend.database_sql import execute, is_postgres

        conn = get_db_connection()
        actor_id = authenticated_user_id(user_id)
        credential = get_request_credential(request).value
        if is_postgres(conn):
            current_key = hash_session_credential(credential)
            order_by = "last_activity DESC"
            session_column = "session_token_hash"
        else:
            register_sqlite_instant_comparison(conn)
            current_key = hash_session_credential(credential)
            order_by = "utc_instant(last_activity) DESC"
            session_column = "session_token"
        sessions = execute(
            conn,
            f"""SELECT id, created_at, last_activity, ip_address, user_agent,
                       CASE WHEN {session_column} = ? THEN 1 ELSE 0 END AS is_current
                FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY {order_by}, id DESC""",
            (current_key, actor_id),
        ).fetchall()
        conn.close()

        return [dict(session) for session in sessions]


    @router.delete("/api/auth/sessions/{session_id}")
    async def revoke_session(
        session_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Revoke a specific session"""
        actor_id = authenticated_user_id(user_id)
        with authenticated_account_write(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            # Verify session belongs to user
            if is_postgres(conn):
                revoked = conn.execute(
                    "UPDATE sessions SET is_active=FALSE WHERE id=%s AND user_id=%s RETURNING id",
                    (session_id, actor_id),
                ).fetchone()
                if revoked:
                    from backend.services.platform_support import end_support_sessions
                    end_support_sessions(conn, actor_user_id=actor_id, end_reason="sessions_revoked",
                                         auth_session_ids=[revoked["id"]])
                else:
                    raise HTTPException(status_code=404, detail="Session not found")
            else:
                execute_cursor(conn, cursor,
                    "UPDATE sessions SET is_active = 0 WHERE id = ? AND user_id = ?",
                    (session_id, actor_id),
                )
                if cursor.rowcount == 0:
                    raise HTTPException(status_code=404, detail="Session not found")


            return {"success": True, "message": "Session revoked"}


    @router.post("/api/auth/sessions/revoke-all")
    async def revoke_all_sessions(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Revoke all sessions except current"""
        actor_id = authenticated_user_id(user_id)
        with authenticated_account_write(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            current_token = get_request_credential(request).value
            from backend.database_sql import execute, is_postgres
            current_key = hash_session_credential(current_token)
            token_column = "session_token_hash" if is_postgres(conn) else "session_token"

            if is_postgres(conn):
                revoked = conn.execute(
                    f"UPDATE sessions SET is_active=FALSE WHERE user_id=%s AND {token_column} != %s AND is_active=TRUE RETURNING id",
                    (actor_id, current_key),
                ).fetchall()
                from backend.services.platform_support import end_support_sessions
                end_support_sessions(conn, actor_user_id=actor_id, end_reason="sessions_revoked",
                                     auth_session_ids=[row["id"] for row in revoked])
                revoked_count = len(revoked)
            else:
                cursor = execute(
                    conn,
                    f"UPDATE sessions SET is_active = 0 WHERE user_id = ? AND {token_column} != ?",
                    (actor_id, current_key),
                )
                revoked_count = cursor.rowcount


            return {"success": True, "revoked_count": revoked_count}


    @router.post("/api/auth/logout")
    @log_endpoint(action="logout", transactional=True)
    async def logout(user_id: int = Depends(get_current_user), request: Request = None, csrf_valid: bool = Depends(verify_csrf)):
        """Logout and clear session cookie"""
        actor_id = authenticated_user_id(user_id)
        credential = get_request_credential(request).value
        with authenticated_account_write(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()
            from backend.database_sql import execute, is_postgres
            if not is_postgres(conn):
                execute(conn, "UPDATE users SET session_token = NULL, session_expires = NULL WHERE id = ?", (actor_id,))
            token_column = "session_token_hash" if is_postgres(conn) else "session_token"
            token_value = hash_session_credential(credential)
            support_auth_id = None
            if is_postgres(conn):
                row = conn.execute(
                    f"SELECT id FROM sessions WHERE user_id=%s AND {token_column}=%s AND is_active=TRUE FOR UPDATE",
                    (actor_id, token_value),
                ).fetchone()
                support_auth_id = row["id"] if row else None
            execute(
                conn,
                f"UPDATE sessions SET is_active = FALSE WHERE user_id = ? AND {token_column} = ?",
                (actor_id, token_value),
            )
            if is_postgres(conn) and support_auth_id is not None:
                from backend.services.platform_support import end_support_sessions
                end_support_sessions(conn, actor_user_id=actor_id, end_reason="user_logout",
                                     auth_session_ids=[support_auth_id])

            response = JSONResponse(content={"success": True})
            # Browser logout clears its ambient cookie; native logout uses only
            # the explicit bearer credential and must not mutate cookie state.
            if request.url.path != "/api/v1/auth/logout":
                response.delete_cookie(key="session_token")

            _result = response

            if is_postgres(conn):
                from backend.services.platform_audit import record_user_logout
                record_user_logout(conn, actor_id)
            else:
                _record_mutation_activity(conn, actor_id, 'logout', None, _result, request)
            return _result


    @router.get("/api/me", response_model=UserResponse)
    @instant_response
    async def get_current_user_info(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get current user information"""
        conn = get_db_connection()
        try:
            from backend.database_sql import execute, is_postgres
            if is_postgres(conn):
                principal = user_id
                row = execute(
                    conn,
                    "SELECT id, email, name, territory, archived_at FROM users WHERE id = ?",
                    (principal.user_id,),
                ).fetchone()
                user = (dict(row) | {
                    "role": principal.company_role or "platform_admin",
                    "is_platform_admin": principal.is_platform_admin,
                    "saas_mode": True,
                }) if row else None
            else:
                register_sqlite_instant_comparison(conn)
                row = execute(
                    conn,
                    "SELECT id, email, name, role, territory, archived_at FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()
                user = (dict(row) | {"is_platform_admin": False, "saas_mode": False}) if row else None
        finally:
            conn.close()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return dict(user)

    async def require_native_bearer(
        request: Request,
        _user=Depends(get_current_user),
    ):
        """Require the explicit Bearer transport on protected v1 routes."""
        credential = get_request_credential(request)
        if credential.transport != "bearer":
            raise HTTPException(status_code=401, detail="Not authenticated")

    router.add_api_route(
        "/api/v1/csrf-token",
        get_csrf_token,
        methods=["GET"],
        response_model=CsrfTokenResponse,
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/auth/native/login",
        native_login,
        methods=["POST"],
        response_model=NativeLoginResponse,
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/auth/native/refresh",
        native_refresh,
        methods=["POST"],
        response_model=NativeRefreshResponse,
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/me",
        get_current_user_info,
        methods=["GET"],
        response_model=UserResponse,
        dependencies=[Depends(require_native_bearer)],
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/auth/logout",
        logout,
        methods=["POST"],
        response_model=SuccessResponse,
        dependencies=[Depends(require_native_bearer)],
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/auth/email-change/confirm",
        confirm_profile_email_change,
        methods=["POST"],
        response_model=EmailChangeConfirmationResponse,
        include_in_schema=True,
    )


    return router
