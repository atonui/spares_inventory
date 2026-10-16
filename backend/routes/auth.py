"""Authentication routes composed with explicit application dependencies."""
from backend.services.session_credentials import get_request_credential
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
from backend.services.session_credentials import hash_session_credential
from backend.database_sql import execute, execute_cursor, is_postgres


def register_sqlite_instant_comparison(conn):
    if not is_postgres(conn):
        register_instant_comparison(conn)


def create_auth_router(*, get_connection, authenticated_writer, stock_writer, current_user,
                       csrf_dependency, authenticated_csrf_dependency, csrf_token_factory, password_hash,
                       password_verify, security_config, reset_email,
                       activity_log, endpoint_log, mutation_activity,
                       limiter, logger, cookie_secure,
                       native_refresh_encryption_key=None) -> APIRouter:
    """Register existing HTTP flows without owning application infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
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
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    def authenticated_user_id(user):
        return getattr(user, "user_id", user)

    @router.get("/api/csrf-token")
    @instant_response
    async def get_csrf_token():
        """Get CSRF token for forms"""
        token = generate_csrf_token()
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


    @router.post("/api/profile/change-password")
    async def change_password(
        password_data: PasswordChange,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Change user password"""
        actor_id = authenticated_user_id(user_id)
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
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
            execute_cursor(conn, cursor, "UPDATE sessions SET is_active = 0 WHERE user_id = ?", (actor_id,))


            logger.info(f"Password changed successfully for user {actor_id}")

            return {"message": "Password changed successfully. Please login again."}


    @router.post("/api/auth/revoke-other-sessions")
    async def revoke_other_sessions(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        # Revoke all sessions except the current one
        actor_id = authenticated_user_id(user_id)
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            current_token = get_request_credential(request).value
            from backend.database_sql import execute, is_postgres
            current_key = hash_session_credential(current_token) if is_postgres(conn) else current_token
            token_column = "session_token_hash" if is_postgres(conn) else "session_token"

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

        # Log the attempt (even if email doesn't exist, for security monitoring)
        if user:
            user_id = user["id"]
            user_name = user["name"]
        else:
            user_id = 0
            user_name = request_data.email

        log_activity(
            user_id=user_id,
            username=user_name,
            action="password_reset_request",
            details={"email": request_data.email},
            status="success",
            ip_address=ip_address,
            user_agent=user_agent,
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

        conn.commit()
        conn.close()

        # Send email
        try:
            send_reset_email(request_data.email, token)
            logger.info(f"Password reset email sent to {request_data.email}")
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
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
            """SELECT id, name, email, reset_token_expires
               FROM users
               WHERE reset_token = ? AND archived_at IS NULL""",
            (request_data.token,),
        )
        user = cursor.fetchone()

        if not user:
            # Log failed attempt
            log_activity(
                user_id=0,
                username="unknown",
                action="password_reset_failed",
                details={"reason": "invalid_token"},
                status="error",
                error_message="Invalid or expired token",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        # Check if token expired
        expires_at = stored_instant(user["reset_token_expires"], "reset_token_expires")
        if utc_now() > expires_at:
            log_activity(
                user_id=user["id"],
                username=user["name"],
                action="password_reset_failed",
                details={"reason": "token_expired", "email": user["email"]},
                status="error",
                error_message="Token has expired",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=400, detail="Token has expired")

        # Validate new password
        if len(request_data.new_password) < 8:
            log_activity(
                user_id=user["id"],
                username=user["name"],
                action="password_reset_failed",
                details={"reason": "weak_password", "email": user["email"]},
                status="error",
                error_message="Password too short",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(
                status_code=400, detail="Password must be at least 8 characters long"
            )

        # Hash before taking the write lock, then reject revoked tokens atomically.
        new_hash = hash_password(request_data.new_password)
        if utc_now() > expires_at:
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
            raise HTTPException(status_code=400,detail='Invalid or expired token')

        execute_cursor(conn, cursor, "UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user["id"],))

        conn.commit()
        conn.close()

        # Log successful password reset
        log_activity(
            user_id=user["id"],
            username=user["name"],
            action="password_reset_success",
            details={"email": user["email"]},
            status="success",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info(
            f"Password successfully reset for user {user['name']} ({user['email']})"
        )

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
                log_activity(
                    user_id=user["id"], username=user["name"], action="login_blocked",
                    status="error", error_message="Account locked", ip_address=ip_address,
                    user_agent=user_agent,
                )
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
                    log_activity(
                        user_id=user["id"], username=user["name"], action="account_locked",
                        status="error", error_message="Too many failed attempts",
                        ip_address=ip_address, user_agent=user_agent,
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
            log_activity(
                user_id=user["id"] if user else 0, username=user_login.email,
                action="login_failed", status="error", error_message="Invalid credentials",
                ip_address=ip_address, user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=401, detail="Invalid credentials")

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
                    session_id = session_conn.execute(
                        """INSERT INTO sessions (user_id, session_token_hash, expires_at,
                                                  absolute_expires_at, ip_address, user_agent)
                           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                        (user["id"], hash_session_credential(raw_credential),
                         serialize_instant(expires), serialize_instant(absolute_expires),
                         ip_address, user_agent),
                    ).fetchone()["id"]
                    if native:
                        session_conn.execute(
                            """INSERT INTO session_refresh_credentials
                               (session_id, token_hash, issued_at, expires_at)
                               VALUES (%s, %s, %s, %s)""",
                            (session_id, hash_session_credential(raw_refresh_credential),
                             serialize_instant(utc_now()), serialize_instant(absolute_expires)),
                        )
                    session_conn.execute(
                        """UPDATE users SET failed_login_attempts = 0,
                                  account_locked_until = NULL, last_login = %s
                           WHERE id = %s""",
                        (serialize_instant(utc_now()), user["id"]),
                    )
                    from backend.services.principals import resolve_principal
                    principal = resolve_principal(session_conn, raw_credential)
                    user_role = principal.company_role or "platform_admin"
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
                    (user["id"], raw_credential, serialize_instant(expires), ip_address, user_agent),
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

        log_activity(
            user_id=user["id"], username=user["name"], action="login",
            details={"role": user_role, "remember_me": user_login.remember_me},
            ip_address=ip_address, user_agent=user_agent,
        )
        logger.info("User %s (%s) logged in from %s", user["name"], user["id"], ip_address)

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
        try:
            with postgres_transaction(conn):
                credential = conn.execute(
                    """SELECT id, session_id, token_hash, consumed_at, retry_request_id,
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
                    elif now >= parse_native_refresh_instant(session["absolute_expires_at"], "absolute_expires_at"):
                        conn.execute("UPDATE sessions SET is_active = FALSE WHERE id = %s", (session["id"],))
                        error_status = 401
                    else:
                        account = conn.execute(
                            """SELECT u.archived_at,
                                      EXISTS (SELECT 1 FROM organization_memberships om
                                              WHERE om.user_id = u.id AND om.is_active = TRUE) AS has_membership,
                                      EXISTS (SELECT 1 FROM platform_admins pa WHERE pa.user_id = u.id) AS is_platform_admin
                               FROM users u WHERE u.id = %s""",
                            (session["user_id"],),
                        ).fetchone()
                        if (account is None or account["archived_at"] is not None
                                or not (account["has_membership"] or account["is_platform_admin"])):
                            conn.execute("UPDATE sessions SET is_active = FALSE WHERE id = %s", (session["id"],))
                            error_status = 401
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
            raise HTTPException(status_code=error_status, detail="Invalid or expired refresh credential")
        return JSONResponse(content=result, headers={"Cache-Control": "no-store", "X-Request-ID": request_id})


    router.add_api_route(
        "/api/auth/native/refresh", native_refresh, methods=["POST"],
        response_model=NativeRefreshResponse,
        responses={401: {"description": "Invalid, expired, or replayed refresh credential"},
                   422: {"description": "Invalid request or missing request ID"},
                   503: {"description": "Native refresh is unavailable"}},
    )


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
            current_key = credential
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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            # Verify session belongs to user
            execute_cursor(conn, cursor,
                """
                UPDATE sessions
                SET is_active = 0
                WHERE id = ? AND user_id = ?
            """,
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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            current_token = get_request_credential(request).value
            from backend.database_sql import execute, is_postgres
            current_key = hash_session_credential(current_token) if is_postgres(conn) else current_token
            token_column = "session_token_hash" if is_postgres(conn) else "session_token"

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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()
            from backend.database_sql import execute, is_postgres
            if not is_postgres(conn):
                execute(conn, "UPDATE users SET session_token = NULL, session_expires = NULL WHERE id = ?", (actor_id,))
            token_column = "session_token_hash" if is_postgres(conn) else "session_token"
            token_value = hash_session_credential(credential) if is_postgres(conn) else credential
            execute(
                conn,
                f"UPDATE sessions SET is_active = 0 WHERE user_id = ? AND {token_column} = ?",
                (actor_id, token_value),
            )

            response = JSONResponse(content={"success": True})
            # Browser logout clears its ambient cookie; native logout uses only
            # the explicit bearer credential and must not mutate cookie state.
            if request.url.path != "/api/v1/auth/logout":
                response.delete_cookie(key="session_token")

            _result = response

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


    return router
