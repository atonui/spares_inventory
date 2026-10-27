Warning: truncated output (original token count: 17654)
Total output lines: 1578

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
                       authenticated_account_writer=None) -> APIRouter:
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
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    def authenticated_user_id(user):
        return getattr(user, "user_id", user)

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
        if setting not in {'app.mobile_pairing_qr_token_hash', 'app.mobile_pairing_claim_token_hash'}:
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
                        status_code=409,
                        detail="Email addresses must be changed through verification.",
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
        from backend.services.email_change import EmailChangeFailure, request_email_change

        try:
            with authenticated_account_write_transaction(
                user, get_request_credential(request).value
            ) as (conn, _principal):
                require_postgres(conn)
                set_email_change_user_scope(conn, authenticated_user_id(user))
                request_email_change(
                    conn,
                    user_id=authenticated_user_id(user),
                    proposed_email=str(data.email),
                    frontend_url=frontend_url or "",
                    encryption_key=mail_payload_encryption_key,
                )
        except EmailChangeFailure as exc:
            raise email_change_http_error(exc) from None
        except ValueError:
            raise HTTPException(status_code=503, detail="Email change is unavailable") from None
        # The response is intentionally identical for an available or occupied address.
        return JSONResponse(
            status_code=202,
            content={
                "success": True,
                "message": "If the address can be used, a confirmation email has been sent.",
            },
            headers={"Cache-Control": "no-store"},
        )


    @router.get(
        "/api/profile/email-change-request",
        response_model=EmailChangeStatus,
    )
    @instant_response
    async def get_profile_email_change(
        request: Request,
        user=Depends(email_change_user),
    ):
        from backend.services.email_change import get_pending_email_change

        with authenticated_account_write_transaction(
            user, get_request_credential(request).value
        ) as (conn, _principal):
            require_postgres(conn)
            set_email_change_user_scope(conn, authenticated_user_id(user))
            result = get_pending_email_change(conn, user_id=authenticated_user_id(user))
        return JSONResponse(
            content=result or {"status": "none"},
            headers={"Cache-Control": "no-store"},
        )


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
        from backend.services.email_change import cancel_email_change

        with authenticated_account_write_transaction(
            user, get_request_credential(request).value
        ) as (conn, _principal):
            require_postgres(conn)
            set_email_change_user_scope(conn, authenticated_user_id(user))
            cancel_email_change(conn, user_id=authenticated_user_id(user))
        return JSONResponse(
            content={"success": True, "message": "Pending email change canceled."},
            headers={"Cache-Control": "no-store"},
        )


    @router.post(
        "/api/auth/email-change/confirm",
        response_model=EmailChangeConfirmationResponse,
        responses={400: {"description": "Invalid or expired confirmation"}, 409: {"description": "Email address unavailable"}},
    )
    @limiter.limit("5/minute")
    async def confirm_profile_email_change(
        data: EmailChangeConfirmation,
        request: Request,
    ):
        from backend.services.email_change import EmailChangeFailure, confirm_email_change
        from backend.postgres_database import postgres_transaction
        import psycopg

        conn = get_db_connection()
        try:
            require_postgres(conn)
            with postgres_transaction(conn):
                confirm_email_change(
                    conn,
                    token=data.token,
                    encryption_key=mail_payload_encryption_key,
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
            execute_cursor(conn, cursor, "UPDATE sessions SET is_active = FALSE WHERE user_id = ?", (actor_id,))


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
        else:
            user_id = None

        log_activity(
            user_id=user_id,
            username="account_holder" if user else "unmatched_account",
            action="password_reset_request",
            details={"account_match": bool(user)},
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

        return {"message": "If the email exists, a reset link has been…7654 tokens truncated…now() >= stored_instant(row["expires_at"], "expires_at"):
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
        try:
            parsed = urlsplit(payload.qr_data)
            values = parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            raise HTTPException(status_code=400, detail="This QR code is invalid or has expired") from None
        token_values = values.get("token", [])
        if (parsed.scheme != "sparesflow" or parsed.netloc != "pair" or parsed.path or parsed.fragment
                or set(values) != {"token"} or len(token_values) != 1 or not token_values[0]):
            raise HTTPException(status_code=400, detail="This QR code is invalid or has expired")
        qr_hash = hash_session_credential(token_values[0])
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
                set_mobile_pairing_token_scope(conn, 'app.mobile_pairing_qr_token_hash', qr_hash)
                row = conn.execute(
                    """SELECT request_id, status, expires_at FROM mobile_pairing_requests
                       WHERE qr_token_hash = %s FOR UPDATE""",
                    (qr_hash,),
                ).fetchone()
                if (row is None or row["status"] != "created"
                        or now >= stored_instant(row["expires_at"], "expires_at")):
                    raise HTTPException(status_code=410, detail="This QR code is invalid or has expired")
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
                cfg = get_security_config()
                absolute_expires = now + timedelta(hours=cfg["session_duration_hours"])
                access_expires = min(now + timedelta(minutes=15), absolute_expires)
                session_id = conn.execute(
                    """INSERT INTO sessions (user_id, session_token_hash, expires_at,
                                              absolute_expires_at, ip_address, user_agent)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                    (user["id"], hash_session_credential(access_token), serialize_instant(access_expires),
                     serialize_instant(absolute_expires), request.client.host if request.client else None,
                     request.headers.get("user-agent", "")[:512]),
                ).fetchone()["id"]
                conn.execute(
                    """INSERT INTO session_refresh_credentials (session_id, token_hash, issued_at, expires_at)
                       VALUES (%s, %s, %s, %s)""",
                    (session_id, hash_session_credential(refresh_token), serialize_instant(now), serialize_instant(absolute_expires)),
                )
                from backend.services.principals import resolve_principal
                principal = resolve_principal(conn, access_token)
                if principal.user_id != user["id"] or not (principal.company_role or principal.is_platform_admin):
                    raise HTTPException(status_code=403, detail="The account has no active company access")
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
                f"UPDATE sessions SET is_active = FALSE WHERE user_id = ? AND {token_column} = ?",
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
    router.add_api_route(
        "/api/v1/me/email-change-requests",
        request_profile_email_change,
        methods=["POST"],
        status_code=202,
        response_model=EmailChangeRequestResponse,
        dependencies=[Depends(require_native_bearer)],
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/me/email-change-request",
        get_profile_email_change,
        methods=["GET"],
        response_model=EmailChangeStatus,
        dependencies=[Depends(require_native_bearer)],
        include_in_schema=True,
    )
    router.add_api_route(
        "/api/v1/me/email-change-request",
        cancel_profile_email_change,
        methods=["DELETE"],
        response_model=EmailChangeCancelResponse,
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
