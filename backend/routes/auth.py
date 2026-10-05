"""Authentication routes composed with explicit application dependencies."""
from datetime import datetime, timedelta
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from backend.schemas.auth import (
    UserProfileUpdate, PasswordChange, ForgotPasswordRequest, ResetPasswordRequest,
    UserLogin, UserResponse,
)


def create_auth_router(*, get_connection, authenticated_writer, stock_writer, current_user,
                       csrf_dependency, csrf_token_factory, password_hash,
                       password_verify, security_config, reset_email,
                       activity_log, endpoint_log, mutation_activity,
                       limiter, logger, cookie_secure) -> APIRouter:
    """Register existing HTTP flows without owning application infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    stock_write_transaction = stock_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    generate_csrf_token = csrf_token_factory
    hash_password = password_hash
    verify_password = password_verify
    get_security_config = security_config
    send_reset_email = reset_email
    log_activity = activity_log
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    @router.get("/api/csrf-token")
    async def get_csrf_token():
        """Get CSRF token for forms"""
        token = generate_csrf_token()
        return {"csrf_token": token}


    @router.get("/api/profile")
    async def get_profile(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get current user's profile"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, email, name, role, territory, created_at FROM users WHERE id = ?",
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
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            if profile_update.email:
                # Check if email already exists
                cursor.execute(
                    "SELECT id FROM users WHERE email = ? AND id != ?",
                    (profile_update.email, user_id),
                )
                if cursor.fetchone():
                    raise HTTPException(status_code=400, detail="Email already in use")

                cursor.execute(
                    "UPDATE users SET email = ? WHERE id = ?", (profile_update.email, user_id)
                )


            # Get updated user info
            cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

            return {"message": "Profile updated successfully", "email": user["email"]}


    @router.post("/api/profile/change-password")
    async def change_password(
        password_data: PasswordChange,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Change user password"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Get current user
            cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            # Verify current password using bcrypt
            if not verify_password(password_data.current_password, user["password_hash"]):
                logger.error(f"Password verification failed for user {user_id}")
                raise HTTPException(status_code=400, detail="Current password is incorrect")

            # Validate new password
            if len(password_data.new_password) < 8:
                raise HTTPException(
                    status_code=400, detail="Password must be at least 8 characters long"
                )

            # Update password and invalidate session token
            new_hash = hash_password(password_data.new_password)

            cursor.execute(
                "UPDATE users SET password_hash = ?, session_token = NULL WHERE id = ?",
                (new_hash, user_id),
            )

            # Deactivate all sessions for this user i.e. force logout from all devices
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))


            logger.info(f"Password changed successfully for user {user_id}")

            return {"message": "Password changed successfully. Please login again."}


    @router.post("/api/auth/revoke-other-sessions")
    async def revoke_other_sessions(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        # Revoke all sessions except the current one
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            current_token = request.cookies.get("session_token")

            cursor.execute(
                """
                UPDATE sessions
                SET is_active = 0
                WHERE user_id = ? AND session_token != ? AND is_active = 1
            """,
                (user_id, current_token),
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
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Initiate password reset process"""
        ip_address = request.client.host if hasattr(request, "client") else None
        user_agent = request.headers.get("user-agent", "")[:200]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Find user by email
        cursor.execute("SELECT id, name FROM users WHERE email = ? AND archived_at IS NULL", (request_data.email,))
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
        expires_at = datetime.utcnow() + timedelta(hours=1)

        # Store token in users table
        cursor.execute(
            """UPDATE users 
               SET reset_token = ?, reset_token_expires = ? 
               WHERE id = ? AND archived_at IS NULL""",
            (token, expires_at.isoformat(), user_id),
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
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Reset password using token"""
        ip_address = request.client.host if hasattr(request, "client") else None
        user_agent = request.headers.get("user-agent", "")[:200]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Validate token
        cursor.execute(
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
        expires_at = datetime.fromisoformat(user["reset_token_expires"])
        if datetime.utcnow() > expires_at:
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
        if datetime.utcnow() > expires_at:
            conn.close()
            raise HTTPException(status_code=400,detail='Token has expired')
        # Update password and clear token
        cursor.execute(
            """UPDATE users 
               SET password_hash = ?, 
                   reset_token = NULL, 
                   reset_token_expires = NULL,
                   session_token = NULL
               WHERE id = ? AND reset_token = ? AND archived_at IS NULL""",
            (new_hash, user["id"], request_data.token),
        )

        if cursor.rowcount != 1:
            conn.rollback()
            conn.close()
            raise HTTPException(status_code=400,detail='Invalid or expired token')

        cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user["id"],))

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
    async def verify_reset_token(token: str, request: Request = None):
        """Verify if a reset token is valid"""
        ip_address = request.client.host if hasattr(request, "client") else None

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
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

        expires_at = datetime.fromisoformat(user["reset_token_expires"])
        if datetime.utcnow() > expires_at:
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


    @router.post("/api/auth/login")
    @limiter.limit("5/minute")  # 5 attempts per minute
    async def login(user_login: UserLogin, request: Request):
        """Enhanced user login with security features"""
        ip_address = request.client.host if hasattr(request, "client") else None
        user_agent = request.headers.get("user-agent", "")[:200]

        cfg              = get_security_config()
        max_attempts     = cfg["max_login_attempts"]
        lockout_minutes  = cfg["lockout_duration_minutes"]
        session_hours    = cfg["session_duration_hours"]
        remember_me_days = cfg["remember_me_duration_days"]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user
        cursor.execute(
            """SELECT id, email, name, role, territory, password_hash, 
               failed_login_attempts, account_locked_until 
               FROM users WHERE email = ? AND archived_at IS NULL""",
            (user_login.email,),
        )
        user = cursor.fetchone()

        # Check if account is locked
        if user and user["account_locked_until"]:
            lockout_time = datetime.fromisoformat(user["account_locked_until"])
            if datetime.utcnow() < lockout_time:
                remaining_minutes = int(
                    (lockout_time - datetime.utcnow()).total_seconds() / 60
                )
                log_activity(
                    user_id=user["id"],
                    username=user["name"],
                    action="login_blocked",
                    status="error",
                    error_message="Account locked",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                conn.close()
                raise HTTPException(
                    status_code=423,
                    detail=f"Account locked. Try again in {remaining_minutes} minutes.",
                )

        # Verify password
        if not user or not verify_password(user_login.password, user["password_hash"]):
            # Log failed attempt
            if user:
                failed_attempts = user["failed_login_attempts"] + 1

                if failed_attempts >= max_attempts:
                    # Lock account
                    lockout_until = datetime.utcnow() + timedelta(
                        minutes=lockout_minutes
                    )
                    cursor.execute(
                        """UPDATE users 
                           SET failed_login_attempts = ?, account_locked_until = ? 
                           WHERE id = ?""",
                        (failed_attempts, lockout_until.isoformat(), user["id"]),
                    )
                    conn.commit()

                    log_activity(
                        user_id=user["id"],
                        username=user["name"],
                        action="account_locked",
                        status="error",
                        error_message="Too many failed attempts",
                        ip_address=ip_address,
                        user_agent=user_agent,
                    )

                    conn.close()
                    raise HTTPException(
                        status_code=423,
                        detail=f"Account locked due to too many failed attempts. Try again in {lockout_minutes} minutes.",
                    )
                else:
                    cursor.execute(
                        "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
                        (failed_attempts, user["id"]),
                    )
                    conn.commit()

            log_activity(
                user_id=user["id"] if user else 0,
                username=user_login.email,
                action="login_failed",
                status="error",
                error_message="Invalid credentials",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            conn.close()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Successful login - reset failed attempts and unlock
        session_token = secrets.token_urlsafe(32)

        # Calculate session expiration
        if user_login.remember_me:
            expires = datetime.utcnow() + timedelta(days=remember_me_days)
            max_age = remember_me_days * 24 * 60 * 60
        else:
            expires = datetime.utcnow() + timedelta(hours=session_hours)
            max_age = session_hours * 60 * 60

        # Serialize the active-account check with session creation and archiving.
        conn.close()
        with stock_write_transaction() as conn:
            cursor=conn.cursor()
            if not conn.execute('SELECT 1 FROM users WHERE id=? AND archived_at IS NULL',(user['id'],)).fetchone():
                raise HTTPException(status_code=401,detail='Invalid credentials')
            # Create session in sessions table
            cursor.execute(
                """
                INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """,
                (user["id"], session_token, expires.isoformat(), ip_address, user_agent),
            )

            # Update user record
            cursor.execute(
                """
                UPDATE users
                SET failed_login_attempts = 0,
                    account_locked_until = NULL,
                    last_login = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (user["id"],),
            )



        # Log successful login
        log_activity(
            user_id=user["id"],
            username=user["name"],
            action="login",
            details={"role": user["role"], "remember_me": user_login.remember_me},
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info(f"User {user['name']} ({user['id']}) logged in from {ip_address}")

        # Create response
        response_data = {
            "success": True,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user["name"],
                "role": user["role"],
                "territory": user["territory"],
            },
        }

        response = JSONResponse(content=response_data)

        # Set HTTPOnly cookie
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=cookie_secure(),
            samesite="lax",
            max_age=max_age,
        )

        return response


    @router.get("/api/auth/sessions")
    async def get_active_sessions(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get user's active sessions"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, created_at, last_activity, ip_address, user_agent,
                   CASE WHEN session_token = ? THEN 1 ELSE 0 END as is_current
            FROM sessions
            WHERE user_id = ? AND is_active = 1
            ORDER BY last_activity DESC
        """,
            (request.cookies.get("session_token"), user_id),
        )

        sessions = cursor.fetchall()
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
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Verify session belongs to user
            cursor.execute(
                """
                UPDATE sessions
                SET is_active = 0
                WHERE id = ? AND user_id = ?
            """,
                (session_id, user_id),
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
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            current_token = request.cookies.get("session_token")

            cursor.execute(
                """
                UPDATE sessions
                SET is_active = 0
                WHERE user_id = ? AND session_token != ?
            """,
                (user_id, current_token),
            )

            revoked_count = cursor.rowcount


            return {"success": True, "revoked_count": revoked_count}


    @router.post("/api/auth/logout")
    @log_endpoint(action="logout", transactional=True)
    async def logout(user_id: int = Depends(get_current_user), request: Request = None):
        """Logout and clear session cookie"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET session_token = NULL WHERE id = ?", (user_id,))
            cursor.execute(
                "UPDATE sessions SET is_active = 0 WHERE user_id = ? AND session_token = ?",
                (user_id, request.cookies.get("session_token")),
            )

            response = JSONResponse(content={"success": True})
            # Clear the cookie
            response.delete_cookie(key="session_token")

            _result = response

            _record_mutation_activity(conn, user_id, 'logout', None, _result, request)
            return _result


    @router.get("/api/me", response_model=UserResponse)
    async def get_current_user_info(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get current user information"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, email, name, role, territory FROM users WHERE id = ?", (user_id,)
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return dict(user)


    return router
