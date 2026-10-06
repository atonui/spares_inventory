"""Privileged administration HTTP routes with explicit application dependencies."""
import json
import os
import sqlite3
from datetime import datetime
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from stock_audit import PROTECTED_AUDIT_SQL
from backend.schemas.superadmin import (
    SystemSettingUpdate, AccountUnlockRequest, BulkUnlockRequest, SecurityConfigUpdate,
    DatabaseQueryRequest, UserRoleUpdate, ForceLogoutRequest, SystemAnnouncementRequest,
    SuperadminPasswordReset,
)


def create_superadmin_router(*, get_connection, database_path, authenticated_writer,
                            current_user, csrf_dependency, superadmin_guard,
                            password_hash, activity_log, authenticated_activity,
                            database_defaults, session_validator) -> APIRouter:
    """Register existing operations without owning infrastructure or configuration."""
    superadmin_router = APIRouter(prefix="/api/superadmin", tags=["superadmin"])
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    require_superadmin = superadmin_guard
    hash_password = password_hash
    log_activity = activity_log
    log_authenticated_activity = authenticated_activity
    require_session = session_validator

    @superadmin_router.post("/users/{target_id}/reset-password")
    async def superadmin_reset_password(
        target_id: int,
        body: SuperadminPasswordReset,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)

            if len(body.new_password) < 8:
                raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

            cursor = conn.cursor()

            cursor.execute("SELECT name, email FROM users WHERE id = ?", (target_id,))
            target = cursor.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(body.new_password), target_id),
            )
            # Force logout all their sessions so new password takes effect immediately
            cursor.execute(
                "UPDATE sessions SET is_active = 0 WHERE user_id = ?",
                (target_id,),
            )

            log_activity(user_id, "superadmin", "reset_user_password",
                         resource_type="user", resource_id=target_id,
                         details={"target_email": target["email"]}, conn=conn)

            return {"success": True, "message": f"Password reset for {target['email']}"}


    @superadmin_router.get("/dashboard")
    async def superadmin_dashboard(
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        require_superadmin(user_id)
        conn = get_db_connection()
        cur = conn.cursor()

        # Locked accounts
        cur.execute("""
            SELECT COUNT(*) as n FROM users
            WHERE account_locked_until IS NOT NULL
              AND account_locked_until > datetime('now')
        """)
        locked_count = cur.fetchone()["n"]

        # Active sessions
        cur.execute("""
            SELECT COUNT(*) as n FROM sessions
            WHERE is_active = 1 AND expires_at > datetime('now')
        """)
        active_sessions = cur.fetchone()["n"]

        # Total users by role
        cur.execute("SELECT role, COUNT(*) as n FROM users GROUP BY role")
        users_by_role = {r["role"]: r["n"] for r in cur.fetchall()}

        # Recent failed logins (last 24 h)
        cur.execute("""
            SELECT COUNT(*) as n FROM activity_logs
            WHERE action IN ('login_failed','account_locked')
              AND created_at >= datetime('now','-1 day')
        """)
        recent_failures = cur.fetchone()["n"]

        # DB file size
        db_path = database_path()
        db_size_bytes = os.path.getsize(db_path) if os.path.exists(db_path) else 0

        # Log counts
        cur.execute("SELECT COUNT(*) as n FROM activity_logs")
        total_logs = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(*) as n FROM system_logs")
        total_sys_logs = cur.fetchone()["n"]

        # Current security config from system_settings
        cur.execute("""
            SELECT setting_key, setting_value FROM system_settings
            WHERE setting_key IN (
                'max_login_attempts','lockout_duration_minutes',
                'session_duration_hours','remember_me_duration_days'
            )
        """)
        sec_settings = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}

        conn.close()

        return {
            "locked_accounts": locked_count,
            "active_sessions": active_sessions,
            "users_by_role": users_by_role,
            "recent_failed_logins_24h": recent_failures,
            "database_size_bytes": db_size_bytes,
            "total_activity_logs": total_logs,
            "total_system_logs": total_sys_logs,
            "security_config": sec_settings,
        }


    @superadmin_router.get("/locked-accounts")
    async def get_locked_accounts(
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        require_superadmin(user_id)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, email, role, failed_login_attempts,
                   account_locked_until, last_login
            FROM users
            WHERE account_locked_until IS NOT NULL
              AND account_locked_until > datetime('now')
            ORDER BY account_locked_until DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


    @superadmin_router.post("/unlock-account")
    async def unlock_account(
        body: AccountUnlockRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            cur = conn.cursor()
            cur.execute("SELECT name, email FROM users WHERE id = ?", (body.user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            cur.execute("""
                UPDATE users
                SET account_locked_until = NULL,
                    failed_login_attempts = 0
                WHERE id = ?
            """, (body.user_id,))

            log_activity(user_id, "superadmin", "unlock_account",
                         resource_type="user", resource_id=body.user_id,
                         details={"target_email": target["email"]}, conn=conn)
            return {"success": True, "message": f"Account {target['email']} unlocked"}


    @superadmin_router.post("/unlock-accounts/bulk")
    async def bulk_unlock_accounts(
        body: BulkUnlockRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            if not body.user_ids:
                raise HTTPException(status_code=400, detail="No user IDs provided")

            cur = conn.cursor()
            placeholders = ",".join("?" * len(body.user_ids))
            cur.execute(f"""
                UPDATE users
                SET account_locked_until = NULL, failed_login_attempts = 0
                WHERE id IN ({placeholders})
            """, body.user_ids)
            unlocked = cur.rowcount

            log_activity(user_id, "superadmin", "bulk_unlock_accounts",
                         details={"user_ids": body.user_ids, "unlocked": unlocked}, conn=conn)
            return {"success": True, "unlocked_count": unlocked}


    @superadmin_router.get("/sessions")
    async def get_all_sessions(
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        require_superadmin(user_id)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT s.id, s.user_id, u.name, u.email, u.role,
                   s.created_at, s.last_activity, s.expires_at,
                   s.ip_address, s.user_agent, s.is_active
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.is_active = 1 AND s.expires_at > datetime('now')
            ORDER BY s.last_activity DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


    @superadmin_router.post("/sessions/force-logout")
    async def force_logout_user(
        body: ForceLogoutRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            cur = conn.cursor()
            cur.execute("SELECT name, email FROM users WHERE id = ?", (body.user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            cur.execute("""
                UPDATE sessions SET is_active = 0
                WHERE user_id = ? AND is_active = 1
            """, (body.user_id,))
            killed = cur.rowcount

            log_activity(user_id, "superadmin", "force_logout",
                         resource_type="user", resource_id=body.user_id,
                         details={"target_email": target["email"], "sessions_killed": killed}, conn=conn)
            return {"success": True, "sessions_terminated": killed}


    @superadmin_router.post("/sessions/force-logout-all")
    async def force_logout_all(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            cur = conn.cursor()
            # Preserve the calling superadmin's own session
            current_token = request.cookies.get("session_token")
            cur.execute("""
                UPDATE sessions SET is_active = 0
                WHERE session_token != ? AND is_active = 1
            """, (current_token,))
            killed = cur.rowcount

            log_activity(user_id, "superadmin", "force_logout_all",
                         details={"sessions_killed": killed}, conn=conn)
            return {"success": True, "sessions_terminated": killed}


    @superadmin_router.get("/security-config")
    # async def get_security_config(
    #     user_id: int = Depends(get_current_user),
    #     request: Request = None,
    # ):
    #     require_superadmin(user_id)
    #     conn = get_db_connection()
    #     cur = conn.cursor()

    #     keys = [
    #         "max_login_attempts",
    #         "lockout_duration_minutes",
    #         "session_duration_hours",
    #         "remember_me_duration_days",
    #         "calibration_reminder_days",
    #     ]
    #     placeholders = ",".join("?" * len(keys))
    #     cur.execute(f"""
    #         SELECT setting_key, setting_value, description, updated_at
    #         FROM system_settings
    #         WHERE setting_key IN ({placeholders})
    #     """, keys)
    #     settings = {r["setting_key"]: dict(r) for r in cur.fetchall()}
    #     conn.close()
    #     return settings


    @superadmin_router.put("/security-config/{key}")
    async def update_security_config(
        key: str,
        body: SystemSettingUpdate,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)

            allowed_keys = {
                "max_login_attempts", "lockout_duration_minutes",
                "session_duration_hours", "remember_me_duration_days",
                "calibration_reminder_days",
            }
            if key not in allowed_keys:
                raise HTTPException(status_code=400, detail=f"Unknown config key: {key}")

            # Validate numeric
            try:
                val = int(body.value)
                if val < 1:
                    raise ValueError
            except ValueError:
                raise HTTPException(status_code=400, detail="Value must be a positive integer")

            cur = conn.cursor()
            cur.execute("""
                INSERT INTO system_settings (setting_key, setting_value, updated_by)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key)
                DO UPDATE SET setting_value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
            """, (key, str(val), user_id, str(val), user_id))

            log_activity(user_id, "superadmin", "update_security_config",
                         details={"key": key, "new_value": val}, conn=conn)
            return {"success": True, "key": key, "value": val}


    @superadmin_router.get("/users")
    async def superadmin_get_users(
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        require_superadmin(user_id)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, email, role, territory,
                   failed_login_attempts, account_locked_until,
                   last_login, created_at
            FROM users ORDER BY created_at DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


    @superadmin_router.put("/users/{target_id}/role")
    async def update_user_role(
        target_id: int,
        body: UserRoleUpdate,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            valid_roles = {"engineer", "manager", "admin", "superadmin"}
            if body.role not in valid_roles:
                raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of {valid_roles}")

            cur = conn.cursor()
            cur.execute("SELECT name, email, role FROM users WHERE id = ?", (target_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            old_role = target["role"]
            cur.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, target_id))

            log_activity(user_id, "superadmin", "change_user_role",
                         resource_type="user", resource_id=target_id,
                         details={"email": target["email"], "old_role": old_role, "new_role": body.role}, conn=conn)
            return {"success": True, "message": f"Role updated from {old_role} → {body.role}"}


    @superadmin_router.get("/database/tables")
    async def get_db_tables(
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        require_superadmin(user_id)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [r["name"] for r in cur.fetchall()]

        result = {}
        for table in tables:
            cur.execute(f"SELECT COUNT(*) as n FROM [{table}]")
            count = cur.fetchone()["n"]
            cur.execute(f"PRAGMA table_info([{table}])")
            columns = [{"name": c["name"], "type": c["type"]} for c in cur.fetchall()]
            result[table] = {"row_count": count, "columns": columns}

        conn.close()
        return result


    @superadmin_router.post("/database/query")
    async def run_readonly_query(
        body: DatabaseQueryRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Execute a read-only SQL query (SELECT only)."""
        require_superadmin(user_id)
        sql = body.sql.strip()

        # Allow only SELECT statements
        first_word = sql.split()[0].upper() if sql else ""
        if first_word != "SELECT":
            raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")

        # Block dangerous keywords
        forbidden = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE", "ATTACH"]
        upper_sql = sql.upper()
        for kw in forbidden:
            if kw in upper_sql:
                raise HTTPException(status_code=400, detail=f"Keyword '{kw}' is not allowed")

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(sql, body.params or [])
            rows = cur.fetchmany(500)  # cap at 500 rows
            columns = [desc[0] for desc in cur.description] if cur.description else []
            result = [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Query error: {str(e)}")
        finally:
            conn.close()

        log_authenticated_activity(user_id, request.cookies.get('session_token'), username='superadmin', action='db_query', details={'sql': sql[:200]})
        return {"columns": columns, "rows": result, "count": len(result)}


    @superadmin_router.get("/database/backup")
    async def download_db_backup(
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        """Stream the SQLite DB file as a download."""
        require_superadmin(user_id)
        if not os.path.exists(database_path()):
            raise HTTPException(status_code=404, detail="Database file not found")

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"inventory_backup_{timestamp}.db"
        backup_path = f"/tmp/{backup_name}"

        # Use SQLite backup API for a consistent copy
        src = sqlite3.connect(database_path())
        dst = sqlite3.connect(backup_path)
        src.backup(dst)
        dst.close()
        src.close()

        log_authenticated_activity(user_id, request.cookies.get('session_token'), username='superadmin', action='db_backup', details={'filename': backup_name})
        return FileResponse(backup_path, filename=backup_name,
                            media_type="application/octet-stream")


    @superadmin_router.post("/database/restore")
    async def restore_uploaded_database(
        request: Request,
        file: UploadFile = File(...),
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
    ):
        require_superadmin(user_id)
        session_token = request.cookies.get('session_token')
        def validate_actor(conn):
            require_session(conn, session_token, expected_user_id=user_id)
            require_superadmin(user_id, conn)

        import tempfile
        from database_restore import restore_database
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "upload.db")
                size = 0
                with open(path, "wb") as output:
                    while chunk := await file.read(1024 * 1024):
                        size += len(chunk)
                        if size > 20 * 1024 * 1024:
                            raise HTTPException(status_code=413, detail="Maximum database size is 20 MB")
                        output.write(chunk)
                with open(path, "rb") as uploaded:
                    if uploaded.read(16) != b"SQLite format 3\x00":
                        raise HTTPException(status_code=400, detail="Upload a valid SQLite database")
                backup_name = restore_database(path, database_path(), user_id, defaults=database_defaults(), validate_actor=validate_actor)
        except (ValueError, sqlite3.Error) as error:
            raise HTTPException(status_code=400, detail=str(error))
        except TimeoutError as error:
            raise HTTPException(status_code=409, detail=str(error))
        response = JSONResponse({"success": True, "backup_name": backup_name,
                                 "message": "Database restored. Please sign in again."})
        response.delete_cookie("session_token")
        return response


    @superadmin_router.post("/database/vacuum")
    async def vacuum_database(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Run VACUUM to reclaim space and defragment the SQLite file."""
        require_superadmin(user_id)
        before = os.path.getsize(database_path()) if os.path.exists(database_path()) else 0
        conn = sqlite3.connect(database_path())
        conn.execute("VACUUM")
        conn.close()
        after = os.path.getsize(database_path()) if os.path.exists(database_path()) else 0

        log_authenticated_activity(user_id, request.cookies.get('session_token'), username='superadmin', action='db_vacuum', details={'before_bytes': before, 'after_bytes': after})
        return {
            "success": True,
            "before_bytes": before,
            "after_bytes": after,
            "saved_bytes": before - after,
        }


    @superadmin_router.delete("/database/logs/purge")
    async def purge_all_logs(
        days: int = 0,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Purge activity_logs and system_logs older than `days` days (0 = all)."""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            cur = conn.cursor()

            if days == 0:
                cur.execute(f"DELETE FROM activity_logs WHERE action NOT IN {PROTECTED_AUDIT_SQL}")
                act_deleted = cur.rowcount
                cur.execute("DELETE FROM system_logs")
                sys_deleted = cur.rowcount
            else:
                cur.execute(f"""
                    DELETE FROM activity_logs
                    WHERE action NOT IN {PROTECTED_AUDIT_SQL} AND created_at < datetime('now', ? )
                """, (f"-{days} days",))
                act_deleted = cur.rowcount
                cur.execute("""
                    DELETE FROM system_logs
                    WHERE created_at < datetime('now', ?)
                """, (f"-{days} days",))
                sys_deleted = cur.rowcount


            log_activity(user_id, "superadmin", "purge_logs",
                         details={"days": days, "activity_deleted": act_deleted, "system_deleted": sys_deleted}, conn=conn)
            return {
                "success": True,
                "activity_logs_deleted": act_deleted,
                "system_logs_deleted": sys_deleted,
            }


    @superadmin_router.post("/announcement")
    async def set_announcement(
        body: SystemAnnouncementRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            cur = conn.cursor()
            payload = json.dumps({"message": body.message, "level": body.level,
                                   "set_at": datetime.utcnow().isoformat()})
            cur.execute("""
                INSERT INTO system_settings (setting_key, setting_value, updated_by)
                VALUES ('system_announcement', ?, ?)
                ON CONFLICT(setting_key)
                DO UPDATE SET setting_value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
            """, (payload, user_id, payload, user_id))
            return {"success": True}


    @superadmin_router.delete("/announcement")
    async def clear_announcement(
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_superadmin(user_id, conn)
            cur = conn.cursor()
            cur.execute("DELETE FROM system_settings WHERE setting_key = 'system_announcement'")
            return {"success": True}


    @superadmin_router.get("/announcement")
    async def get_announcement(request: Request = None):
        """Public endpoint – any authenticated user can read the announcement."""
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'system_announcement'")
        row = cur.fetchone()
        conn.close()
        if not row:
            return {"announcement": None}
        return {"announcement": json.loads(row["setting_value"])}


    @superadmin_router.get("/audit-log")
    async def get_superadmin_audit(
        limit: int = 200,
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        require_superadmin(user_id)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM activity_logs
            WHERE username = 'superadmin'
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


    return superadmin_router
