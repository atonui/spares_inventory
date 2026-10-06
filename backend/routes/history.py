"""History routes with explicit application dependencies."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.history import MovementResponse, ActivityLogResponse
from stock_audit import PROTECTED_AUDIT_SQL


def create_history_router(*, get_connection, authenticated_writer, current_user,
                          csrf_dependency, admin_guard, activity_log, error_log) -> APIRouter:
    """Keep database ownership and audit infrastructure in the application."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    check_admin = admin_guard
    log_activity = activity_log

    @router.get("/api/logs/test")
    async def test_logging(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Test endpoint to verify logging is working"""
        try:
            # Test database connection
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if table exists
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='activity_logs'
            """)
            table_exists = cursor.fetchone() is not None

            # Get count of logs
            if table_exists:
                cursor.execute("SELECT COUNT(*) as count FROM activity_logs")
                log_count = cursor.fetchone()["count"]
            else:
                log_count = 0

            # Get user info
            cursor.execute("SELECT name, role FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

            conn.close()

            return {
                "status": "ok",
                "table_exists": table_exists,
                "log_count": log_count,
                "current_user": dict(user) if user else None,
                "can_view_logs": user["role"] == "admin" if user else False,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @router.get("/api/movements", response_model=List[MovementResponse])
    async def get_movements(
        user_id: int = Depends(get_current_user),
        limit: int = 100,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        movement_type: Optional[str] = None,
        part_id: Optional[int] = None,
        store_id: Optional[int] = None,
        request: Request = None,
    ):
        """Get movement history with advanced filtering"""
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            SELECT
                m.id,
                s1.name as from_store_name,
                s2.name as to_store_name,
                p.part_number,
                m.quantity,
                m.movement_type,
                wo.work_order_number as work_order,
                u.name as created_by_name,
                m.created_at,
                CASE WHEN m.movement_type='transfer' THEN COALESCE(t.status,'completed') END AS transfer_status,
                u2.name AS completed_by_name,t.completed_at
            FROM movements m
            LEFT JOIN stock_transfers t ON t.movement_id=m.id
            LEFT JOIN users u2 ON u2.id=t.completed_by
            LEFT JOIN stores s1 ON m.from_store_id = s1.id
            LEFT JOIN stores s2 ON m.to_store_id = s2.id
            JOIN parts p ON m.part_id = p.id
            LEFT JOIN work_orders wo ON m.work_order_id = wo.id
            JOIN users u ON m.created_by = u.id
            WHERE 1=1
        """

        params = []

        # query += """
        #     AND (m.created_by = ?
        #     OR s1.assigned_user_id = ?
        #     OR s2.assigned_user_id = ?)
        #     """
        # params.extend([user_id, user_id, user_id])

        # Date range filtering
        if start_date:
            query += " AND m.created_at >= ?"
            params.append(start_date)

        if end_date:
            query += " AND m.created_at <= ?"
            params.append(end_date + " 23:59:59")

        # Movement type filtering
        if movement_type:
            query += " AND m.movement_type = ?"
            params.append(movement_type)

        # Part filtering
        if part_id:
            query += " AND m.part_id = ?"
            params.append(part_id)

        # Store filtering (from or to)
        if store_id:
            query += " AND (m.from_store_id = ? OR m.to_store_id = ?)"
            params.extend([store_id, store_id])

        query += " ORDER BY m.created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        movements = cursor.fetchall()
        conn.close()

        return [dict(movement) for movement in movements]

    @router.get("/api/logs/activity", response_model=List[ActivityLogResponse])
    async def get_activity_logs(
        user_id: int = Depends(get_current_user),
        limit: int = 100,
        action: Optional[str] = None,
        target_user_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        status: Optional[str] = None,
        request: Request = None,
    ):
        """Get activity logs (admin only for all logs, users can see their own)"""
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM activity_logs WHERE 1=1"
        params = []

        # Non-admins can only see their own logs
        if not check_admin(user_id):
            query += " AND user_id = ?"
            params.append(user_id)
        else:
            # Admins can filter by specific user
            if target_user_id:
                query += " AND user_id = ?"
                params.append(target_user_id)

        # Apply filters
        if action:
            query += " AND action = ?"
            params.append(action)

        if start_date:
            query += " AND created_at >= ?"
            params.append(start_date)

        if end_date:
            query += " AND created_at <= ?"
            params.append(end_date + " 23:59:59")

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        logs = cursor.fetchall()
        # conn.close()

        try:
            cursor.execute(query, params)
            logs = cursor.fetchall()
            conn.close()

            # Convert to list of dicts and ensure all fields are present
            result = []
            for log in logs:
                log_dict = dict(log)
                # Ensure all expected fields exist with defaults
                log_dict.setdefault("details", None)
                log_dict.setdefault("ip_address", None)
                log_dict.setdefault("user_agent", None)
                log_dict.setdefault("error_message", None)
                result.append(log_dict)

            return result
        except Exception as e:
            error_log(f"Failed to get activity logs: {e}")
            conn.close()
            raise HTTPException(
                status_code=500, detail=f"Failed to retrieve logs: {str(e)}"
            )

    @router.get("/api/logs/activity/stats")
    async def get_activity_stats(
        user_id: int = Depends(get_current_user),
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        request: Request = None,
    ):
        """Get activity statistics (admin only)"""
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user is admin
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")

        # Date filter
        date_filter = ""
        params = []
        if start_date:
            date_filter += " AND created_at >= ?"
            params.append(start_date)
        if end_date:
            date_filter += " AND created_at <= ?"
            params.append(end_date + " 23:59:59")

        # Total activities
        cursor.execute(
            f"SELECT COUNT(*) as total FROM activity_logs WHERE 1=1 {date_filter}", params
        )
        total_activities = cursor.fetchone()["total"]

        # Activities by action
        cursor.execute(
            f"""
            SELECT action, COUNT(*) as count
            FROM activity_logs
            WHERE 1=1 {date_filter}
            GROUP BY action
            ORDER BY count DESC
            LIMIT 10
        """,
            params,
        )
        by_action = [dict(row) for row in cursor.fetchall()]

        # Activities by user (top 10)
        cursor.execute(
            f"""
            SELECT username, COUNT(*) as count
            FROM activity_logs
            WHERE 1=1 {date_filter}
            GROUP BY username
            ORDER BY count DESC
            LIMIT 10
        """,
            params,
        )
        by_user = [dict(row) for row in cursor.fetchall()]

        # Error rate
        cursor.execute(
            f"""
            SELECT
                COUNT(CASE WHEN status = 'error' THEN 1 END) as errors,
                COUNT(CASE WHEN status = 'success' THEN 1 END) as successes
            FROM activity_logs
            WHERE 1=1 {date_filter}
        """,
            params,
        )
        error_stats = dict(cursor.fetchone())

        # Recent logins
        cursor.execute(
            f"""
            SELECT username, created_at, ip_address
            FROM activity_logs
            WHERE action = 'login' {date_filter}
            ORDER BY created_at DESC
            LIMIT 10
        """,
            params,
        )
        recent_logins = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            "total_activities": total_activities,
            "by_action": by_action,
            "by_user": by_user,
            "error_rate": error_stats,
            "recent_logins": recent_logins,
        }

    @router.delete("/api/logs/activity/cleanup")
    async def cleanup_old_logs(
        days: int = 90,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Delete activity logs older than specified days (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if user is admin
            cursor.execute("SELECT role,name FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

            if not user or user["role"] != "admin":
                raise HTTPException(status_code=403, detail="Admin access required")

            # Delete old logs
            cursor.execute(
                f"""
                DELETE FROM activity_logs
                WHERE action NOT IN {PROTECTED_AUDIT_SQL} AND created_at < datetime('now', '-' || ? || ' days')
            """,
                (days,),
            )

            deleted_count = cursor.rowcount


            log_activity(
                user_id=user_id,
                username=user["name"],
                action="cleanup_logs",
                details={"days": days, "deleted_count": deleted_count}, conn=conn)

            return {"success": True, "deleted_count": deleted_count, "days": days}

    return router
