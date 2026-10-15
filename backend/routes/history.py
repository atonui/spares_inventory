"""History routes with explicit application dependencies."""
from backend.services.session_credentials import get_request_credential
from datetime import timedelta
from backend.temporal_contract import instant_response
from typing import List, Optional
from backend.temporal_contract import date_metadata, date_predicates, register_instant_comparison
from backend.services.timezone_policy import resolve_business_context
import json
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from backend.schemas.history import MovementResponse, ActivityLogResponse
from backend.database_sql import execute, is_postgres
from backend.services.principals import AuthenticatedPrincipal
from backend.services.tenant_context import authenticated_database_transaction
from backend.temporal import serialize_instant, utc_now
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

    def actor_id(principal):
        return principal.user_id if isinstance(principal, AuthenticatedPrincipal) else principal

    def company_admin(principal):
        return (principal.company_role in {"owner", "admin"}
                if isinstance(principal, AuthenticatedPrincipal) else bool(check_admin(principal)))

    def log_manager(principal, conn):
        if isinstance(principal, AuthenticatedPrincipal):
            return principal.organization_id is not None and principal.company_role in {"owner", "admin"}
        user = execute(conn, "SELECT role FROM users WHERE id = ?", (principal,)).fetchone()
        return bool(user and user["role"] == "admin")

    @router.get("/api/logs/test")
    @instant_response
    async def test_logging(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Test endpoint to verify logging is working"""
        try:
            with authenticated_database_transaction(
                get_db_connection, principal_or_user=user_id,
                session_token=get_request_credential(request).value if request else None, readonly=True,
            ) as (conn, principal):
                if is_postgres(conn):
                    table_exists = bool(execute(conn, "SELECT to_regclass('activity_logs') AS name").fetchone()["name"])
                else:
                    table_exists = execute(conn, "SELECT name FROM sqlite_master WHERE type='table' AND name='activity_logs'").fetchone() is not None
                log_count = execute(conn, "SELECT COUNT(*) AS count FROM activity_logs").fetchone()["count"] if table_exists else 0
                user = execute(conn, "SELECT name, role FROM users WHERE id = ?", (actor_id(principal),)).fetchone()
                return {
                    "status": "ok", "table_exists": table_exists, "log_count": log_count,
                    "current_user": dict(user) if user else None,
                    "can_view_logs": log_manager(principal, conn),
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @router.get("/api/movements", response_model=List[MovementResponse])
    @instant_response
    async def get_movements(
        user_id: int = Depends(get_current_user),
        limit: int = 100,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        movement_type: Optional[str] = None,
        part_id: Optional[int] = None,
        store_id: Optional[int] = None,
        response: Response = None,
        request: Request = None,
    ):
        """Get movement history with advanced filtering"""
        with authenticated_database_transaction(
            get_db_connection, principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None, readonly=True,
        ) as (conn, principal):
            context=resolve_business_context(conn,actor_id=principal)
            metadata=date_metadata(context,start_date,end_date)
            if response is not None:
                response.headers['X-Report-Time-Context']=json.dumps(metadata,separators=(',',':'))
            if not is_postgres(conn):
                register_instant_comparison(conn)
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

            date_sql,date_params=date_predicates('m.created_at',metadata,canonical_instants=is_postgres(conn))
            query+=date_sql;params.extend(date_params)

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

            query += (" ORDER BY m.created_at DESC, m.id DESC LIMIT ?" if is_postgres(conn)
                      else " ORDER BY utc_instant(m.created_at) DESC, m.id DESC LIMIT ?")
            params.append(limit)

            movements = execute(conn, query, params).fetchall()

            return [dict(movement) for movement in movements]

    @router.get("/api/logs/activity", response_model=List[ActivityLogResponse])
    @instant_response
    async def get_activity_logs(
        user_id: int = Depends(get_current_user),
        limit: int = 100,
        action: Optional[str] = None,
        target_user_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        status: Optional[str] = None,
        response: Response = None,
        request: Request = None,
    ):
        """Get activity logs (admin only for all logs, users can see their own)"""
        with authenticated_database_transaction(
            get_connection=get_db_connection, principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None, readonly=True,
        ) as (conn, principal):
            context=resolve_business_context(conn,actor_id=principal)
            metadata=date_metadata(context,start_date,end_date)
            if response is not None:
                response.headers['X-Report-Time-Context']=json.dumps(metadata,separators=(',',':'))
            if not is_postgres(conn):
                register_instant_comparison(conn)
            query = "SELECT * FROM activity_logs WHERE 1=1"
            params = []

            # Non-admins can only see their own logs
            if not company_admin(principal):
                query += " AND user_id = ?"
                params.append(actor_id(principal))
            else:
                # Admins can filter by specific user
                if target_user_id:
                    query += " AND user_id = ?"
                    params.append(target_user_id)

            # Apply filters
            if action:
                query += " AND action = ?"
                params.append(action)

            date_sql,date_params=date_predicates('created_at',metadata,canonical_instants=is_postgres(conn))
            query+=date_sql;params.extend(date_params)

            if status:
                query += " AND status = ?"
                params.append(status)

            query += (" ORDER BY created_at DESC, id DESC LIMIT ?" if is_postgres(conn)
                      else " ORDER BY utc_instant(created_at) DESC, id DESC LIMIT ?")
            params.append(limit)

            logs = execute(conn, query, params).fetchall()

            try:
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
                raise HTTPException(
                    status_code=500, detail=f"Failed to retrieve logs: {str(e)}"
                )

    @router.get("/api/logs/activity/stats")
    @instant_response
    async def get_activity_stats(
        user_id: int = Depends(get_current_user),
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        request: Request = None,
    ):
        """Get activity statistics (admin only)"""
        with authenticated_database_transaction(
            get_db_connection, principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None, readonly=True,
        ) as (conn, principal):
            context=resolve_business_context(conn,actor_id=principal)
            metadata=date_metadata(context,start_date,end_date)
            if not is_postgres(conn):
                register_instant_comparison(conn)

            # Check if user is admin
            if not log_manager(principal, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            date_filter,params=date_predicates('created_at',metadata,canonical_instants=is_postgres(conn))

            # Total activities
            total_activities = execute(conn,
                f"SELECT COUNT(*) as total FROM activity_logs WHERE 1=1 {date_filter}", params
            ).fetchone()["total"]

            # Activities by action
            by_action = [dict(row) for row in execute(conn,
                f"""
                SELECT action, COUNT(*) as count
                FROM activity_logs
                WHERE 1=1 {date_filter}
                GROUP BY action
                ORDER BY count DESC
                LIMIT 10
            """,
                params,
            ).fetchall()]

            # Activities by user (top 10)
            by_user = [dict(row) for row in execute(conn,
                f"""
                SELECT username, COUNT(*) as count
                FROM activity_logs
                WHERE 1=1 {date_filter}
                GROUP BY username
                ORDER BY count DESC
                LIMIT 10
            """,
                params,
            ).fetchall()]

            # Error rate
            error_stats = dict(execute(conn,
                f"""
                SELECT
                    COUNT(CASE WHEN status = 'error' THEN 1 END) as errors,
                    COUNT(CASE WHEN status = 'success' THEN 1 END) as successes
                FROM activity_logs
                WHERE 1=1 {date_filter}
            """,
                params,
            ).fetchone())

            # Recent logins
            recent_order = "created_at DESC, id DESC" if is_postgres(conn) else "utc_instant(created_at) DESC, id DESC"
            recent_logins = [dict(row) for row in execute(conn,
                f"""
                SELECT username, created_at, ip_address
                FROM activity_logs
                WHERE action = 'login' {date_filter}
                ORDER BY {recent_order}
                LIMIT 10
            """,
                params,
            ).fetchall()]


            return {
                **metadata,
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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            user = execute(conn, "SELECT name FROM users WHERE id = ?", (actor_id(user_id),)).fetchone()

            if not user or not log_manager(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Delete old logs
            cutoff = serialize_instant(utc_now() - timedelta(days=days))
            older_than_cutoff = "created_at < ?" if is_postgres(conn) else "julianday(created_at) < julianday(?)"
            deleted_count = execute(conn,
                f"""
                DELETE FROM activity_logs
                WHERE action NOT IN {PROTECTED_AUDIT_SQL} AND {older_than_cutoff}
            """,
                (cutoff,),
            ).rowcount


            log_activity(
                user_id=user_id,
                username=user["name"],
                action="cleanup_logs",
                details={"days": days, "deleted_count": deleted_count}, conn=conn)

            return {"success": True, "deleted_count": deleted_count, "days": days}

    return router
