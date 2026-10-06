"""Application activity logging helpers with injectable app dependencies."""

import json
from functools import wraps

from fastapi import HTTPException, Request

from backend.services.activity import record_activity


def log_activity(
    get_connection,
    audit_logger,
    error_logger,
    *,
    user_id: int,
    username: str,
    action: str,
    resource_type: str = None,
    resource_id: int = None,
    details: dict = None,
    status: str = "success",
    error_message: str = None,
    ip_address: str = None,
    user_agent: str = None,
    conn=None,
):
    """Log user activity to database and audit log file."""
    if conn is not None:
        record_activity(
            conn,
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            status=status,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return
    try:
        conn = get_connection()
        cursor = conn.cursor()
        details_json = json.dumps(details) if details else None
        cursor.execute(
            """
            INSERT INTO activity_logs
            (user_id, username, action, resource_type, resource_id, details,
             ip_address, user_agent, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user_id if user_id else None,
                username,
                action,
                resource_type,
                resource_id,
                details_json,
                ip_address,
                user_agent,
                status,
                error_message,
            ),
        )
        conn.commit()
        conn.close()
        audit_logger.info(
            f"USER={username}({user_id}) ACTION={action} "
            f"RESOURCE={resource_type}/{resource_id} STATUS={status}"
        )
    except Exception as e:
        error_logger.error(f"Failed to log activity: {str(e)}")


def log_system_event(get_connection, logger, error_logger, level: str, component: str,
                     message: str, details: dict = None):
    """Log system events to database and application logger."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        details_json = json.dumps(details) if details else None
        cursor.execute(
            """
            INSERT INTO system_logs (level, component, message, details)
            VALUES (?, ?, ?, ?)
        """,
            (level, component, message, details_json),
        )
        conn.commit()
        conn.close()
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{component}] {message}")
    except Exception as e:
        error_logger.error(f"Failed to log system event: {str(e)}")


def log_authenticated_activity(authenticated_writer, error_logger, user_id: int,
                               session_token: str | None, **activity):
    """Best-effort read/maintenance evidence; never write with a stale session."""
    try:
        with authenticated_writer(user_id, session_token) as conn:
            record_activity(conn, user_id=user_id, **activity)
    except HTTPException:
        return
    except Exception:
        error_logger.exception("Failed to record authenticated activity")


def record_mutation_activity(conn, user_id, action, resource_type, result, request):
    actor = conn.execute("SELECT name FROM users WHERE id=?", (user_id,)).fetchone()
    details = (
        {
            k: v
            for k, v in result.items()
            if k not in {"password_hash", "session_token", "reset_token"}
        }
        if isinstance(result, dict)
        else {}
    )
    record_activity(
        conn,
        user_id=user_id,
        username=actor["name"] if actor else "Unknown",
        action=action,
        resource_type=resource_type,
        resource_id=result.get("id") if isinstance(result, dict) else None,
        details=details,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent", "")[:200] if request else None,
    )


def create_endpoint_logger(
    *,
    get_connection_provider,
    authenticated_activity_provider,
    logger_provider,
    error_logger_provider,
    stock_audit_actions_provider,
):
    def log_endpoint(action: str, resource_type: str = None, *, transactional: bool = False):
        """Decorator to automatically log API endpoint calls."""

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                user_id = kwargs.get("user_id")
                request = None
                for value in kwargs.values():
                    if isinstance(value, Request):
                        request = value
                        break
                ip_address = request.client.host if request and hasattr(request, "client") else None
                user_agent = request.headers.get("user-agent", "")[:200] if request else None
                username = "Unknown"
                resource_id = None
                details = {}
                status = "success"
                error_message = None
                try:
                    get_connection = get_connection_provider()
                    logger = logger_provider()
                    if user_id:
                        try:
                            conn = get_connection()
                            cursor = conn.cursor()
                            cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))
                            user = cursor.fetchone()
                            conn.close()
                            if user:
                                username = user["name"]
                        except Exception as e:
                            logger.error(f"Failed to get username: {e}")
                    result = await func(*args, **kwargs)
                    if isinstance(result, dict):
                        resource_id = result.get("id")
                        details = {
                            k: v
                            for k, v in result.items()
                            if k not in ["password_hash", "session_token", "reset_token"]
                        }
                    return result
                except HTTPException as e:
                    status = "error"
                    error_message = e.detail
                    error_logger_provider().error(
                        f"HTTPException in {func.__name__}: {e.detail}",
                        extra={"user_id": user_id, "status_code": e.status_code},
                    )
                    raise
                except Exception as e:
                    status = "error"
                    error_message = str(e)
                    error_logger_provider().exception(
                        f"Exception in {func.__name__}: {str(e)}",
                        extra={"user_id": user_id},
                    )
                    raise
                finally:
                    if user_id and not transactional and not (
                        status == "success" and action in stock_audit_actions_provider()
                    ):
                        try:
                            authenticated_activity = authenticated_activity_provider()
                            authenticated_activity(
                                user_id=user_id,
                                session_token=request.cookies.get("session_token") if request else None,
                                username=username,
                                action=action,
                                resource_type=resource_type,
                                resource_id=resource_id,
                                details=details,
                                status=status,
                                error_message=error_message,
                                ip_address=ip_address,
                                user_agent=user_agent,
                            )
                        except Exception as log_error:
                            error_logger_provider().error(f"Failed to log activity: {log_error}")

            return wrapper

        return decorator

    return log_endpoint
