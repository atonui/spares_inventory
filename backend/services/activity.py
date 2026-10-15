"""Write mutation activity using the caller's transaction and connection."""
import json
from backend.database_sql import execute
from .principals import AuthenticatedPrincipal


def record_activity(conn, *, user_id, username, action, resource_type=None,
                    resource_id=None, details=None, status='success',
                    error_message=None, ip_address=None, user_agent=None):
    principal = user_id if isinstance(user_id, AuthenticatedPrincipal) else None
    if principal is not None:
        user_id = user_id.user_id
    values = (user_id or None, username, action, resource_type, resource_id,
              json.dumps(details) if details else None, ip_address, user_agent,
              status, error_message)
    if hasattr(conn, "info"):
        organization_id = principal.organization_id if principal else conn.execute(
            "SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid AS organization_id"
        ).fetchone()["organization_id"]
        execute(
            conn,
            """INSERT INTO activity_logs
               (organization_id,user_id,username,action,resource_type,resource_id,
                details,ip_address,user_agent,status,error_message)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (organization_id, *values),
        )
    else:
        execute(conn, '''INSERT INTO activity_logs
            (user_id,username,action,resource_type,resource_id,details,ip_address,
             user_agent,status,error_message) VALUES(?,?,?,?,?,?,?,?,?,?)''', values)
