"""Write mutation activity using the caller's transaction and connection."""
import json


def record_activity(conn, *, user_id, username, action, resource_type=None,
                    resource_id=None, details=None, status='success',
                    error_message=None, ip_address=None, user_agent=None):
    conn.execute('''INSERT INTO activity_logs
        (user_id,username,action,resource_type,resource_id,details,ip_address,
         user_agent,status,error_message) VALUES(?,?,?,?,?,?,?,?,?,?)''',
        (user_id or None, username, action, resource_type, resource_id,
         json.dumps(details) if details else None, ip_address, user_agent,
         status, error_message))
