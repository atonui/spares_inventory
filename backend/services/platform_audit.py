"""Curated platform audit writes and safe reads."""

import json
from uuid import UUID


_DETAIL_FIELDS = {
    "support_session_started": {"support_session_id", "reason", "request_id", "operation"},
    "support_data_read": {"support_session_id", "resource", "operation", "request_id"},
    "support_access_denied": {"support_session_id", "resource", "operation", "request_id"},
    "support_session_ended": {"support_session_id", "operation", "request_id", "end_reason", "target_user_id"},
    "organization_created": {"invitation_created"},
    "company_role_changed": {"target_user_id", "role", "reason"},
    "platform_admin_granted": {"target_user_id"},
    "platform_admin_revoked": {"target_user_id"},
    "platform_announcement_saved": {"revision", "audience"},
    "platform_announcement_removed": {"revision"},
    "global_security_setting_changed": {"key", "value"},
    "organization_suspended": {"reason"},
    "organization_reactivated": {"reason"},
}


def record_platform_audit_event(
    conn, actor_user_id: int, action: str, result: str,
    organization_id=None, details=None,
) -> None:
    """Write only an allowlisted detail payload into the platform trail."""
    if action not in _DETAIL_FIELDS:
        raise ValueError("Unsupported platform audit action")
    safe_details = safe_platform_audit_details(action, details)
    conn.execute(
        """INSERT INTO platform_audit_events
           (actor_user_id, organization_id, action, result, details)
           VALUES (%s, %s, %s, %s, %s::jsonb)""",
        (actor_user_id, organization_id, action, result,
         json.dumps(safe_details, separators=(",", ":"))),
    )


def safe_platform_audit_details(action: str, details) -> dict:
    """Strip unknown keys from historical rows before returning them."""
    allowed = _DETAIL_FIELDS.get(action, set())
    if not isinstance(details, dict):
        return {}
    safe = {}
    for key, value in details.items():
        if key not in allowed:
            continue
        if key in {"support_session_id", "request_id"} and isinstance(value, str):
            try:
                safe[key] = str(UUID(value))
            except (ValueError, TypeError):
                pass
        elif key == "resource" and isinstance(value, str) and value in {"session", "accounts", "inventory", "work-orders", "equipment", "equipment-history", "movements"}:
            safe[key] = value
        elif key == "operation" and isinstance(value, str) and value in {"start", "lookup", "end"}:
            safe[key] = value
        elif key == "end_reason" and isinstance(value, str) and value in {
            "user_logout", "password_changed", "sessions_revoked", "platform_admin_revoked", "expired",
            "membership_removed", "membership_deactivated",
        }:
            safe[key] = value
        elif key == "invitation_created" and value is True:
            safe[key] = True
        elif key == "target_user_id" and isinstance(value, int) and not isinstance(value, bool) and value > 0:
            safe[key] = value
        elif key == "role" and isinstance(value, str) and value in {"owner", "admin", "manager", "engineer"}:
            safe[key] = value
        elif key == "reason" and isinstance(value, str) and 10 <= len(value) <= 500:
            safe[key] = value
        elif key == "revision" and isinstance(value, str) and 1 <= len(value) <= 100:
            safe[key] = value
        elif key == "audience" and isinstance(value, str) and value in {"everyone", "authenticated", "roles"}:
            safe[key] = value
        elif key == "key" and isinstance(value, str) and value in {
            "max_login_attempts", "lockout_duration_minutes",
            "session_duration_hours", "remember_me_duration_days",
        }:
            safe[key] = value
        elif key == "value" and isinstance(value, int) and not isinstance(value, bool):
            limits = {
                "max_login_attempts": 100,
                "lockout_duration_minutes": 1440,
                "session_duration_hours": 720,
                "remember_me_duration_days": 365,
            }
            setting_key = details.get("key")
            if setting_key in limits and 1 <= value <= limits[setting_key]:
                safe[key] = value
    return safe
