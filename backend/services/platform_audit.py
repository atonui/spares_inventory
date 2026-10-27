"""Curated platform audit writes and safe reads."""

import json


_DETAIL_FIELDS = {
    "organization_created": {"invitation_created"},
    "company_role_changed": {"target_user_id", "role"},
    "platform_admin_granted": {"target_user_id"},
    "platform_admin_revoked": {"target_user_id"},
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
        if key == "invitation_created" and value is True:
            safe[key] = True
        elif key == "target_user_id" and isinstance(value, int) and not isinstance(value, bool) and value > 0:
            safe[key] = value
        elif key == "role" and isinstance(value, str) and value in {"owner", "admin", "manager", "engineer"}:
            safe[key] = value
    return safe
