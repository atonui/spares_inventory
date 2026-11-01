"""Privacy-limited global authentication and account security events."""

import json
from uuid import UUID, uuid4


_EVENT_DETAILS = {
    "login_succeeded": {"is_mobile", "remember_me"},
    "login_failed": {"account_match", "reason"},
    "login_blocked": {"account_match"},
    "account_locked": {"account_match"},
    "password_reset_requested": {"account_match"},
    "password_reset_failed": {"reason"},
    "password_reset_completed": set(),
    "password_changed": set(),
    "session_revoked": {"is_mobile", "reason", "session_count", "target_user_id"},
    "session_issued": {"is_mobile", "source"},
    "session_rotated": {"is_mobile", "source"},
}
_OUTCOMES = {"success", "failure", "blocked"}
_SOURCES = {"browser_login", "native_login", "mobile_pairing", "native_refresh"}
_REASONS = {"membership_removed", "membership_deactivated", "user_logout", "user_revoked", "other_sessions_revoked", "mobile_access_revoked", "session_replaced", "refresh_reuse", "account_unavailable", "invalid_credentials", "invalid_token", "token_expired", "weak_password", "too_many_attempts"}


def safe_security_event_details(event: str, details) -> dict:
    allowed = _EVENT_DETAILS.get(event, set())
    if not isinstance(details, dict):
        return {}
    safe = {}
    for key, value in details.items():
        if key == "account_match" and type(value) is bool:
            safe[key] = value
        elif key in {"is_mobile", "remember_me"} and type(value) is bool:
            safe[key] = value
        elif key == "source" and isinstance(value, str) and value in _SOURCES:
            safe[key] = value
        elif key == "target_user_id" and type(value) is int and 0 < value < 9223372036854775808:
            safe[key] = value
        elif key == "session_count" and type(value) is int and 0 < value <= 2147483647:
            safe[key] = value
        elif key == "reason" and isinstance(value, str) and value in _REASONS:
            safe[key] = value
    return {key: value for key, value in safe.items() if key in allowed}


def record_security_event(
    conn,
    *,
    event: str,
    outcome: str,
    actor_user_id: int | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details=None,
) -> None:
    """Write one global event; unmatched identities have no tenant or identifier."""
    if event not in _EVENT_DETAILS:
        raise ValueError("Unsupported security event")
    if outcome not in _OUTCOMES:
        raise ValueError("Unsupported security event outcome")
    if actor_user_id is not None and (type(actor_user_id) is not int or actor_user_id <= 0):
        raise ValueError("actor_user_id must be a positive integer")
    try:
        request_id = str(UUID(request_id)) if request_id else str(uuid4())
    except (ValueError, TypeError):
        request_id = str(uuid4())
    conn.execute(
        """INSERT INTO platform_security_events
           (actor_user_id,event,outcome,request_id,ip_address,user_agent,details)
           VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)""",
        (actor_user_id, event, outcome, request_id,
         ip_address[:64] if isinstance(ip_address, str) else None,
         user_agent[:200] if isinstance(user_agent, str) else None,
         json.dumps(safe_security_event_details(event, details), separators=(",", ":"))),
    )
