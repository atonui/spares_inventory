"""Read-only, platform-authorized access to curated security events."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from backend.database_sql import is_postgres
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.security_events import safe_security_event_details
from backend.services.session_credentials import get_request_credential


_EVENT_FAMILIES = {
    "authentication": ("login_succeeded", "login_failed", "login_blocked", "account_locked"),
    "password": ("password_reset_requested", "password_reset_failed", "password_reset_completed", "password_changed"),
    "session": ("session_issued", "session_rotated", "session_revoked"),
}
_OUTCOMES = {"success", "failure", "blocked"}


def _utc_bound(value: str | None, field: str) -> str | None:
    if value in (None, ""):
        return None
    if len(value) > 40:
        raise HTTPException(status_code=422, detail=f"Invalid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail=f"Invalid {field}") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HTTPException(status_code=422, detail=f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def create_platform_security_events_router(*, get_connection, current_user) -> APIRouter:
    router = APIRouter(prefix="/api/platform", tags=["platform"])

    @router.get("/security-events")
    async def list_security_events(
        request: Request, response: Response, actor=Depends(current_user),
        event_family: str | None = None, outcome: str | None = None,
        account_match: bool | None = None, actor_user_id: int | None = None,
        start_at: str | None = None, end_at: str | None = None,
        limit: int = 50, offset: int = 0,
    ):
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
        if not isinstance(offset, int) or not 0 <= offset <= 100000:
            raise HTTPException(status_code=422, detail="offset must be between 0 and 100000")
        if event_family is not None and event_family not in _EVENT_FAMILIES:
            raise HTTPException(status_code=422, detail="Invalid event_family")
        if outcome is not None and outcome not in _OUTCOMES:
            raise HTTPException(status_code=422, detail="Invalid outcome")
        if actor_user_id is not None and actor_user_id <= 0:
            raise HTTPException(status_code=422, detail="actor_user_id must be positive")
        start = _utc_bound(start_at, "start_at")
        end = _utc_bound(end_at, "end_at")
        if start and end and start >= end:
            raise HTTPException(status_code=422, detail="start_at must be earlier than end_at")

        conn = get_connection()
        try:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Platform administration requires PostgreSQL")
        finally:
            conn.close()

        filters = []
        params = []
        if event_family is not None:
            filters.append("e.event = ANY(%s)")
            params.append(list(_EVENT_FAMILIES[event_family]))
        if outcome is not None:
            filters.append("e.outcome = %s")
            params.append(outcome)
        if account_match is not None:
            filters.append(
                "(e.actor_user_id IS NOT NULL OR e.details->>'account_match' = 'true')"
                if account_match else
                "(e.actor_user_id IS NULL AND e.details->>'account_match' = 'false')"
            )
        if actor_user_id is not None:
            filters.append("e.actor_user_id = %s")
            params.append(actor_user_id)
        if start:
            filters.append("e.created_at >= %s")
            params.append(start)
        if end:
            filters.append("e.created_at < %s")
            params.append(end)
        where = " WHERE " + " AND ".join(filters) if filters else ""

        with authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor), readonly=True,
        ) as (conn, _principal):
            total = conn.execute(
                "SELECT count(e.id) AS total FROM platform_security_events AS e" + where, tuple(params)
            ).fetchone()["total"]
            rows = conn.execute(
                """SELECT e.id, e.actor_user_id, e.event, e.outcome, e.details, e.created_at
                   FROM platform_security_events AS e
                   """ + where +
                " ORDER BY e.created_at DESC, e.id DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            ).fetchall()
            safe_rows = []
            for row in rows:
                item = dict(row)
                item["details"] = safe_security_event_details(item["event"], item["details"])
                safe_rows.append(item)
            return {"rows": safe_rows, "total": total, "limit": limit, "offset": offset}

    return router
