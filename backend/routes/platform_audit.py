"""Read-only, platform-authorized access to curated audit events."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.database_sql import is_postgres
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.session_credentials import get_request_credential
from backend.services.platform_audit import safe_platform_audit_details


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


def create_platform_audit_router(*, get_connection, current_user) -> APIRouter:
    router = APIRouter(prefix="/api/platform", tags=["platform"])

    @router.get("/audit-events")
    async def list_audit_events(
        request: Request, actor=Depends(current_user),
        actor_user_id: int | None = None, organization_id: str | None = None,
        action: str | None = None, result: str | None = None,
        start_at: str | None = None, end_at: str | None = None,
        limit: int = 50, offset: int = 0,
    ):
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
        if not isinstance(offset, int) or not 0 <= offset <= 100000:
            raise HTTPException(status_code=422, detail="offset must be between 0 and 100000")
        if actor_user_id is not None and actor_user_id <= 0:
            raise HTTPException(status_code=422, detail="actor_user_id must be positive")
        org_id = None
        if organization_id:
            try:
                org_id = UUID(organization_id)
            except (ValueError, TypeError):
                raise HTTPException(status_code=422, detail="Invalid organization_id") from None
        for field, value in (("action", action), ("result", result)):
            if value is not None and (not value.strip() or len(value) > 100):
                raise HTTPException(status_code=422, detail=f"Invalid {field}")
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
        for column, value in (("actor_user_id", actor_user_id), ("organization_id", org_id),
                              ("action", action), ("result", result)):
            if value is not None:
                filters.append(f"e.{column} = %s")
                params.append(value)
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
                "SELECT count(*) AS total FROM platform_audit_events AS e" + where, tuple(params)
            ).fetchone()["total"]
            rows = conn.execute(
                """SELECT e.id, e.actor_user_id, e.organization_id, e.action, e.result,
                          e.details, e.created_at, u.name AS actor_name,
                          o.name AS organization_name, o.slug AS organization_slug
                   FROM platform_audit_events AS e
                   LEFT JOIN users AS u ON u.id = e.actor_user_id
                   LEFT JOIN organizations AS o ON o.id = e.organization_id""" + where +
                " ORDER BY e.created_at DESC, e.id DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            ).fetchall()
            safe_rows = []
            for row in rows:
                item = dict(row)
                item["organization_id"] = str(item["organization_id"]) if item["organization_id"] else None
                item["details"] = safe_platform_audit_details(item["action"], item["details"])
                safe_rows.append(item)
            return {"rows": safe_rows, "total": total,
                    "limit": limit, "offset": offset}

    return router
