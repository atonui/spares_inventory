"""Versioned native read routes for mobile overview, equipment and movements."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.database_sql import execute
from backend.schemas.api_v1 import (
    EquipmentPageResponse,
    MobileOverviewResponse,
    MovementPageResponse,
)
from backend.services.mobile_list_cursor import decode_list_cursor, encode_list_cursor
from backend.services.principals import AuthenticatedPrincipal
from backend.services.session_credentials import get_request_credential
from backend.services.tenant_context import authenticated_database_transaction
from backend.temporal_contract import instant_response


def create_mobile_read_router(*, get_connection, current_user, cursor_secret: str) -> APIRouter:
    router = APIRouter()

    def native_cursor(request: Request, kind: str, cursor: str | None):
        credential = get_request_credential(request)
        if credential.transport != "bearer":
            raise HTTPException(status_code=401, detail="Not authenticated")
        try:
            last_id = decode_list_cursor(cursor_secret, kind, cursor)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid continuation cursor") from None
        return credential, last_id

    def page(rows, kind: str, limit: int):
        items = [dict(row) for row in rows[:limit]]
        next_cursor = (
            encode_list_cursor(cursor_secret, kind, items[-1]["id"])
            if len(rows) > limit and items
            else None
        )
        return {"items": items, "page": {"limit": limit, "next_cursor": next_cursor}}

    @router.get("/api/v1/overview", response_model=MobileOverviewResponse)
    @instant_response
    async def get_mobile_overview(
        request: Request,
        user_id: int = Depends(current_user),
    ):
        """Return the mobile dashboard totals for the authenticated company member."""
        credential = get_request_credential(request)
        if credential.transport != "bearer":
            raise HTTPException(status_code=401, detail="Not authenticated")

        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=credential.value,
            readonly=True,
        ) as (conn, principal):
            actor_id = (
                principal.user_id
                if isinstance(principal, AuthenticatedPrincipal)
                else principal
            )

            def count(query: str, params=()):
                row = execute(conn, query, params).fetchone()
                return row["count"] if isinstance(row, dict) else row[0]

            return {
                "total_parts": count(
                    "SELECT COUNT(DISTINCT part_number) AS count FROM parts WHERE archived_at IS NULL"
                ),
                "total_stores": count(
                    "SELECT COUNT(*) AS count FROM stores WHERE archived_at IS NULL"
                ),
                "my_equipment": count(
                    "SELECT COUNT(*) AS count FROM equipment WHERE status='active' AND assigned_user_id=?",
                    (actor_id,),
                ),
                "my_parts": count(
                    """SELECT COUNT(DISTINCT i.part_id) AS count
                       FROM inventory i JOIN stores s ON i.store_id=s.id
                       WHERE s.assigned_user_id=?""",
                    (actor_id,),
                ),
            }

    @router.get("/api/v1/equipment", response_model=EquipmentPageResponse)
    @instant_response
    async def get_mobile_equipment(
        request: Request,
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = Query(default=None, max_length=2048),
        user_id: int = Depends(current_user),
    ):
        """List active equipment visible to the current user in stable ID order."""
        credential, last_id = native_cursor(request, "equipment", cursor)
        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=credential.value,
            readonly=True,
        ) as (conn, principal):
            actor_id = (
                principal.user_id
                if isinstance(principal, AuthenticatedPrincipal)
                else principal
            )
            if isinstance(principal, AuthenticatedPrincipal):
                can_see_all = principal.company_role in {"owner", "admin"}
            else:
                user = execute(
                    conn, "SELECT role FROM users WHERE id=?", (actor_id,)
                ).fetchone()
                can_see_all = bool(user and user["role"] == "admin")

            visibility = "" if can_see_all else " AND e.assigned_user_id=?"
            params = [last_id]
            if not can_see_all:
                params.append(actor_id)
            params.append(limit + 1)
            rows = execute(
                conn,
                f"""SELECT e.id, e.equipment_name, e.make, e.model, e.serial_number,
                           e.assigned_user_id, u.name AS assigned_user_name,
                           e.next_calibration_date, e.status
                    FROM equipment e
                    LEFT JOIN users u ON e.assigned_user_id=u.id
                    WHERE e.status='active' AND e.id>?{visibility}
                    ORDER BY e.id
                    LIMIT ?""",
                tuple(params),
            ).fetchall()
            return page(rows, "equipment", limit)

    @router.get("/api/v1/inventory/movements", response_model=MovementPageResponse)
    @instant_response
    async def get_mobile_movements(
        request: Request,
        part_id: int = Query(..., ge=1),
        store_id: int = Query(..., ge=1),
        limit: int = Query(default=20, ge=1, le=100),
        cursor: str | None = Query(default=None, max_length=2048),
        user_id: int = Depends(current_user),
    ):
        """List recent movement history for one part and store in descending ID order."""
        credential, before_id = native_cursor(request, "movements", cursor)
        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=credential.value,
            readonly=True,
        ) as (conn, _principal):
            rows = execute(
                conn,
                """SELECT m.id, s1.name AS from_store_name, s2.name AS to_store_name,
                          p.part_number, m.quantity, m.movement_type,
                          wo.work_order_number AS work_order, u.name AS created_by_name,
                          m.created_at,
                          CASE WHEN m.movement_type='transfer'
                               THEN COALESCE(t.status, 'completed') END AS transfer_status,
                          u2.name AS completed_by_name, t.completed_at
                   FROM movements m
                   LEFT JOIN stock_transfers t ON t.movement_id=m.id
                   LEFT JOIN users u2 ON u2.id=t.completed_by
                   LEFT JOIN stores s1 ON m.from_store_id=s1.id
                   LEFT JOIN stores s2 ON m.to_store_id=s2.id
                   JOIN parts p ON m.part_id=p.id
                   LEFT JOIN work_orders wo ON m.work_order_id=wo.id
                   JOIN users u ON m.created_by=u.id
                   WHERE m.part_id=?
                     AND (m.from_store_id=? OR m.to_store_id=?)
                     AND m.id < ?
                   ORDER BY m.id DESC
                   LIMIT ?""",
                (part_id, store_id, store_id, before_id or 9223372036854775807, limit + 1),
            ).fetchall()
            return page(rows, "movements", limit)

    return router
