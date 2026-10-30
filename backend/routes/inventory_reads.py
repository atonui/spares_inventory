"""Read-only inventory routes with explicit application dependencies."""
from backend.services.session_credentials import get_request_credential
from backend.temporal_contract import register_instant_comparison
from backend.temporal_contract import instant_response
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from backend.database_sql import execute, is_postgres
from backend.schemas.inventory_reads import InventoryResponse, StatsResponse
from backend.schemas.api_v1 import InventoryPageResponse, StorePageResponse, PendingTransferPageResponse
from backend.services.mobile_list_cursor import decode_list_cursor, encode_list_cursor
from backend.services.api_v1_pagination import (
    decode_inventory_cursor,
    encode_inventory_cursor,
)
from backend.services.tenant_context import authenticated_database_transaction
from backend.services.principals import AuthenticatedPrincipal


def create_inventory_read_router(*, get_connection, current_user,
                                 transfer_permission, cursor_secret: str) -> APIRouter:
    """Keep transfer policy and database ownership shared with stock writes."""
    router = APIRouter()
    get_db_connection = get_connection
    get_current_user = current_user
    transfer_permissions = transfer_permission

    @router.get("/api/v1/inventory", response_model=InventoryPageResponse)
    @instant_response
    async def get_inventory_v1(
        request: Request,
        limit: int = Query(
            default=50,
            ge=1,
            le=100,
            description="Page size. Defaults to 50 and must be between 1 and 100.",
        ),
        cursor: str | None = Query(
            default=None,
            max_length=2048,
            description="Opaque continuation cursor returned by this endpoint.",
        ),
        user_id: int = Depends(get_current_user),
    ):
        """Get one authenticated tenant's inventory page using a signed cursor."""
        credential = get_request_credential(request)
        if credential.transport != "bearer":
            raise HTTPException(status_code=401, detail="Not authenticated")
        try:
            continuation = (
                decode_inventory_cursor(cursor_secret, cursor) if cursor is not None else None
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid inventory cursor") from None

        where = "WHERE p.archived_at IS NULL AND s.archived_at IS NULL"
        params = []
        cursor_cte = ""
        cursor_join = ""
        if continuation is not None:
            cursor_cte = """
                WITH cursor_key AS (
                    SELECT cp.part_number, cs.name AS store_name
                    FROM inventory cursor_inventory
                    JOIN parts cp ON cursor_inventory.part_id = cp.id
                    JOIN stores cs ON cursor_inventory.store_id = cs.id
                    WHERE cursor_inventory.id = ?
                      AND cp.archived_at IS NULL
                      AND cs.archived_at IS NULL
                )
            """
            cursor_join = "CROSS JOIN cursor_key"
            where += " AND (p.part_number, s.name, i.id) > (cursor_key.part_number, cursor_key.store_name, ?)"
            params.extend([continuation.inventory_id, continuation.inventory_id])
        query = f"""
            {cursor_cte}
            SELECT
                i.id,
                i.store_id,
                i.part_id,
                (i.work_order_id IS NOT NULL) AS is_allocated,
                p.part_number,
                p.description,
                s.name AS store_name,
                s.type AS store_type,
                s.assigned_user_id AS store_owner,
                i.quantity,
                i.min_threshold,
                wo.work_order_number AS work_order
            FROM inventory i
            JOIN parts p ON i.part_id = p.id
            JOIN stores s ON i.store_id = s.id
            LEFT JOIN work_orders wo ON i.work_order_id = wo.id
            {cursor_join}
            {where}
            ORDER BY p.part_number, s.name, i.id
            LIMIT ?
        """
        params.append(limit + 1)

        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=credential.value,
            readonly=True,
        ) as (conn, _principal):
            if not is_postgres(conn):
                register_instant_comparison(conn)
            rows = execute(conn, query, tuple(params)).fetchall()

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        next_cursor = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = encode_inventory_cursor(
                cursor_secret,
                last["id"],
            )
        return {
            "items": [dict(row) for row in page_rows],
            "page": {"limit": limit, "next_cursor": next_cursor},
        }

    @router.get("/api/inventory", response_model=List[InventoryResponse])
    @instant_response
    async def get_inventory(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get inventory with full visibility for engineers"""
        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, _principal):
            if not is_postgres(conn):
                register_instant_comparison(conn)
            query = """
            SELECT
                i.id,
                i.store_id,
                i.part_id,
                (i.work_order_id IS NOT NULL) AS is_allocated,
                p.part_number,
                p.description,
                s.name as store_name,
                s.type as store_type,
                s.assigned_user_id as store_owner,
                i.quantity,
                i.min_threshold,
                wo.work_order_number as work_order
            FROM inventory i
            JOIN parts p ON i.part_id = p.id
            JOIN stores s ON i.store_id = s.id
            LEFT JOIN work_orders wo ON i.work_order_id = wo.id
            WHERE p.archived_at IS NULL AND s.archived_at IS NULL
            ORDER BY p.part_number, s.name
        """

            inventory = execute(conn, query).fetchall()

        return [dict(item) for item in inventory]

    @router.get("/api/stats", response_model=StatsResponse)
    @instant_response
    async def get_stats(user_id: int = Depends(get_current_user), request: Request = None):
        """Get dashboard statistics"""
        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            if not is_postgres(conn):
                register_instant_comparison(conn)
            actor_id = principal.user_id if isinstance(principal, AuthenticatedPrincipal) else principal
            # Total unique parts
            total_parts = execute(conn, "SELECT COUNT(DISTINCT part_number) AS count FROM parts WHERE archived_at IS NULL").fetchone()
            total_parts = total_parts["count"] if isinstance(total_parts, dict) else total_parts[0]

            # Total stores
            total_stores = execute(conn, "SELECT COUNT(*) AS count FROM stores WHERE archived_at IS NULL").fetchone()
            total_stores = total_stores["count"] if isinstance(total_stores, dict) else total_stores[0]

            # Low stock items
            low_stock = execute(conn, "SELECT COUNT(*) AS count FROM inventory i JOIN parts p ON p.id=i.part_id JOIN stores s ON s.id=i.store_id WHERE i.min_threshold > 0 AND i.quantity < i.min_threshold AND i.work_order_id IS NULL AND p.archived_at IS NULL AND s.archived_at IS NULL").fetchone()
            low_stock = low_stock["count"] if isinstance(low_stock, dict) else low_stock[0]

            # User's parts (stores they own)
            my_parts = execute(conn,
                """
            SELECT COUNT(DISTINCT i.part_id)
            FROM inventory i
            JOIN stores s ON i.store_id = s.id
            WHERE s.assigned_user_id = ?
        """,
                (actor_id,),
            ).fetchone()
            my_parts = my_parts["count"] if isinstance(my_parts, dict) else my_parts[0]

            in_transit_quantity = execute(conn, "SELECT COALESCE(SUM(m.quantity),0) AS quantity FROM stock_transfers t JOIN movements m ON m.id=t.movement_id WHERE t.status='in_transit'").fetchone()
            in_transit_quantity = in_transit_quantity["quantity"] if isinstance(in_transit_quantity, dict) else in_transit_quantity[0]

        return {
            "in_transit_quantity": in_transit_quantity,
            "total_parts": total_parts,
            "total_stores": total_stores,
            "low_stock": low_stock,
            "my_parts": my_parts,
        }

    @router.get('/api/inventory/transfers')
    @instant_response
    async def pending_transfers(user_id: int = Depends(get_current_user), request: Request = None):
        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            if not is_postgres(conn):
                register_instant_comparison(conn)
            actor = principal if isinstance(principal, AuthenticatedPrincipal) else execute(
                conn, "SELECT role FROM users WHERE id = ?", (principal,)
            ).fetchone()
            rows=execute(conn, """SELECT m.id,m.quantity,m.created_at,m.created_by,m.from_store_id,m.to_store_id,
                p.part_number,p.description,s1.name AS from_store_name,s2.name AS to_store_name,
                s1.assigned_user_id AS source_owner,s2.assigned_user_id AS dest_owner,s2.type AS dest_type,
                u.name AS created_by_name,wo.work_order_number AS work_order,t.status
                FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
                JOIN parts p ON p.id=m.part_id JOIN stores s1 ON s1.id=m.from_store_id
                JOIN stores s2 ON s2.id=m.to_store_id JOIN users u ON u.id=m.created_by
                LEFT JOIN work_orders wo ON wo.id=m.work_order_id
                WHERE t.status='in_transit' ORDER BY m.created_at,m.id""").fetchall()
            result=[]
            for row in rows:
                item=dict(row)
                actor_id = principal.user_id if isinstance(principal, AuthenticatedPrincipal) else principal
                item['can_receive'],item['can_return']=transfer_permissions(actor,row,actor_id)
                result.append(item)
            return result

    def native_continuation(request, kind, cursor):
        credential = get_request_credential(request)
        if credential.transport != 'bearer':
            raise HTTPException(status_code=401, detail='Not authenticated')
        try:
            last_id = decode_list_cursor(cursor_secret, kind, cursor)
        except ValueError:
            raise HTTPException(status_code=400, detail='Invalid continuation cursor') from None
        return credential, last_id

    def page_response(rows, kind, limit):
        visible = rows[:limit]
        next_cursor = encode_list_cursor(cursor_secret, kind, visible[-1]['id']) if len(rows) > limit else None
        return {'items': visible, 'page': {'limit': limit, 'next_cursor': next_cursor}}

    @router.get('/api/v1/stores', response_model=StorePageResponse)
    @instant_response
    async def stores_v1(request: Request, limit: int = Query(50, ge=1, le=100),
                        cursor: str | None = Query(None, max_length=2048),
                        user_id=Depends(get_current_user)):
        """List active stores, including empty stores, in ascending ID order."""
        credential, last_id = native_continuation(request, 'stores', cursor)
        with authenticated_database_transaction(get_db_connection, principal_or_user=user_id,
                session_token=credential.value, readonly=True) as (conn, _principal):
            rows = execute(conn, '''SELECT id,name,type,location,assigned_user_id,archived_at
                FROM stores WHERE archived_at IS NULL AND id > ? ORDER BY id LIMIT ?''',
                (last_id, limit + 1)).fetchall()
            return page_response([dict(row) for row in rows], 'stores', limit)

    @router.get('/api/v1/inventory/transfers', response_model=PendingTransferPageResponse)
    @instant_response
    async def transfers_v1(request: Request, limit: int = Query(50, ge=1, le=100),
                           cursor: str | None = Query(None, max_length=2048),
                           user_id=Depends(get_current_user)):
        """List pending transfers in ascending movement ID order with action permissions."""
        credential, last_id = native_continuation(request, 'transfers', cursor)
        with authenticated_database_transaction(get_db_connection, principal_or_user=user_id,
                session_token=credential.value, readonly=True) as (conn, principal):
            actor = principal if isinstance(principal, AuthenticatedPrincipal) else execute(
                conn, 'SELECT role FROM users WHERE id = ?', (principal,)).fetchone()
            actor_id = principal.user_id if isinstance(principal, AuthenticatedPrincipal) else principal
            rows = execute(conn, '''SELECT m.id,m.quantity,m.created_at,m.created_by,m.from_store_id,m.to_store_id,
                p.part_number,p.description,s1.name AS from_store_name,s2.name AS to_store_name,
                s1.assigned_user_id AS source_owner,s2.assigned_user_id AS dest_owner,s2.type AS dest_type,
                u.name AS created_by_name,wo.work_order_number AS work_order,t.status
                FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
                JOIN parts p ON p.id=m.part_id JOIN stores s1 ON s1.id=m.from_store_id
                JOIN stores s2 ON s2.id=m.to_store_id JOIN users u ON u.id=m.created_by
                LEFT JOIN work_orders wo ON wo.id=m.work_order_id
                WHERE t.status='in_transit' AND m.id > ? ORDER BY m.id LIMIT ?''',
                (last_id, limit + 1)).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item['can_receive'], item['can_return'] = transfer_permissions(actor, row, actor_id)
                result.append(item)
            return page_response(result, 'transfers', limit)

    return router
