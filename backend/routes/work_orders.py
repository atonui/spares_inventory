"""Work-order listing routes with explicit application dependencies."""
import sqlite3
from collections.abc import Callable
from contextlib import closing
import psycopg
from fastapi import APIRouter, Depends, Request
from backend.schemas.work_orders import WorkOrderResponse
from backend.services.work_orders import list_work_orders


def create_work_order_router(*, get_connection: Callable[[], sqlite3.Connection],
                             current_user: Callable) -> APIRouter:
    router = APIRouter()

    @router.get('/api/work-orders', response_model=list[WorkOrderResponse])
    async def get_work_orders(user_id: int = Depends(current_user), request: Request = None):
        """Get work orders"""
        conn = get_connection()
        if isinstance(conn, psycopg.Connection):
            from backend.services.tenant_context import authenticated_tenant_transaction

            expected_user_id = user_id.user_id if hasattr(user_id, "user_id") else user_id
            with authenticated_tenant_transaction(
                lambda: conn,
                session_token=request.cookies.get("session_token") if request else None,
                expected_user_id=expected_user_id,
                readonly=True,
            ) as (tenant_conn, principal):
                return list_work_orders(tenant_conn, principal)
        with closing(conn) as conn:
            return list_work_orders(conn, user_id)

    return router
