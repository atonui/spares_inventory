"""Work-order listing routes with explicit application dependencies."""
import sqlite3
from collections.abc import Callable
from contextlib import closing
from fastapi import APIRouter, Depends, Request
from backend.schemas.work_orders import WorkOrderResponse
from backend.services.work_orders import list_work_orders


def create_work_order_router(*, get_connection: Callable[[], sqlite3.Connection],
                             current_user: Callable) -> APIRouter:
    router = APIRouter()

    @router.get('/api/work-orders', response_model=list[WorkOrderResponse])
    async def get_work_orders(user_id: int = Depends(current_user), request: Request = None):
        """Get work orders"""
        with closing(get_connection()) as conn:
            return list_work_orders(conn, user_id)

    return router
