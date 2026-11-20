"""Work-order listing routes with explicit application dependencies."""
from collections.abc import Callable

from fastapi import APIRouter, Depends, Request

from backend.schemas.work_orders import WorkOrderResponse
from backend.services.session_credentials import get_request_credential
from backend.services.tenant_context import authenticated_tenant_transaction
from backend.services.work_orders import list_work_orders


def create_work_order_router(*, get_connection: Callable, current_user: Callable) -> APIRouter:
    router = APIRouter()

    @router.get('/api/work-orders', response_model=list[WorkOrderResponse])
    async def get_work_orders(user_id: int = Depends(current_user), request: Request = None):
        """Get work orders"""
        expected_user_id = user_id.user_id if hasattr(user_id, "user_id") else user_id
        with authenticated_tenant_transaction(
            get_connection,
            session_token=get_request_credential(request).value if request else None,
            expected_user_id=expected_user_id,
            readonly=True,
        ) as (tenant_conn, principal):
            return list_work_orders(tenant_conn, principal)

    return router
