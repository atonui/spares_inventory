"""The public work-order listing response."""
from typing import Optional
from pydantic import BaseModel


class WorkOrderResponse(BaseModel):
    id: int
    work_order_number: str
    customer_name: Optional[str]
    description: Optional[str]
    status: str
    assigned_engineer_id: Optional[int]
    engineer_name: Optional[str]

