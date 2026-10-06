"""Response contracts for movement history and activity logs."""
from typing import Optional
from pydantic import BaseModel


class MovementResponse(BaseModel):
    transfer_status: Optional[str] = None
    completed_by_name: Optional[str] = None
    completed_at: Optional[str] = None
    id: int
    from_store_name: Optional[str]
    to_store_name: Optional[str]
    part_number: str
    quantity: int
    movement_type: str
    work_order: Optional[str]
    created_by_name: str
    created_at: str

class ActivityLogResponse(BaseModel):
    id: int
    user_id: int
    username: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[int]
    details: Optional[str]
    ip_address: Optional[str]
    status: str
    error_message: Optional[str]
    created_at: str
