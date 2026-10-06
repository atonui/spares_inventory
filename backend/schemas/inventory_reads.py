"""Response contracts for inventory listing and dashboard statistics."""
from typing import Optional
from pydantic import BaseModel


class InventoryResponse(BaseModel):
    part_id: int
    is_allocated: bool
    id: int
    store_id: int
    part_number: str
    description: str
    store_name: str
    store_type: str
    store_owner: Optional[int]
    quantity: int
    min_threshold: int
    work_order: Optional[str]

class StatsResponse(BaseModel):
    in_transit_quantity: int = 0
    total_parts: int
    total_stores: int
    low_stock: int
    my_parts: int
