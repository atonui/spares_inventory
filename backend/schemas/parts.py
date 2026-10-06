"""Parts administration HTTP schemas."""
from typing import Optional
from pydantic import BaseModel


class PartResponse(BaseModel):
    archived_at: Optional[str] = None
    id: int
    part_number: str
    description: str
    category: str
    unit_cost: float


class CreatePartRequest(BaseModel):
    part_number: str
    description: str
    category: str
    unit_cost: float


class UpdatePartRequest(BaseModel):
    part_number: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    unit_cost: Optional[float] = None
