"""Parts administration HTTP schemas."""
from typing import Optional
from pydantic import BaseModel, Field

# Part numbers are short codes (typically 10-12 characters).
PART_NUMBER_MAX_LENGTH = 100


class PartResponse(BaseModel):
    archived_at: Optional[str] = None
    id: int
    part_number: str
    description: str
    category: str
    unit_cost: float


class CreatePartRequest(BaseModel):
    part_number: str = Field(min_length=1, max_length=PART_NUMBER_MAX_LENGTH)
    description: str
    category: str
    unit_cost: float


class UpdatePartRequest(BaseModel):
    part_number: Optional[str] = Field(None, min_length=1, max_length=PART_NUMBER_MAX_LENGTH)
    description: Optional[str] = None
    category: Optional[str] = None
    unit_cost: Optional[float] = None
