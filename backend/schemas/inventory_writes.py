"""Request contracts for stock-changing inventory routes."""
from typing import List, Optional
from pydantic import BaseModel, Field

class AddStockRequest(BaseModel):
    part_id: int
    store_id: int
    quantity: int = Field(gt=0, strict=True)
    work_order_number: Optional[str] = None

class ImportBalanceRow(BaseModel):
    part_number: str = Field(min_length=1, max_length=200)
    quantity: int = Field(ge=0, le=9007199254740991, strict=True)
    expected_quantity: Optional[int] = Field(..., ge=0, le=9007199254740991, strict=True)

class ImportBalancesRequest(BaseModel):
    store_id: int
    rows: List[ImportBalanceRow] = Field(min_length=1, max_length=1000)

class UpdateStockRequest(BaseModel):
    inventory_id: int
    new_quantity: int = Field(ge=0, strict=True)

class TransferConfirmationRequest(BaseModel):
    confirmed: bool = Field(strict=True)
    notes: Optional[str] = Field(default=None, max_length=1000)

class TransferStockRequest(BaseModel):
    replenishment: bool = Field(default=False, strict=True)
    inventory_id: int
    to_store_id: int
    quantity: int = Field(gt=0, strict=True)

class ConsumeStockRequest(BaseModel):
    inventory_id: int
    quantity: int = Field(gt=0, strict=True)
    work_order_number: str
    notes: Optional[str] = None
