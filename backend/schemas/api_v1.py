"""Response schemas for the versioned native API."""

from pydantic import BaseModel

from backend.schemas.inventory_reads import InventoryResponse
from backend.schemas.stores import StoreResponse


class InventoryPageMetadata(BaseModel):
    limit: int
    next_cursor: str | None


class InventoryPageResponse(BaseModel):
    items: list[InventoryResponse]
    page: InventoryPageMetadata


class StorePageResponse(BaseModel):
    items: list[StoreResponse]
    page: InventoryPageMetadata


class PendingTransferResponse(BaseModel):
    id: int
    quantity: int
    created_at: str
    created_by: int
    from_store_id: int
    to_store_id: int
    part_number: str
    description: str
    from_store_name: str
    to_store_name: str
    created_by_name: str
    work_order: str | None
    status: str
    can_receive: bool
    can_return: bool


class PendingTransferPageResponse(BaseModel):
    items: list[PendingTransferResponse]
    page: InventoryPageMetadata


class CsrfTokenResponse(BaseModel):
    csrf_token: str


class SuccessResponse(BaseModel):
    success: bool
