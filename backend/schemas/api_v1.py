"""Response schemas for the versioned native API."""

from pydantic import BaseModel

from backend.schemas.inventory_reads import InventoryResponse


class InventoryPageMetadata(BaseModel):
    limit: int
    next_cursor: str | None


class InventoryPageResponse(BaseModel):
    items: list[InventoryResponse]
    page: InventoryPageMetadata


class CsrfTokenResponse(BaseModel):
    csrf_token: str


class SuccessResponse(BaseModel):
    success: bool
