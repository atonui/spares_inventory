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


class MobilePartResponse(BaseModel):
    id: int
    part_number: str
    description: str
    category: str


class PartPageResponse(BaseModel):
    items: list[MobilePartResponse]
    page: InventoryPageMetadata


class MobileOverviewResponse(BaseModel):
    total_parts: int
    total_stores: int
    my_equipment: int
    my_parts: int


class MobileEquipmentResponse(BaseModel):
    id: int
    equipment_name: str
    make: str
    model: str
    serial_number: str
    assigned_user_id: int | None
    assigned_user_name: str | None
    next_calibration_date: str | None
    status: str


class EquipmentPageResponse(BaseModel):
    items: list[MobileEquipmentResponse]
    page: InventoryPageMetadata


class MobileMovementResponse(BaseModel):
    id: int
    from_store_name: str | None
    to_store_name: str | None
    part_number: str
    quantity: int
    movement_type: str
    work_order: str | None
    created_by_name: str
    created_at: str
    transfer_status: str | None
    completed_by_name: str | None
    completed_at: str | None


class MovementPageResponse(BaseModel):
    items: list[MobileMovementResponse]
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
