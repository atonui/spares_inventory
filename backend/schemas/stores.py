"""Store and store-type HTTP schemas."""
from typing import Optional
from pydantic import BaseModel, Field, validator


class StoreResponse(BaseModel):
    archived_at: Optional[str] = None
    id: int
    name: str
    type: str
    location: Optional[str]
    assigned_user_id: Optional[int]

class StoreTypeResponse(BaseModel):
    id: int
    type_code: str
    type_name: str
    description: Optional[str]
    is_active: bool
    display_order: int

class CreateStoreTypeRequest(BaseModel):
    type_code: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z_]+$")
    type_name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    display_order: int = Field(default=0, ge=0)

    @validator("type_code")
    def type_code_lowercase(cls, v):
        return v.lower().strip()

class UpdateStoreTypeRequest(BaseModel):
    type_name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = Field(None, ge=0)

class CreateStoreRequest(BaseModel):
    name: str
    type: str
    location: Optional[str] = None
    assigned_user_id: Optional[int] = None

class UpdateStoreRequest(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    location: Optional[str] = None
    assigned_user_id: Optional[int] = None
