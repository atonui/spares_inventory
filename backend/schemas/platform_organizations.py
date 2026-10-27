"""Platform-only organization lifecycle requests."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class PlatformOrganizationStatusRequest(BaseModel):
    action: Literal["suspend", "reactivate"]
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_and_require_reason(cls, value):
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("A reason is required")
        return cleaned


class PlatformCompanyRoleUpdateRequest(BaseModel):
    role: Literal["admin", "manager", "engineer"]
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_and_require_reason(cls, value):
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("A reason is required")
        return cleaned
