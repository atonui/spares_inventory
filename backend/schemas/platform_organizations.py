"""Platform-only organization lifecycle requests."""

from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

from backend.services.platform_audit import normalize_platform_audit_reason


class PlatformOrganizationStatusRequest(BaseModel):
    action: Literal["suspend", "reactivate"]
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("reason", mode="before")
    @classmethod
    def strip_and_require_reason(cls, value):
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        if normalize_platform_audit_reason(cleaned) is None:
            raise ValueError("Reason must be 10–500 characters and must not contain contact details, links, query parameters, or credentials")
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
        if normalize_platform_audit_reason(cleaned) is None:
            raise ValueError("Reason must be 10–500 characters and must not contain contact details, links, query parameters, or credentials")
        return cleaned


class PlatformAdminGrantRequest(BaseModel):
    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def trim_email(cls, value):
        return value.strip() if isinstance(value, str) else value
