"""Company settings and ownership-transfer request contracts."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.temporal import validate_zone


class OrganizationSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    business_timezone: str = Field(min_length=1, max_length=100)
    expected_revision: int = Field(strict=True, ge=1)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Organization name cannot be blank")
        return cleaned

    @field_validator("business_timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        validate_zone(value)
        return value


class OwnerTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_user_id: int = Field(strict=True, gt=0)
