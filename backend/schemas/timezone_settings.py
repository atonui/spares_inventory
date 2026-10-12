from pydantic import BaseModel, ConfigDict, Field, field_validator
from backend.temporal import validate_zone


class BusinessTimezoneUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    timezone: str = Field(max_length=100)
    expected_revision: int = Field(strict=True, ge=1)

    @field_validator('timezone')
    @classmethod
    def valid_timezone(cls, value):
        validate_zone(value)
        return value
