"""Request and response models for verified email changes."""

from datetime import datetime

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class EmailChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr


class EmailChangeConfirmation(BaseModel):
    # Any lets the handler return a stable generic failure for malformed bodies
    # without FastAPI echoing an invalid token value in validation details.
    token: Any = Field(
        description="Single-use confirmation token received at the proposed address.",
        json_schema_extra={"type": "string", "minLength": 20, "maxLength": 200},
    )


class EmailChangeStatus(BaseModel):
    status: Literal["pending", "none"]
    proposed_email: str | None = Field(default=None, description="Masked proposed email, only when pending.")
    expires_at: datetime | None = Field(default=None, description="Expiration instant in UTC, only when pending.")


class EmailChangeRequestResponse(BaseModel):
    success: bool
    message: str


class EmailChangeCancelResponse(BaseModel):
    success: bool
    message: str


class EmailChangeConfirmationResponse(BaseModel):
    success: bool
    message: str
