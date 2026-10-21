"""Payloads for short-lived desktop approval of native mobile sessions."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from backend.schemas.auth import NativeLoginUserResponse


class MobilePairingCreated(BaseModel):
    request_id: str
    qr_data: str
    qr_svg: str
    expires_at: datetime


class MobilePairingClaim(BaseModel):
    qr_data: str = Field(min_length=1, max_length=2048)
    device_name: str = Field(min_length=1, max_length=80)

    @field_validator("device_name")
    @classmethod
    def device_name_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Device name must not be blank")
        return value.strip()


class MobilePairingClaimResponse(BaseModel):
    claim_token: str
    expires_at: datetime


class MobilePairingComplete(BaseModel):
    claim_token: str = Field(min_length=20, max_length=200)


class MobilePairingDesktopStatus(BaseModel):
    status: str
    device_name: str | None = None
    expires_at: datetime


class MobilePairingCompleteResponse(BaseModel):
    status: str
    success: bool | None = None
    token_type: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    user: NativeLoginUserResponse | None = None
