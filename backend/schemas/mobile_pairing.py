"""Payloads for short-lived desktop approval of native mobile sessions."""

from datetime import datetime

import re

from pydantic import BaseModel, Field, field_validator, model_validator

from backend.schemas.auth import NativeLoginUserResponse


class MobilePairingCreated(BaseModel):
    request_id: str
    qr_data: str
    qr_svg: str
    pairing_code: str
    expires_at: datetime


class MobilePairingClaim(BaseModel):
    qr_data: str | None = Field(default=None, min_length=1, max_length=2048)
    pairing_code: str | None = Field(default=None, min_length=10, max_length=11)
    device_name: str = Field(min_length=1, max_length=80)

    @field_validator("pairing_code")
    @classmethod
    def pairing_code_must_be_valid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not re.fullmatch(r"[A-HJ-NP-Z2-9]{5}-?[A-HJ-NP-Z2-9]{5}", normalized):
            raise ValueError("Pairing code is invalid")
        return normalized.replace("-", "")

    @model_validator(mode="after")
    def exactly_one_pairing_credential(self):
        if (self.qr_data is None) == (self.pairing_code is None):
            raise ValueError("Provide either a QR payload or a pairing code")
        return self

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


class MobileDeviceResponse(BaseModel):
    device_id: str
    device_name: str
    paired_at: datetime
    last_activity: datetime | None = None


class MobilePairingCompleteResponse(BaseModel):
    status: str
    success: bool | None = None
    token_type: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    user: NativeLoginUserResponse | None = None
