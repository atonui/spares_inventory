"""Request and response models for invitation-only tenant onboarding."""

from typing import Literal
from pydantic import BaseModel, EmailStr, Field

CompanyRole = Literal["owner", "admin", "manager", "engineer"]


class InvitationCreateRequest(BaseModel):
    email: EmailStr
    role: Literal["admin", "manager", "engineer"]


class InvitationAcceptRequest(BaseModel):
    organization_id: str
    token: str = Field(min_length=1, max_length=256)
    name: str | None = Field(default=None, max_length=200)
    password: str = Field(min_length=8, max_length=128)


class OrganizationCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=63)
    owner_email: EmailStr
