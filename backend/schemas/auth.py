"""Authentication, profile and shared user response schemas."""
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
from backend.temporal import validate_zone


class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None
    display_timezone: Optional[str] = Field(default=None, max_length=100)

    @field_validator('display_timezone')
    @classmethod
    def valid_display_timezone(cls, value):
        if value is not None:
            validate_zone(value)
        return value

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class UserLogin(BaseModel):
    email: str
    password: str
    remember_me: bool = False

class UserResponse(BaseModel):
    archived_at: Optional[str] = None
    id: int
    email: str
    name: str
    role: str
    territory: Optional[str]
    is_platform_admin: bool = False
    saas_mode: bool = False
