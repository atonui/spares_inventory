"""Authentication, profile and shared user response schemas."""
from typing import Optional
from pydantic import BaseModel, EmailStr


class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None

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
