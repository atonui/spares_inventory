"""Request schemas for regular user administration."""
from typing import Literal, Optional
from pydantic import BaseModel

UserRole = Literal["engineer", "manager", "admin", "superadmin"]


class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    role: UserRole
    territory: Optional[str] = None


class UpdateUserRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[UserRole] = None
    territory: Optional[str] = None
    password: Optional[str] = None
