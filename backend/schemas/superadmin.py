"""Existing privileged administration request schemas."""
from typing import List, Optional
from pydantic import BaseModel


class SystemSettingUpdate(BaseModel):
    value: str

class AccountUnlockRequest(BaseModel):
    user_id: int

class BulkUnlockRequest(BaseModel):
    user_ids: List[int]

class SecurityConfigUpdate(BaseModel):
    max_login_attempts: Optional[int] = None
    lockout_duration_minutes: Optional[int] = None
    session_duration_hours: Optional[int] = None
    remember_me_duration_days: Optional[int] = None

class DatabaseQueryRequest(BaseModel):
    sql: str                    # SELECT only – enforced server-side
    params: Optional[list] = []

class UserRoleUpdate(BaseModel):
    role: str                   # engineer | manager | admin | superadmin

class ForceLogoutRequest(BaseModel):
    user_id: int

class SystemAnnouncementRequest(BaseModel):
    message: str
    level: str = "info"         # info | warning | danger

class SuperadminPasswordReset(BaseModel):
    user_id: int
    new_password: str
