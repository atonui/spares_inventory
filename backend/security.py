"""Password, JWT, and CSRF helpers."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
from typing import Callable

from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer
from jose import jwt
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash password for storage."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, secret_key: str):
    """Create JWT token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm="HS256")


@dataclass(frozen=True)
class CsrfHelpers:
    serializer: URLSafeTimedSerializer

    def generate_csrf_token(self) -> str:
        """Generate CSRF token."""
        return self.serializer.dumps(secrets.token_urlsafe(32))

    def verify_csrf_token(self, token: str, max_age: int = 3600) -> bool:
        """Verify CSRF token."""
        try:
            self.serializer.loads(token, max_age=max_age)
            return True
        except Exception:
            return False


def create_csrf_helpers(secret: str) -> CsrfHelpers:
    return CsrfHelpers(serializer=URLSafeTimedSerializer(secret))


def require_csrf_token(token: str | None, verifier: Callable[[str], bool]) -> bool:
    """Validate CSRF credentials for state-changing requests."""
    if not token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if not verifier(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return True
