"""Password, JWT, and CSRF helpers."""

from dataclasses import dataclass
from datetime import timedelta
from backend.temporal import utc_now
from base64 import urlsafe_b64encode
from hashlib import sha256
import secrets
import hmac
from typing import Callable

from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer
from jose import jwt
import bcrypt
from backend.services.session_credentials import hash_session_credential

_BCRYPT_SHA256_PREFIX = "$spares-bcrypt-sha256$v1$"


def _password_bytes(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("bcrypt passwords cannot contain NUL bytes")
    if len(encoded) > 4096:
        raise ValueError("password exceeds maximum supported length")
    return encoded


def _legacy_bcrypt_password(password: str) -> bytes:
    """Match historical hashes until a successful login upgrades them."""
    encoded = _password_bytes(password)
    return encoded[:72]


def _bcrypt_sha256_password(password: str) -> bytes:
    encoded = _password_bytes(password)
    digest = sha256(b"spares-tracker-password-v1\0" + encoded).digest()
    return urlsafe_b64encode(digest).rstrip(b"=")


def hash_password(password: str) -> str:
    """Hash the full UTF-8 password using a bcrypt-compatible SHA-256 prehash."""
    hashed = bcrypt.hashpw(_bcrypt_sha256_password(password), bcrypt.gensalt(rounds=12))
    return _BCRYPT_SHA256_PREFIX + hashed.decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify current hashes and preserve compatibility with legacy bcrypt hashes."""
    if hashed_password.startswith(_BCRYPT_SHA256_PREFIX):
        stored = hashed_password[len(_BCRYPT_SHA256_PREFIX):]
        return bcrypt.checkpw(_bcrypt_sha256_password(plain_password), stored.encode("ascii"))
    return bcrypt.checkpw(
        _legacy_bcrypt_password(plain_password), hashed_password.encode("ascii")
    )


def password_needs_rehash(hashed_password: str) -> bool:
    """Identify historical hashes that still truncate passwords at bcrypt's byte limit."""
    return not hashed_password.startswith(_BCRYPT_SHA256_PREFIX)


def create_access_token(data: dict, secret_key: str):
    """Create JWT token."""
    to_encode = data.copy()
    expire = utc_now() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm="HS256")


@dataclass(frozen=True)
class CsrfHelpers:
    serializer: URLSafeTimedSerializer

    def generate_csrf_token(self, session_token: str | None = None) -> str:
        """Generate a signed token optionally bound to the current browser session."""
        session_binding = hash_session_credential(session_token) if session_token else None
        return self.serializer.dumps({
            "version": 2,
            "nonce": secrets.token_urlsafe(32),
            "session": session_binding,
        })

    def verify_csrf_token(
        self, token: str, max_age: int = 3600, session_token: str | None = None
    ) -> bool:
        """Verify token age, signature, and the browser session binding."""
        try:
            payload = self.serializer.loads(token, max_age=max_age)
        except Exception:
            return False
        expected = hash_session_credential(session_token) if session_token else None
        if isinstance(payload, dict) and payload.get("version") == 2:
            actual = payload.get("session")
            if actual is None or expected is None:
                return actual is None and expected is None
            return isinstance(actual, str) and hmac.compare_digest(actual, expected)
        # Previously issued tokens remain usable for anonymous login flows only.
        return isinstance(payload, str) and expected is None


def create_csrf_helpers(secret: str) -> CsrfHelpers:
    return CsrfHelpers(serializer=URLSafeTimedSerializer(secret))


def require_csrf_token(token: str | None, verifier: Callable[[str], bool]) -> bool:
    """Validate CSRF credentials for state-changing requests."""
    if not token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if not verifier(token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return True
