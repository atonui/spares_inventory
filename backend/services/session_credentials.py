"""Helpers for opaque session credentials shared by web and native clients."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re

from fastapi import HTTPException, Request


_BEARER_CREDENTIAL = re.compile(r"^Bearer ([A-Za-z0-9._~-]+)$", re.IGNORECASE)


@dataclass(frozen=True)
class RequestCredential:
    value: str
    transport: str


def hash_session_credential(credential: str) -> str:
    """Return the lowercase SHA-256 hex digest of a high-entropy session token."""
    return sha256(credential.encode("utf-8")).hexdigest()


def resolve_request_credential(
    cookie_credential: str | None,
    authorization: str | None,
    *,
    allow_bearer: bool = True,
) -> RequestCredential:
    """Parse exactly one cookie or Bearer credential, failing closed otherwise."""
    if authorization is not None:
        match = _BEARER_CREDENTIAL.fullmatch(authorization)
        if match is None or not allow_bearer or cookie_credential:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return RequestCredential(value=match.group(1), transport="bearer")
    if cookie_credential:
        return RequestCredential(value=cookie_credential, transport="cookie")
    raise HTTPException(status_code=401, detail="Not authenticated")


def get_request_credential(request: Request, *, allow_bearer: bool = True) -> RequestCredential:
    """Extract the session credential from one request without logging its value."""
    cookies = getattr(request, "cookies", {})
    headers = getattr(request, "headers", {})
    return resolve_request_credential(
        cookies.get("session_token"),
        headers.get("Authorization"),
        allow_bearer=allow_bearer,
    )


def get_optional_request_credential(request: Request) -> RequestCredential | None:
    """Return no credential for an unauthenticated request, but reject malformed auth."""
    cookies = getattr(request, "cookies", {})
    headers = getattr(request, "headers", {})
    cookie_credential = cookies.get("session_token")
    authorization = headers.get("Authorization")
    if not cookie_credential and authorization is None:
        return None
    return resolve_request_credential(cookie_credential, authorization)
