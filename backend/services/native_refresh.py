"""Encryption helpers for short-lived native refresh retry responses."""

import base64
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backend.temporal import parse_storage_instant
from backend.temporal_manifest import TemporalField


_INSTANT_FIELDS = {
    "refresh_expires_at": TemporalField(
        "session_refresh_credentials", "expires_at", "instant", "utc",
        "Native refresh credentials expire at the absolute session deadline.",
    ),
    "absolute_expires_at": TemporalField(
        "sessions", "absolute_expires_at", "instant", "utc",
        "Version 6 backfills the session bound from expires_at; native auth writes serialize_instant values.",
    ),
    "retry_response_expires_at": TemporalField(
        "session_refresh_credentials", "retry_response_expires_at", "instant", "utc",
        "Native refresh writes the 60-second retry deadline with serialize_instant.",
    ),
}


def parse_native_refresh_instant(value: str, column: str):
    return parse_storage_instant(value, field=_INSTANT_FIELDS[column])


def _key(value: str | None) -> bytes:
    if not value:
        raise ValueError("Native refresh encryption key is not configured")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError("Native refresh encryption key is invalid") from exc
    if len(decoded) != 32:
        raise ValueError("Native refresh encryption key must encode 32 bytes")
    return decoded


def encrypt_retry_response(value: str, response: dict, aad: str) -> str:
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(response, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(_key(value)).encrypt(nonce, plaintext, aad.encode("ascii"))
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_retry_response(value: str, ciphertext: str, aad: str) -> dict:
    raw = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    plaintext = AESGCM(_key(value)).decrypt(raw[:12], raw[12:], aad.encode("ascii"))
    return json.loads(plaintext.decode("utf-8"))
