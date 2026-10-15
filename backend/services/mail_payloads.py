"""Encryption for sensitive values retained in the transactional mail outbox."""

import json
from typing import Any

from cryptography.fernet import Fernet


def _fernet(key: str) -> Fernet:
    if not isinstance(key, str) or not key:
        raise ValueError("MAIL_PAYLOAD_ENCRYPTION_KEY is required")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("MAIL_PAYLOAD_ENCRYPTION_KEY must be a valid Fernet key") from exc


def validate_mail_encryption_key(key: str) -> None:
    """Validate worker configuration before claiming any durable mail."""
    _fernet(key)


def encrypt_mail_payload(payload: dict[str, Any], key: str) -> str:
    if not isinstance(payload, dict):
        raise TypeError("mail payload must be an object")
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _fernet(key).encrypt(serialized).decode("ascii")


def decrypt_mail_payload(ciphertext: str, key: str) -> dict[str, Any]:
    plaintext = _fernet(key).decrypt(ciphertext.encode("ascii"))
    payload = json.loads(plaintext)
    if not isinstance(payload, dict):
        raise ValueError("decrypted mail payload must be an object")
    return payload
