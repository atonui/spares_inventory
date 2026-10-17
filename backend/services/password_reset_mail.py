"""Queue password-reset links through the encrypted PostgreSQL mail outbox."""

from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

from backend.services.mail_outbox import enqueue_mail
from backend.services.mail_payloads import encrypt_mail_payload
from backend.temporal import serialize_instant


def enqueue_password_reset_mail(
    conn, *, email: str, token: str, frontend_url: str, encryption_key: str,
    expires_at,
) -> int:
    parsed = urlsplit(frontend_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Password-reset base URL must be an absolute HTTP URL")
    base_path = parsed.path.rstrip("/")
    reset_path = base_path + "/reset_password.html"
    reset_url = urlunsplit((parsed.scheme, parsed.netloc, reset_path, urlencode({"token": token}), ""))
    encrypted_payload = encrypt_mail_payload(
        {"reset_url": reset_url, "expires_at": serialize_instant(expires_at)},
        encryption_key,
    )
    return enqueue_mail(
        conn,
        organization_id=None,
        message_type="password_reset",
        recipient_email=email,
        encrypted_payload=encrypted_payload,
        idempotency_key="password-reset-" + uuid4().hex,
    )
