"""Queue email-change messages through the encrypted PostgreSQL mail outbox."""

from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4

from backend.services.mail_outbox import enqueue_mail
from backend.services.mail_payloads import encrypt_mail_payload
from backend.temporal import serialize_instant


def enqueue_email_change_verification(
    conn, *, email: str, token: str, frontend_url: str, encryption_key: str,
    expires_at,
) -> int:
    parsed = urlsplit(frontend_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Email-change base URL must be an absolute HTTP URL")
    if not isinstance(token, str) or not token:
        raise ValueError("Email-change token is required")
    base_path = parsed.path.rstrip("/")
    confirmation_path = base_path + "/email_change_confirmation.html"
    verification_url = urlunsplit((
        parsed.scheme,
        parsed.netloc,
        confirmation_path,
        "",
        urlencode({"token": token}),
    ))
    encrypted_payload = encrypt_mail_payload(
        {
            "verification_url": verification_url,
            "expires_at": serialize_instant(expires_at),
        },
        encryption_key,
    )
    return enqueue_mail(
        conn,
        organization_id=None,
        message_type="email_change_verification",
        recipient_email=email,
        encrypted_payload=encrypted_payload,
        idempotency_key="email-change-verification-" + uuid4().hex,
    )


def enqueue_email_changed_notice(
    conn, *, old_email: str, new_email: str, encryption_key: str,
) -> int:
    encrypted_payload = encrypt_mail_payload({"new_email": new_email}, encryption_key)
    return enqueue_mail(
        conn,
        organization_id=None,
        message_type="email_changed_notice",
        recipient_email=old_email,
        encrypted_payload=encrypted_payload,
        idempotency_key="email-changed-notice-" + uuid4().hex,
    )
