"""Transactional operations for the encrypted PostgreSQL mail outbox."""

import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from backend.temporal import serialize_instant

RETRY_DELAYS_SECONDS = (60, 300, 1200, 3600, 14400)
MAX_ATTEMPTS = 6
_ERROR_CODE = re.compile(r"^[a-z0-9_:-]{1,80}$")


def _stamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("An aware timestamp is required.")
    return serialize_instant(value)


def enqueue_mail(
    conn, *, organization_id, message_type: str, recipient_email: str,
    encrypted_payload: str, idempotency_key: str,
) -> int:
    if message_type != "organization_invitation":
        raise ValueError("Unsupported mail message type.")
    if not all(isinstance(value, str) and value.strip() for value in
               (recipient_email, encrypted_payload, idempotency_key)):
        raise ValueError("Recipient, encrypted payload, and idempotency key are required.")
    row = conn.execute(
        """INSERT INTO mail_outbox
           (organization_id, message_type, recipient_email, encrypted_payload, idempotency_key)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
           RETURNING id""",
        (organization_id, message_type, recipient_email.strip(), encrypted_payload, idempotency_key),
    ).fetchone()
    return row["id"]


def claim_pending_mail(conn, *, now: datetime, lease_seconds: int = 60) -> dict | None:
    if not isinstance(lease_seconds, int) or lease_seconds < 1 or lease_seconds > 3600:
        raise ValueError("Lease duration must be between 1 and 3600 seconds.")
    current = _stamp(now)
    lease_until = _stamp(now + timedelta(seconds=lease_seconds))
    token = uuid4()
    row = conn.execute(
        """WITH candidate AS (
               SELECT id FROM mail_outbox
               WHERE (status = 'pending' AND attempt_count < %s AND available_at <= %s)
                  OR (status = 'claimed' AND lease_expires_at <= %s)
               ORDER BY available_at, id
               LIMIT 1
               FOR UPDATE SKIP LOCKED
           )
           UPDATE mail_outbox AS mail
           SET status = 'claimed', claim_token = %s, lease_expires_at = %s,
               attempt_count = CASE WHEN mail.status = 'pending'
                                    THEN mail.attempt_count + 1 ELSE mail.attempt_count END,
               updated_at = %s
           FROM candidate
           WHERE mail.id = candidate.id
           RETURNING mail.id, mail.organization_id, mail.message_type,
                     mail.recipient_email, mail.encrypted_payload, mail.attempt_count,
                     mail.status, mail.claim_token""",
        (MAX_ATTEMPTS, current, current, token, lease_until, current),
    ).fetchone()
    return dict(row) if row is not None else None


def mark_mail_sent(conn, *, mail_id: int, claim_token: str) -> None:
    now = _stamp(datetime.now(timezone.utc))
    result = conn.execute(
        """UPDATE mail_outbox SET status = 'sent', claim_token = NULL,
                  lease_expires_at = NULL, sent_at = %s, updated_at = %s,
                  last_error_code = NULL
           WHERE id = %s AND status = 'claimed' AND claim_token = %s""",
        (now, now, mail_id, claim_token),
    )
    if result.rowcount != 1:
        raise RuntimeError("Mail claim is no longer current.")


def mark_mail_failed(
    conn, *, mail_id: int, claim_token: str, retry_at: datetime,
    error_code: str, terminal: bool = False,
) -> bool:
    if not isinstance(error_code, str) or not _ERROR_CODE.fullmatch(error_code):
        raise ValueError("A sanitized mail error code is required.")
    available = _stamp(retry_at)
    now = _stamp(datetime.now(timezone.utc))
    row = conn.execute(
        """UPDATE mail_outbox
           SET status = CASE WHEN attempt_count >= %s OR %s THEN 'failed' ELSE 'pending' END,
               claim_token = NULL, lease_expires_at = NULL, available_at = %s,
               last_error_code = %s, updated_at = %s
           WHERE id = %s AND status = 'claimed' AND claim_token = %s
           RETURNING status""",
        (MAX_ATTEMPTS, terminal, available, error_code, now, mail_id, claim_token),
    ).fetchone()
    if row is None:
        raise RuntimeError("Mail claim is no longer current.")
    return row["status"] == "failed"
