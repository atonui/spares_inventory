"""Transactional operations for the encrypted PostgreSQL mail outbox."""

import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from backend.temporal import serialize_instant

RETRY_DELAYS_SECONDS = (60, 300, 1200, 3600, 14400)
MAX_ATTEMPTS = 6
RESEND_EVENT_STATUS = {
    "email.sent": "sent",
    "email.delivered": "delivered",
    "email.delivery_delayed": "delayed",
    "email.bounced": "bounced",
    "email.complained": "complained",
    "email.failed": "failed",
    "email.suppressed": "suppressed",
}
_DELIVERY_PRIORITY = {
    "unknown": 0, "sent": 1, "delayed": 2, "delivered": 3,
    "bounced": 4, "failed": 4, "complained": 5, "suppressed": 5,
}
_ERROR_CODE = re.compile(r"^[a-z0-9_:-]{1,80}$")


def _stamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("An aware timestamp is required.")
    return serialize_instant(value)


def enqueue_mail(
    conn, *, organization_id, message_type: str, recipient_email: str,
    encrypted_payload: str, idempotency_key: str,
) -> int:
    if message_type not in {
        "organization_invitation",
        "password_reset",
        "email_change_verification",
        "email_changed_notice",
    }:
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


def mark_mail_sent(
    conn, *, mail_id: int, claim_token: str, provider_message_id: str | None = None,
) -> None:
    now = _stamp(datetime.now(timezone.utc))
    if provider_message_id is not None and (
        not isinstance(provider_message_id, str) or not provider_message_id.strip()
        or len(provider_message_id) > 255
    ):
        raise ValueError("Provider message ID is invalid.")
    result = conn.execute(
        """UPDATE mail_outbox SET status = 'sent', claim_token = NULL,
                  lease_expires_at = NULL, sent_at = %s, updated_at = %s,
                  last_error_code = NULL, provider_message_id = %s,
                  delivery_status = 'sent', delivery_event_at = NULL
           WHERE id = %s AND status = 'claimed' AND claim_token = %s""",
        (now, now, provider_message_id, mail_id, claim_token),
    )
    if result.rowcount != 1:
        raise RuntimeError("Mail claim is no longer current.")
    if provider_message_id is not None:
        apply_pending_resend_events(conn, provider_message_id)


def record_resend_webhook_event(
    conn, *, event_id: str, provider_message_id: str, event_type: str, occurred_at: str,
) -> bool:
    """Store a minimal verified Resend event and apply it when its outbox row exists."""
    if event_type not in RESEND_EVENT_STATUS:
        raise ValueError("Unsupported Resend email event.")
    if not isinstance(event_id, str) or not 1 <= len(event_id) <= 255:
        raise ValueError("A valid Resend event ID is required.")
    if not isinstance(provider_message_id, str) or not 1 <= len(provider_message_id) <= 255:
        raise ValueError("A valid provider message ID is required.")
    inserted = conn.execute(
        """INSERT INTO resend_webhook_events
           (event_id, provider_message_id, event_type, occurred_at)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (event_id) DO NOTHING
           RETURNING event_id""",
        (event_id, provider_message_id, event_type, occurred_at),
    ).fetchone()
    apply_pending_resend_events(conn, provider_message_id)
    return inserted is not None


def apply_pending_resend_events(conn, provider_message_id: str) -> int:
    """Apply deduplicated events in timestamp order; keep unmatched events for send races."""
    events = conn.execute(
        """SELECT event_id, event_type, occurred_at
           FROM resend_webhook_events
           WHERE provider_message_id = %s AND processed_at IS NULL
           ORDER BY occurred_at, event_id
           FOR UPDATE""",
        (provider_message_id,),
    ).fetchall()
    processed = 0
    now = _stamp(datetime.now(timezone.utc))
    for event in events:
        delivery_status = RESEND_EVENT_STATUS[event["event_type"]]
        priority = _DELIVERY_PRIORITY[delivery_status]
        mail_row = conn.execute(
            "SELECT id FROM mail_outbox WHERE provider_message_id = %s FOR UPDATE",
            (provider_message_id,),
        ).fetchone()
        if mail_row is None:
            # The webhook can arrive before mark_mail_sent stores the provider ID.
            continue
        conn.execute(
            """UPDATE mail_outbox
               SET delivery_status = %s, delivery_event_at = %s,
                   delivered_at = CASE WHEN %s = 'delivered' THEN %s ELSE delivered_at END,
                   bounced_at = CASE WHEN %s = 'bounced' THEN %s ELSE bounced_at END,
                   complained_at = CASE WHEN %s = 'complained' THEN %s ELSE complained_at END,
                   updated_at = %s
               WHERE provider_message_id = %s
                 AND (delivery_event_at IS NULL OR delivery_event_at < %s OR
                      (delivery_event_at = %s AND
                       CASE delivery_status
                         WHEN 'unknown' THEN 0 WHEN 'sent' THEN 1 WHEN 'delayed' THEN 2
                         WHEN 'delivered' THEN 3 WHEN 'bounced' THEN 4 WHEN 'failed' THEN 4
                         WHEN 'complained' THEN 5 WHEN 'suppressed' THEN 5 ELSE 0
                       END <= %s))""",
            (
                delivery_status, event["occurred_at"],
                delivery_status, event["occurred_at"],
                delivery_status, event["occurred_at"],
                delivery_status, event["occurred_at"],
                now, provider_message_id, event["occurred_at"], event["occurred_at"], priority,
            ),
        )
        conn.execute(
            """UPDATE resend_webhook_events SET processed_at = %s
               WHERE event_id = %s AND processed_at IS NULL""",
            (now, event["event_id"]),
        )
        processed += 1
    return processed


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
