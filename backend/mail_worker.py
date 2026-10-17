"""PostgreSQL transactional mail worker: ``python -m backend.mail_worker``."""

import argparse
import logging
import os
import time
from datetime import timedelta

import psycopg
from psycopg.rows import dict_row

from backend.services.mail_delivery import MailDeliveryError, send_mail
from backend.services.mail_outbox import (
    RETRY_DELAYS_SECONDS,
    claim_pending_mail,
    mark_mail_failed,
    mark_mail_sent,
)
from backend.services.mail_payloads import decrypt_mail_payload, validate_mail_encryption_key
from backend.temporal import utc_now

logger = logging.getLogger("backend.mail_worker")


def deliver_claimed_mail(
    message: dict, *, encryption_key: str, api_key: str, from_address: str,
    http_transport=None, decrypt=decrypt_mail_payload,
) -> bool:
    try:
        payload = decrypt(message["encrypted_payload"], encryption_key)
        send_mail(
            {**message, "payload": payload},
            api_key=api_key,
            from_address=from_address,
            http_transport=http_transport,
        )
    except MailDeliveryError as exc:
        message["_delivery_error_code"] = exc.code
        logger.warning("mail delivery failed code=%s", exc.code)
        return False
    except Exception:
        message["_delivery_error_code"] = "payload_unavailable"
        logger.warning("mail delivery failed code=payload_unavailable")
        return False
    logger.info("mail delivery sent")
    return True


def claim_and_deliver_once(
    conn, *, encryption_key: str, api_key: str, from_address: str,
    http_transport=None, now=None,
) -> bool:
    """Claim and deliver one item; invalid key configuration consumes no claim."""
    validate_mail_encryption_key(encryption_key)
    current = now or utc_now()
    with conn.transaction():
        message = claim_pending_mail(conn, now=current)
    if message is None:
        return False
    sent = deliver_claimed_mail(
        message,
        encryption_key=encryption_key,
        api_key=api_key,
        from_address=from_address,
        http_transport=http_transport,
    )
    with conn.transaction():
        if sent:
            mark_mail_sent(conn, mail_id=message["id"], claim_token=str(message["claim_token"]))
        else:
            attempt = int(message["attempt_count"])
            terminal = attempt >= len(RETRY_DELAYS_SECONDS) + 1
            retry_delay = RETRY_DELAYS_SECONDS[min(attempt - 1, len(RETRY_DELAYS_SECONDS) - 1)]
            mark_mail_failed(
                conn,
                mail_id=message["id"],
                claim_token=str(message["claim_token"]),
                retry_at=current + timedelta(seconds=retry_delay),
                error_code=message.get("_delivery_error_code", "delivery_failed"),
                terminal=terminal,
            )
    return True


def run(*, once: bool = False) -> None:
    database_url = os.environ.get("MAIL_WORKER_DATABASE_URL")
    encryption_key = os.environ.get("MAIL_PAYLOAD_ENCRYPTION_KEY")
    api_key = os.environ.get("RESEND_API_KEY")
    from_address = os.environ.get("RESEND_FROM_EMAIL")
    # Validate secrets and sender configuration before opening a DB connection
    # or claiming a message, so a bad deployment is non-destructive.
    validate_mail_encryption_key(encryption_key)
    if not api_key or not from_address:
        raise RuntimeError("RESEND_API_KEY and RESEND_FROM_EMAIL are required")
    if not database_url or not database_url.strip():
        raise RuntimeError("MAIL_WORKER_DATABASE_URL is required")
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        while True:
            did_work = claim_and_deliver_once(
                conn,
                encryption_key=encryption_key,
                api_key=api_key,
                from_address=from_address,
            )
            if once:
                return
            if not did_work:
                time.sleep(5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver queued invitation email")
    parser.add_argument("--once", action="store_true", help="process at most one queued message")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(once=args.once)


if __name__ == "__main__":
    main()
