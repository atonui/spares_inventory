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
from backend.temporal import parse_api_instant, utc_now

logger = logging.getLogger("backend.mail_worker")


def deliver_claimed_mail(
    message: dict, *, encryption_key: str, api_key: str, from_address: str,
    http_transport=None, decrypt=decrypt_mail_payload, now=None,
) -> bool:
    try:
        payload = decrypt(message["encrypted_payload"], encryption_key)
        message_type = message.get("message_type")
        if message_type in {"password_reset", "email_change_verification"}:
            error_prefix = (
                "password_reset" if message_type == "password_reset" else "email_change"
            )
            try:
                expires_at = parse_api_instant(payload.get("expires_at"))
            except ValueError:
                message["_delivery_error_code"] = f"invalid_{error_prefix}_message"
                message["_delivery_terminal"] = True
                logger.warning("mail delivery failed code=%s", message["_delivery_error_code"])
                return False
            if (now or utc_now()) >= expires_at:
                message["_delivery_error_code"] = f"{error_prefix}_link_expired"
                message["_delivery_terminal"] = True
                logger.warning("mail delivery failed code=%s", message["_delivery_error_code"])
                return False
        provider_message_id = send_mail(
            {**message, "payload": payload},
            api_key=api_key,
            from_address=from_address,
            http_transport=http_transport,
        )
        message["_provider_message_id"] = provider_message_id
    except MailDeliveryError as exc:
        message["_delivery_error_code"] = exc.code
        if any((
            exc.provider_status is not None,
            exc.provider_error_category is not None,
            exc.provider_response_format is not None,
            exc.provider_edge is not None,
        )):
            logger.warning(
                "mail delivery failed code=%s provider_status=%s provider_error_category=%s "
                "provider_response_format=%s provider_edge=%s",
                exc.code,
                exc.provider_status if exc.provider_status is not None else "unknown",
                exc.provider_error_category or "unknown",
                exc.provider_response_format or "unknown",
                exc.provider_edge or "unknown",
            )
        else:
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
        now=current,
    )
    with conn.transaction():
        if sent:
            mark_mail_sent(
                conn, mail_id=message["id"], claim_token=str(message["claim_token"]),
                provider_message_id=message.get("_provider_message_id"),
            )
        else:
            attempt = int(message["attempt_count"])
            terminal = message.get("_delivery_terminal", False) or attempt >= len(RETRY_DELAYS_SECONDS) + 1
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
                return did_work
            if not did_work:
                time.sleep(5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver queued invitation email")
    parser.add_argument("--once", action="store_true", help="process at most one queued message")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.once:
        run(once=True)
        return
    import uvicorn

    uvicorn.run(
        "backend.mail_webhook:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        log_level="info",
    )


if __name__ == "__main__":
    main()
