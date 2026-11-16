"""Verified Resend webhook receiver hosted with the isolated mail worker."""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

import psycopg
from fastapi import FastAPI, HTTPException, Request, Response
from psycopg.rows import dict_row

from backend.mail_worker import run
from backend.services.mail_outbox import RESEND_EVENT_STATUS, record_resend_webhook_event
from backend.temporal import parse_api_instant, serialize_instant
from backend.services.platform_support_inbox import store_inbound_message

logger = logging.getLogger("backend.mail_webhook")
MAX_WEBHOOK_BYTES = 64 * 1024
SIGNATURE_TOLERANCE_SECONDS = 300
_LOG_TYPE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SQLSTATE = re.compile(r"^[A-Za-z0-9]{5}$")


def safe_worker_error_fields(exc: Exception) -> tuple[str, str]:
    """Expose only a bounded exception class and PostgreSQL SQLSTATE."""
    error_type = type(exc).__name__
    if not _LOG_TYPE.fullmatch(error_type):
        error_type = "Exception"
    sqlstate = getattr(exc, "sqlstate", None)
    if not isinstance(sqlstate, str) or not _SQLSTATE.fullmatch(sqlstate):
        sqlstate = "unknown"
    return error_type, sqlstate


def verify_resend_signature(
    body: bytes, *, webhook_id: str, timestamp: str, signature: str,
    secret: str, now: int | None = None,
) -> bool:
    """Verify Svix v1 signatures and reject old or malformed requests."""
    if not all(isinstance(value, str) and value for value in (webhook_id, timestamp, signature, secret)):
        return False
    if len(webhook_id) > 255 or len(timestamp) > 20 or len(signature) > 4096 or not secret.startswith("whsec_"):
        return False
    try:
        timestamp_value = int(timestamp)
        secret_bytes = base64.b64decode(secret.removeprefix("whsec_"), validate=True)
    except (ValueError, TypeError):
        return False
    current_time = int(time.time()) if now is None else now
    if abs(current_time - timestamp_value) > SIGNATURE_TOLERANCE_SECONDS:
        return False
    signed_content = webhook_id.encode("utf-8") + b"." + timestamp.encode("ascii") + b"." + body
    expected = base64.b64encode(
        hmac.new(secret_bytes, signed_content, hashlib.sha256).digest()
    ).decode("ascii")
    for item in signature.split():
        version, separator, value = item.partition(",")
        if separator and version == "v1" and hmac.compare_digest(expected, value):
            return True
    return False


async def _deliver_mail_loop() -> None:
    while True:
        try:
            did_work = await asyncio.to_thread(run, once=True)
        except Exception as exc:
            error_type, sqlstate = safe_worker_error_fields(exc)
            logger.error(
                "mail worker cycle failed error_type=%s sqlstate=%s",
                error_type,
                sqlstate,
            )
            did_work = False
        if not did_work:
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    worker_task = asyncio.create_task(_deliver_mail_loop())
    try:
        yield
    finally:
        worker_task.cancel()
        await asyncio.gather(worker_task, return_exceptions=True)


app = FastAPI(lifespan=lifespan)


def fetch_received_email(email_id: str, api_key: str) -> dict:
    """Fetch full inbound content from Resend without exposing provider errors."""
    if not isinstance(email_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", email_id):
        raise ValueError("Invalid provider email identifier")
    request = UrlRequest(
        f"https://api.resend.com/emails/receiving/{email_id}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=10) as response:
            content = response.read(2_000_001)
        if len(content) > 2_000_000:
            raise ValueError("Inbound message too large")
        result = json.loads(content.decode("utf-8"))
        if isinstance(result, dict) and isinstance(result.get("data"), dict):
            result = result["data"]
        if not isinstance(result, dict):
            raise ValueError("Invalid provider message")
        return result
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Inbound provider unavailable") from None


def is_spares_tracker_message(data: dict) -> bool:
    tags = data.get("tags")
    return isinstance(tags, list) and any(
        isinstance(tag, dict) and tag.get("name") == "app"
        and tag.get("value") == "spares_tracker"
        for tag in tags
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhooks/resend", status_code=204)
async def receive_resend_webhook(request: Request) -> Response:
    secret = os.environ.get("RESEND_WEBHOOK_SECRET")
    database_url = os.environ.get("MAIL_WORKER_DATABASE_URL")
    if not secret or not database_url:
        raise HTTPException(status_code=503, detail="Webhook receiver is not configured")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_WEBHOOK_BYTES:
                raise HTTPException(status_code=413, detail="Webhook payload is too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid webhook request") from None
    body_buffer = bytearray()
    async for chunk in request.stream():
        body_buffer.extend(chunk)
        if len(body_buffer) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="Webhook payload is too large")
    body = bytes(body_buffer)

    if not verify_resend_signature(
        body,
        webhook_id=request.headers.get("svix-id", ""),
        timestamp=request.headers.get("svix-timestamp", ""),
        signature=request.headers.get("svix-signature", ""),
        secret=secret,
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        event = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid webhook payload") from None
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    event_id = event.get("id")
    event_type = event.get("type")
    data = event.get("data")
    if not isinstance(event_id, str) or not isinstance(event_type, str) or not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid webhook payload")
    if event_type not in RESEND_EVENT_STATUS or not is_spares_tracker_message(data):
        return Response(status_code=204)

    provider_message_id = data.get("email_id")
    if not isinstance(provider_message_id, str) or not provider_message_id:
        raise HTTPException(status_code=400, detail="Invalid email event")
    try:
        occurred_at = serialize_instant(parse_api_instant(event.get("created_at")))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid event timestamp") from None

    try:
        with psycopg.connect(database_url, row_factory=dict_row) as conn:
            with conn.transaction():
                record_resend_webhook_event(
                    conn,
                    event_id=event_id,
                    provider_message_id=provider_message_id,
                    event_type=event_type,
                    occurred_at=occurred_at,
                )
                rfc_message_id = data.get("message_id")
                if isinstance(rfc_message_id, str) and len(rfc_message_id) <= 2000:
                    conn.execute("UPDATE resend_webhook_events SET provider_rfc_message_id=%s WHERE event_id=%s",
                                 (rfc_message_id, event_id))
                    conn.execute(
                        """UPDATE platform_support_messages SET provider_message_id=%s,
                                  delivery_status=CASE
                                    WHEN CASE delivery_status WHEN 'sent' THEN 1 WHEN 'delayed' THEN 2
                                      WHEN 'delivered' THEN 3 WHEN 'bounced' THEN 4 WHEN 'failed' THEN 4
                                      WHEN 'complained' THEN 5 WHEN 'suppressed' THEN 5 ELSE 0 END
                                      >= CASE %s WHEN 'sent' THEN 1 WHEN 'delayed' THEN 2
                                      WHEN 'delivered' THEN 3 WHEN 'bounced' THEN 4 WHEN 'failed' THEN 4
                                      WHEN 'complained' THEN 5 WHEN 'suppressed' THEN 5 ELSE 0 END
                                    THEN delivery_status ELSE %s END
                           WHERE provider_email_id=%s AND direction='outbound'""",
                        (rfc_message_id, RESEND_EVENT_STATUS[event_type],
                         RESEND_EVENT_STATUS[event_type], provider_message_id),
                    )
    except Exception:
        logger.warning("Resend webhook persistence failed")
        raise HTTPException(status_code=503, detail="Webhook persistence unavailable") from None
    return Response(status_code=204)


@app.post("/webhooks/resend/inbound", status_code=204)
async def receive_resend_inbound_webhook(request: Request) -> Response:
    secret = os.environ.get("RESEND_INBOUND_WEBHOOK_SECRET")
    database_url = os.environ.get("MAIL_WORKER_DATABASE_URL")
    api_key = os.environ.get("RESEND_API_KEY")
    encryption_key = os.environ.get("MAIL_PAYLOAD_ENCRYPTION_KEY")
    support_address = os.environ.get("RESEND_SUPPORT_ADDRESS", "support@sparestracker.com")
    if not all((secret, database_url, api_key, encryption_key)):
        raise HTTPException(status_code=503, detail="Inbound webhook receiver is not configured")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="Webhook payload is too large")
    raw = bytes(body)
    if not verify_resend_signature(
        raw, webhook_id=request.headers.get("svix-id", ""),
        timestamp=request.headers.get("svix-timestamp", ""),
        signature=request.headers.get("svix-signature", ""), secret=secret,
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    try:
        event = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid webhook payload") from None
    if not isinstance(event, dict) or event.get("type") != "email.received":
        return Response(status_code=204)
    data = event.get("data")
    event_id = event.get("id")
    email_id = data.get("email_id") if isinstance(data, dict) else None
    if not all(isinstance(value, str) and value for value in (event_id, email_id)):
        raise HTTPException(status_code=400, detail="Invalid received email event")
    try:
        message = await asyncio.to_thread(fetch_received_email, email_id, api_key)
    except (RuntimeError, ValueError):
        logger.warning("Resend inbound message retrieval failed")
        raise HTTPException(status_code=503, detail="Inbound message temporarily unavailable") from None
    message.setdefault("message_id", data.get("message_id"))
    message.setdefault("created_at", data.get("created_at") or event.get("created_at"))
    try:
        with psycopg.connect(database_url, row_factory=dict_row) as conn:
            with conn.transaction():
                store_inbound_message(conn, event_id=event_id, provider_email_id=email_id,
                    message=message, support_address=support_address, encryption_key=encryption_key)
    except ValueError:
        # Bad recipient or malformed sender is intentionally acknowledged and discarded.
        logger.warning("Resend inbound message rejected")
        return Response(status_code=204)
    except Exception:
        logger.warning("Resend inbound message persistence failed")
        raise HTTPException(status_code=503, detail="Inbound message persistence unavailable") from None
    return Response(status_code=204)
