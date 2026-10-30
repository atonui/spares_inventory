"""Verified Resend webhook receiver hosted with the isolated mail worker."""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, HTTPException, Request, Response
from psycopg.rows import dict_row

from backend.mail_worker import run
from backend.services.mail_outbox import RESEND_EVENT_STATUS, record_resend_webhook_event
from backend.temporal import parse_api_instant, serialize_instant

logger = logging.getLogger("backend.mail_webhook")
MAX_WEBHOOK_BYTES = 64 * 1024
SIGNATURE_TOLERANCE_SECONDS = 300


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
        except Exception:
            logger.warning("mail worker cycle failed")
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
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="Webhook payload is too large")

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
    except Exception:
        logger.warning("Resend webhook persistence failed")
        raise HTTPException(status_code=503, detail="Webhook persistence unavailable") from None
    return Response(status_code=204)
