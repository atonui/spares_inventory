"""Resend webhook signatures reject tampering and replayed requests."""

import base64
import hashlib
import hmac
import json
import time
from contextlib import contextmanager

from backend.mail_webhook import verify_resend_signature


def _signed_request(body, *, secret, webhook_id, timestamp):
    key = base64.b64decode(secret.removeprefix("whsec_"))
    signed = webhook_id.encode() + b"." + timestamp.encode() + b"." + body
    signature = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return signature


def test_resend_signature_accepts_valid_signed_request():
    body = b'{"id":"evt-1","type":"email.delivered"}'
    webhook_id = "msg-123"
    timestamp = "1800000000"
    secret = "whsec_" + base64.b64encode(b"test-webhook-signing-key").decode()
    signature = _signed_request(body, secret=secret, webhook_id=webhook_id, timestamp=timestamp)

    assert verify_resend_signature(
        body, webhook_id=webhook_id, timestamp=timestamp,
        signature="v1," + signature, secret=secret, now=1800000000,
    )


def test_resend_signature_rejects_tampering_and_stale_timestamp():
    body = b'{"id":"evt-1","type":"email.delivered"}'
    webhook_id = "msg-123"
    timestamp = "1800000000"
    secret = "whsec_" + base64.b64encode(b"test-webhook-signing-key").decode()
    signature = _signed_request(body, secret=secret, webhook_id=webhook_id, timestamp=timestamp)

    assert not verify_resend_signature(
        body + b" ", webhook_id=webhook_id, timestamp=timestamp,
        signature="v1," + signature, secret=secret, now=1800000000,
    )
    assert not verify_resend_signature(
        body, webhook_id=webhook_id, timestamp=timestamp,
        signature="v1," + signature, secret=secret, now=1800000301,
    )
    assert not verify_resend_signature(
        body, webhook_id=webhook_id, timestamp=timestamp,
        signature="v0," + signature, secret=secret, now=1800000000,
    )


def test_worker_failure_diagnostics_keep_only_bounded_database_codes():
    from backend.mail_webhook import safe_worker_error_fields

    class DatabaseError(Exception):
        sqlstate = "42501"

    error_type, sqlstate = safe_worker_error_fields(
        DatabaseError("private connection detail")
    )

    assert error_type == "DatabaseError"
    assert sqlstate == "42501"


def test_webhook_event_filter_accepts_only_spares_tracker_tagged_messages():
    from backend.mail_webhook import is_spares_tracker_message

    assert is_spares_tracker_message(
        {"tags": [{"name": "app", "value": "spares_tracker"}]}
    )
    assert not is_spares_tracker_message(
        {"tags": [{"name": "app", "value": "another_app"}]}
    )
    assert not is_spares_tracker_message({"tags": []})


def test_receiver_persists_verified_spares_tracker_event(monkeypatch):
    from fastapi.testclient import TestClient

    import backend.mail_webhook as webhook

    raw_secret = b"test-webhook-signing-key"
    secret = "whsec_" + base64.b64encode(raw_secret).decode()
    timestamp = str(int(time.time()))
    event = {
        "id": "evt-delivered-1",
        "type": "email.delivered",
        "created_at": "2026-10-30T12:00:00Z",
        "data": {
            "email_id": "re_message_1",
            "tags": [{"name": "app", "value": "spares_tracker"}],
        },
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    signature = _signed_request(
        body, secret=secret, webhook_id="msg-webhook-1", timestamp=timestamp
    )
    saved = {}

    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @contextmanager
        def transaction(self):
            yield self

    monkeypatch.setenv("RESEND_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("MAIL_WORKER_DATABASE_URL", "postgresql://mail-worker/test")
    monkeypatch.setattr(webhook, "run", lambda *, once: False)
    monkeypatch.setattr(webhook.psycopg, "connect", lambda *args, **kwargs: _Connection())
    monkeypatch.setattr(
        webhook,
        "record_resend_webhook_event",
        lambda conn, **fields: saved.update(fields),
    )

    headers = {
        "svix-id": "msg-webhook-1",
        "svix-timestamp": timestamp,
        "svix-signature": "v1," + signature,
    }
    with TestClient(webhook.app) as client:
        response = client.post("/webhooks/resend", content=body, headers=headers)

    assert response.status_code == 204
    assert saved["event_id"] == "evt-delivered-1"
    assert saved["provider_message_id"] == "re_message_1"
    assert saved["event_type"] == "email.delivered"
    assert saved["occurred_at"].startswith("2026-10-30T12:00:00")


def test_inbound_receiver_validates_signature_fetches_and_persists_message(monkeypatch):
    from fastapi.testclient import TestClient

    import backend.mail_webhook as webhook

    secret = "whsec_" + base64.b64encode(b"inbound-test-key").decode()
    timestamp = str(int(time.time()))
    event = {"id": "evt-inbound-1", "type": "email.received", "created_at": "2026-11-15T12:00:00Z",
             "data": {"email_id": "re_received_1", "message_id": "<incoming@example.test>"}}
    body = json.dumps(event, separators=(",", ":")).encode()
    signature = _signed_request(body, secret=secret, webhook_id="msg-inbound-1", timestamp=timestamp)
    saved = {}

    class _Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        @contextmanager
        def transaction(self): yield self

    monkeypatch.setenv("RESEND_INBOUND_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("MAIL_WORKER_DATABASE_URL", "postgresql://mail-worker/test")
    monkeypatch.setenv("RESEND_API_KEY", "test-api-key")
    monkeypatch.setenv("MAIL_PAYLOAD_ENCRYPTION_KEY", "test-encryption-key")
    monkeypatch.setattr(webhook, "run", lambda *, once: False)
    monkeypatch.setattr(webhook.psycopg, "connect", lambda *args, **kwargs: _Connection())
    monkeypatch.setattr(webhook, "fetch_received_email", lambda email_id, api_key: {
        "from": "Owner <owner@example.test>", "to": ["support@sparestracker.com"],
        "subject": "Help", "text": "Please help", "created_at": "2026-11-15T12:00:00Z",
        "headers": {"Message-ID": "<incoming@example.test>"}, "attachments": [],
    })
    monkeypatch.setattr(webhook, "store_inbound_message", lambda conn, **fields: saved.update(fields))
    headers = {"svix-id": "msg-inbound-1", "svix-timestamp": timestamp, "svix-signature": "v1," + signature}
    with TestClient(webhook.app) as client:
        response = client.post("/webhooks/resend/inbound", content=body, headers=headers)
    assert response.status_code == 204
    assert saved["event_id"] == "evt-inbound-1"
    assert saved["provider_email_id"] == "re_received_1"
    assert saved["message"]["message_id"] == "<incoming@example.test>"


def test_inbound_receiver_rejects_invalid_signature_before_fetch(monkeypatch):
    from fastapi.testclient import TestClient

    import backend.mail_webhook as webhook

    secret = "whsec_" + base64.b64encode(b"inbound-test-key").decode()
    monkeypatch.setenv("RESEND_INBOUND_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("MAIL_WORKER_DATABASE_URL", "postgresql://mail-worker/test")
    monkeypatch.setenv("RESEND_API_KEY", "test-api-key")
    monkeypatch.setenv("MAIL_PAYLOAD_ENCRYPTION_KEY", "test-encryption-key")
    monkeypatch.setattr(webhook, "run", lambda *, once: False)
    monkeypatch.setattr(webhook, "fetch_received_email", lambda *_args: (_ for _ in ()).throw(AssertionError("must not fetch")))
    with TestClient(webhook.app) as client:
        response = client.post("/webhooks/resend/inbound", json={"id": "evt", "type": "email.received", "data": {"email_id": "abc"}})
    assert response.status_code == 401
