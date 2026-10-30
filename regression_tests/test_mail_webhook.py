"""Resend webhook signatures reject tampering and replayed requests."""

import base64
import hashlib
import hmac

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
