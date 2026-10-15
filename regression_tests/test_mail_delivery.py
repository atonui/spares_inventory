"""Resend adapter failures remain sanitized and invitation payloads stay private."""

import logging

import pytest


class _Response:
    status_code = 202

    def raise_for_status(self):
        return None


class _Transport:
    def __init__(self, *, error=None):
        self.error = error
        self.calls = []

    def post(self, url, *, json, headers, timeout):
        self.calls.append((url, json, headers, timeout))
        if self.error:
            raise self.error
        return _Response()


def test_missing_payload_key_does_not_claim_pending_message():
    from backend.mail_worker import claim_and_deliver_once

    class _Connection:
        def transaction(self):
            raise AssertionError("must validate encryption key before opening a transaction")

    with pytest.raises(ValueError, match="MAIL_PAYLOAD_ENCRYPTION_KEY"):
        claim_and_deliver_once(
            _Connection(), encryption_key="", api_key="secret",
            from_address="Inventory <no-reply@example.test>",
        )


def test_resend_adapter_sends_invitation_via_configured_sender():
    from backend.services.mail_delivery import send_mail

    transport = _Transport()
    send_mail(
        {
            "message_type": "organization_invitation",
            "recipient_email": "owner@example.test",
            "payload": {"invitation_url": "https://inventory.example.test/accept?token=raw-secret"},
        },
        api_key="resend-secret",
        from_address="Inventory <no-reply@example.test>",
        http_transport=transport,
    )
    url, body, headers, timeout = transport.calls[0]
    assert url == "https://api.resend.com/emails"
    assert body["from"] == "Inventory <no-reply@example.test>"
    assert body["to"] == ["owner@example.test"]
    assert "raw-secret" in body["html"]
    assert headers["Authorization"] == "Bearer resend-secret"
    assert timeout > 0


def test_provider_error_exposes_only_sanitized_code():
    from backend.services.mail_delivery import MailDeliveryError, send_mail

    transport = _Transport(error=RuntimeError("provider echoed token=raw-secret"))
    with pytest.raises(MailDeliveryError) as error:
        send_mail(
            {"message_type": "organization_invitation", "recipient_email": "a@example.test",
             "payload": {"invitation_url": "https://example.test/?token=raw-secret"}},
            api_key="secret",
            from_address="Inventory <no-reply@example.test>",
            http_transport=transport,
        )
    assert error.value.code == "provider_unavailable"
    assert "raw-secret" not in str(error.value)


def test_worker_logs_never_include_decrypted_invitation_token(caplog):
    from backend.mail_worker import deliver_claimed_mail

    caplog.set_level(logging.INFO)
    transport = _Transport(error=RuntimeError("provider error"))
    deliver_claimed_mail(
        {"id": 17, "message_type": "organization_invitation", "recipient_email": "a@example.test",
         "encrypted_payload": "ciphertext"},
        encryption_key="unused",
        api_key="secret",
        from_address="Inventory <no-reply@example.test>",
        http_transport=transport,
        decrypt=lambda _ciphertext, _key: {"invitation_url": "https://example.test/?token=raw-secret"},
    )
    assert "raw-secret" not in caplog.text
    assert "provider error" not in caplog.text
