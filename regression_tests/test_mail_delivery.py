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


def test_resend_adapter_sends_email_change_verification():
    from backend.services.mail_delivery import send_mail

    transport = _Transport()
    send_mail(
        {
            "message_type": "email_change_verification",
            "recipient_email": "new@example.test",
            "payload": {
                "verification_url": "https://inventory.example.test/email_change_confirmation.html?token=one-time-token",
                "expires_at": "2030-01-02T03:04:05.000000Z",
            },
        },
        api_key="resend-secret",
        from_address="SparesFlow <mail@example.test>",
        http_transport=transport,
    )
    _url, body, _headers, _timeout = transport.calls[0]
    assert body["to"] == ["new@example.test"]
    assert "verify" in body["subject"].lower()
    assert "one-time-token" in body["html"]


def test_old_email_notice_contains_new_address_without_verification_link():
    from backend.services.mail_delivery import send_mail

    transport = _Transport()
    send_mail(
        {
            "message_type": "email_changed_notice",
            "recipient_email": "old@example.test",
            "payload": {"new_email": "new@example.test"},
        },
        api_key="resend-secret",
        from_address="SparesFlow <mail@example.test>",
        http_transport=transport,
    )
    _url, body, _headers, _timeout = transport.calls[0]
    assert body["to"] == ["old@example.test"]
    assert "new@example.test" in body["html"]
    assert "href=" not in body["html"]
    assert "token=" not in body["html"]


def test_default_urllib_transport_accepts_success_status(monkeypatch):
    import backend.services.mail_delivery as delivery

    class _UrlResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    calls = []
    monkeypatch.setattr(delivery, "urlopen", lambda request, timeout: (calls.append((request, timeout)) or _UrlResponse()))
    delivery.send_mail(
        {
            "message_type": "organization_invitation",
            "recipient_email": "owner@example.test",
            "payload": {"invitation_url": "https://example.test/accept?token=secret"},
        },
        api_key="resend-secret",
        from_address="Inventory <no-reply@example.test>",
    )
    assert len(calls) == 1
    assert calls[0][0].full_url == "https://api.resend.com/emails"


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


def test_worker_logs_never_include_decrypted_password_reset_token(caplog):
    from backend.mail_worker import deliver_claimed_mail

    caplog.set_level(logging.INFO)
    transport = _Transport(error=RuntimeError("provider error"))
    deliver_claimed_mail(
        {"id": 18, "message_type": "password_reset", "recipient_email": "person@example.test",
         "encrypted_payload": "ciphertext"},
        encryption_key="unused",
        api_key="secret",
        from_address="Inventory <no-reply@example.test>",
        http_transport=transport,
        decrypt=lambda _ciphertext, _key: {
            "reset_url": "https://example.test/reset_password.html?token=raw-reset-secret",
            "expires_at": "2099-01-02T03:04:05.000000Z",
        },
    )
    assert "raw-reset-secret" not in caplog.text
    assert "provider error" not in caplog.text


def test_expired_password_reset_is_not_sent_and_is_terminally_failed(monkeypatch):
    from cryptography.fernet import Fernet
    from datetime import datetime, timezone
    import backend.mail_worker as worker
    from backend.services.mail_payloads import encrypt_mail_payload

    class _Transaction:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class _Connection:
        def transaction(self):
            return _Transaction()

    now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    encryption_key = Fernet.generate_key().decode("ascii")
    message = {
        "id": 18,
        "message_type": "password_reset",
        "recipient_email": "person@example.test",
        "encrypted_payload": encrypt_mail_payload({
            "reset_url": "https://example.test/reset_password.html?token=expired-secret",
            "expires_at": "2030-01-02T03:04:04.000000Z",
        }, encryption_key),
        "attempt_count": 1,
        "claim_token": "claim-token",
    }
    failed = []
    monkeypatch.setattr(worker, "claim_pending_mail", lambda _conn, *, now: message)
    monkeypatch.setattr(worker, "mark_mail_sent", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker, "mark_mail_failed", lambda _conn, **kwargs: failed.append(kwargs))
    transport = _Transport()

    worker.claim_and_deliver_once(
        _Connection(),
        encryption_key=encryption_key,
        api_key="provider-key",
        from_address="SparesFlow <mail@example.test>",
        http_transport=transport,
        now=now,
    )

    assert transport.calls == []
    assert len(failed) == 1
    assert failed[0]["terminal"] is True
    assert failed[0]["error_code"] == "password_reset_link_expired"
    assert failed[0]["mail_id"] == 18


def test_expired_email_change_verification_is_not_sent(monkeypatch):
    from datetime import datetime, timezone

    import backend.mail_worker as worker
    from cryptography.fernet import Fernet
    from backend.services.mail_payloads import encrypt_mail_payload

    now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    key = Fernet.generate_key().decode("ascii")
    message = {
        "id": 19,
        "message_type": "email_change_verification",
        "recipient_email": "new@example.test",
        "encrypted_payload": encrypt_mail_payload(
            {
                "verification_url": "https://example.test/email_change_confirmation.html?token=expired-token",
                "expires_at": "2030-01-02T03:04:04.000000Z",
            },
            key,
        ),
    }
    transport = _Transport()

    sent = worker.deliver_claimed_mail(
        message,
        encryption_key=key,
        api_key="provider-key",
        from_address="SparesFlow <mail@example.test>",
        http_transport=transport,
        now=now,
    )

    assert sent is False
    assert transport.calls == []
    assert message["_delivery_terminal"] is True
    assert message["_delivery_error_code"] == "email_change_link_expired"


@pytest.mark.parametrize("worker_url", [None, "   "])
def test_worker_requires_its_own_database_url_before_connecting(monkeypatch, worker_url):
    from cryptography.fernet import Fernet

    import backend.mail_worker as worker

    valid_key = Fernet.generate_key().decode()
    monkeypatch.setenv("DATABASE_URL", "postgresql://web-role/example")
    monkeypatch.setenv("MAIL_PAYLOAD_ENCRYPTION_KEY", valid_key)
    monkeypatch.setenv("RESEND_API_KEY", "provider-key")
    monkeypatch.setenv("RESEND_FROM_EMAIL", "SparesFlow <mail@example.test>")
    if worker_url is None:
        monkeypatch.delenv("MAIL_WORKER_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("MAIL_WORKER_DATABASE_URL", worker_url)

    def unexpected_connect(*_args, **_kwargs):
        raise AssertionError("database connection opened before worker URL validation")

    monkeypatch.setattr(worker.psycopg, "connect", unexpected_connect)
    with pytest.raises(RuntimeError, match="MAIL_WORKER_DATABASE_URL"):
        worker.run(once=True)


def test_worker_connects_with_mail_worker_database_url(monkeypatch):
    from cryptography.fernet import Fernet

    import backend.mail_worker as worker

    valid_key = Fernet.generate_key().decode()
    monkeypatch.setenv("DATABASE_URL", "postgresql://web-role/example")
    monkeypatch.setenv("MAIL_WORKER_DATABASE_URL", "postgresql://worker-role/example")
    monkeypatch.setenv("MAIL_PAYLOAD_ENCRYPTION_KEY", valid_key)
    monkeypatch.setenv("RESEND_API_KEY", "provider-key")
    monkeypatch.setenv("RESEND_FROM_EMAIL", "SparesFlow <mail@example.test>")
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(worker.psycopg, "connect", lambda url, **_kwargs: (calls.append(url) or Connection()))
    monkeypatch.setattr(worker, "claim_and_deliver_once", lambda *_args, **_kwargs: True)

    worker.run(once=True)

    assert calls == ["postgresql://worker-role/example"]


def test_worker_logs_provider_http_status_without_response_body_or_secrets(caplog):
    from backend.mail_worker import deliver_claimed_mail

    class _UnauthorizedResponse:
        status_code = 401
        provider_error_category = "api_key_permission_denied"

        def raise_for_status(self):
            raise RuntimeError("provider echoed token=provider-private-detail")

    class _UnauthorizedTransport:
        def post(self, *_args, **_kwargs):
            return _UnauthorizedResponse()

    caplog.set_level(logging.WARNING)
    message = {
        "id": 20,
        "message_type": "organization_invitation",
        "recipient_email": "a@example.test",
        "encrypted_payload": "ciphertext",
    }
    deliver_claimed_mail(
        message,
        encryption_key="unused",
        api_key="secret",
        from_address="Inventory <no-reply@example.test>",
        http_transport=_UnauthorizedTransport(),
        decrypt=lambda _ciphertext, _key: {
            "invitation_url": "https://example.test/?token=invitation-secret",
        },
    )

    assert message["_delivery_error_code"] == "provider_unavailable"
    assert "provider_status=401" in caplog.text
    assert "provider_error_category=api_key_permission_denied" in caplog.text
    assert "provider-private-detail" not in caplog.text
    assert "invitation-secret" not in caplog.text



def test_http_error_logs_only_bounded_provider_category(monkeypatch):
    from io import BytesIO
    from urllib.error import HTTPError

    import backend.services.mail_delivery as delivery

    def reject(request, timeout):
        raise HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=BytesIO(
                b'{"statusCode":403,"name":"restricted_api_key",'
                b'"message":"private recipient and secret token=do-not-log"}'
            ),
        )

    monkeypatch.setattr(delivery, "urlopen", reject)
    with pytest.raises(delivery.MailDeliveryError) as error:
        delivery.send_mail(
            {
                "message_type": "organization_invitation",
                "recipient_email": "owner@example.test",
                "payload": {"invitation_url": "https://example.test/?token=invite-secret"},
            },
            api_key="provider-secret",
            from_address="Inventory <no-reply@example.test>",
        )

    assert error.value.code == "provider_unavailable"
    assert error.value.provider_status == 403
    assert error.value.provider_error_category == "restricted_api_key"
    assert "private recipient" not in str(error.value)
    assert "invite-secret" not in str(error.value)
    assert "provider-secret" not in str(error.value)
