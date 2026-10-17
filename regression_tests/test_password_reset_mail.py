"""Password-reset mail is queued for the PostgreSQL SaaS path."""

from cryptography.fernet import Fernet
from datetime import datetime, timezone


class _InsertResult:
    def fetchone(self):
        return {"id": 41}


class _Connection:
    def __init__(self):
        self.calls = []

    def execute(self, statement, params):
        self.calls.append((statement, params))
        return _InsertResult()


def test_password_reset_enqueue_stores_encrypted_link_without_tenant_scope():
    from backend.services.mail_outbox import enqueue_mail

    connection = _Connection()
    message_id = enqueue_mail(
        connection,
        organization_id=None,
        message_type="password_reset",
        recipient_email="person@example.test",
        encrypted_payload="ciphertext",
        idempotency_key="password-reset-random-id",
    )

    assert message_id == 41
    statement, params = connection.calls[0]
    assert "INSERT INTO mail_outbox" in statement
    assert params == (None, "password_reset", "person@example.test", "ciphertext", "password-reset-random-id")


def test_password_reset_mail_is_sent_with_the_decrypted_reset_link():
    from backend.services.mail_delivery import send_mail
    from regression_tests.test_mail_delivery import _Transport

    transport = _Transport()
    send_mail(
        {
            "message_type": "password_reset",
            "recipient_email": "person@example.test",
            "payload": {"reset_url": "https://app.example.test/reset_password.html?token=raw-token"},
        },
        api_key="provider-key",
        from_address="SparesFlow <mail@example.test>",
        http_transport=transport,
    )

    _url, body, _headers, _timeout = transport.calls[0]
    assert body["to"] == ["person@example.test"]
    assert "raw-token" in body["html"]
    assert "reset" in body["subject"].lower()


def test_password_reset_service_encrypts_reset_link_before_enqueue():
    from backend.services.mail_payloads import decrypt_mail_payload
    from backend.services.password_reset_mail import enqueue_password_reset_mail

    key = Fernet.generate_key().decode("ascii")
    connection = _Connection()
    expires_at = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    message_id = enqueue_password_reset_mail(
        connection,
        email="person@example.test",
        token="raw-token",
        frontend_url="https://app.example.test",
        encryption_key=key,
        expires_at=expires_at,
    )

    assert message_id == 41
    _statement, params = connection.calls[0]
    assert params[0] is None
    assert params[1] == "password_reset"
    assert params[2] == "person@example.test"
    payload = decrypt_mail_payload(params[3], key)
    assert payload == {
        "reset_url": "https://app.example.test/reset_password.html?token=raw-token",
        "expires_at": "2030-01-02T03:04:05.000000Z",
    }
    assert params[4].startswith("password-reset-")
    assert "raw-token" not in params[4]
