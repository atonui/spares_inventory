from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet


class _InsertResult:
    def fetchone(self):
        return {"id": 73}


class _Connection:
    def __init__(self):
        self.calls = []

    def execute(self, statement, params):
        self.calls.append((statement, params))
        return _InsertResult()


def test_email_change_verification_enqueue_encrypts_url_and_expiry():
    from backend.services.email_change_mail import enqueue_email_change_verification
    from backend.services.mail_payloads import decrypt_mail_payload

    key = Fernet.generate_key().decode("ascii")
    expires_at = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    connection = _Connection()

    message_id = enqueue_email_change_verification(
        connection,
        email="new@example.test",
        token="raw-change-token",
        frontend_url="https://app.example.test/base/",
        encryption_key=key,
        expires_at=expires_at,
    )

    assert message_id == 73
    _statement, params = connection.calls[0]
    assert params[0] is None
    assert params[1] == "email_change_verification"
    assert params[2] == "new@example.test"
    assert "raw-change-token" not in params[3]
    assert "raw-change-token" not in params[4]
    assert decrypt_mail_payload(params[3], key) == {
        "verification_url": "https://app.example.test/base/email_change_confirmation.html#token=raw-change-token",
        "expires_at": "2030-01-02T03:04:05.000000Z",
    }


@pytest.mark.parametrize("frontend_url", ["", "relative/path", "javascript:alert(1)"])
def test_email_change_verification_rejects_unsafe_frontend_url(frontend_url):
    from backend.services.email_change_mail import enqueue_email_change_verification

    with pytest.raises(ValueError, match="absolute HTTP URL"):
        enqueue_email_change_verification(
            _Connection(), email="new@example.test", token="token",
            frontend_url=frontend_url, encryption_key=Fernet.generate_key().decode(),
            expires_at=datetime(2030, 1, 2, tzinfo=timezone.utc),
        )


def test_old_address_notice_has_no_verification_token_or_link():
    from backend.services.email_change_mail import enqueue_email_changed_notice
    from backend.services.mail_payloads import decrypt_mail_payload

    key = Fernet.generate_key().decode("ascii")
    connection = _Connection()
    message_id = enqueue_email_changed_notice(
        connection,
        old_email="old@example.test",
        new_email="new@example.test",
        encryption_key=key,
    )

    assert message_id == 73
    _statement, params = connection.calls[0]
    assert params[:3] == (None, "email_changed_notice", "old@example.test")
    assert decrypt_mail_payload(params[3], key) == {"new_email": "new@example.test"}
    assert "token" not in params[3].lower()
