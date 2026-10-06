import smtplib

import pytest
from fastapi import HTTPException


def test_reset_email_service_builds_and_sends_reset_message(monkeypatch):
    from backend.email_service import send_password_reset_email

    sent = []

    class FakeSMTP:
        def __init__(self, server, port, timeout):
            sent.append(("connect", server, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def starttls(self):
            sent.append(("starttls",))

        def login(self, username, password):
            sent.append(("login", username, password))

        def send_message(self, message):
            sent.append(("message", message))

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    send_password_reset_email(
        email="user@example.test",
        token="reset-token",
        frontend_url="https://inventory.example.test",
        smtp_server="smtp.example.test",
        smtp_port=587,
        smtp_username="sender@example.test",
        smtp_password="secret",
        logger=None,
    )

    assert sent[:3] == [
        ("connect", "smtp.example.test", 587, 10),
        ("starttls",),
        ("login", "sender@example.test", "secret"),
    ]
    message = sent[3][1]
    assert message["Subject"] == "Password Reset Request - Inventory System"
    assert message["From"] == "sender@example.test"
    assert message["To"] == "user@example.test"
    assert "https://inventory.example.test/reset_password.html?token=reset-token" in message.as_string()


@pytest.mark.parametrize(
    "error,detail",
    [
        (
            smtplib.SMTPAuthenticationError(535, b"bad credentials"),
            "Email configuration error. Please contact administrator.",
        ),
        (smtplib.SMTPException("smtp down"), "Failed to send reset email."),
        (RuntimeError("network down"), "Failed to send reset email."),
    ],
)
def test_reset_email_service_maps_smtp_errors(monkeypatch, error, detail):
    from backend.email_service import send_password_reset_email

    class FailingSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise error

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(smtplib, "SMTP", FailingSMTP)

    with pytest.raises(HTTPException) as exc:
        send_password_reset_email(
            email="user@example.test",
            token="reset-token",
            frontend_url="https://inventory.example.test",
            smtp_server="smtp.example.test",
            smtp_port=587,
            smtp_username="sender@example.test",
            smtp_password="secret",
            logger=None,
        )

    assert exc.value.status_code == 500
    assert exc.value.detail == detail
