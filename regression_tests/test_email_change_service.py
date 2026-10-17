import hashlib
from datetime import datetime, timedelta, timezone

import pytest


class _Result:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class _Connection:
    def __init__(self):
        self.calls = []
        self.user = {"id": 7, "email": "old@example.test"}
        self.request = None
        self.taken_user = None
        self.pending_row = None
        self.email_updates = []
        self.cancellations = []
        self.consumptions = []
        self.outbox = []
        self.lookup_token = "raw-change-token"

    def execute(self, statement, params=()):
        self.calls.append((statement, params))
        if "set_config('app.email_change_token_hash'" in statement:
            return _Result()
        if "SELECT id, email FROM users" in statement:
            return _Result(dict(self.user))
        if "UPDATE email_change_requests SET canceled_at" in statement:
            self.cancellations.append(params)
            return _Result()
        if "SELECT id FROM users" in statement and "lower(btrim(email))" in statement:
            return _Result(self.taken_user)
        if "INSERT INTO email_change_requests" in statement:
            self.request = {
                "id": 81,
                "user_id": params[0],
                "proposed_email": params[1],
                "token_hash": params[2],
                "delivery_suppressed": params[3],
                "expires_at": params[4],
                "consumed_at": None,
                "canceled_at": None,
            }
            return _Result({"id": 81})
        if "SELECT proposed_email, expires_at FROM email_change_requests" in statement:
            return _Result(self.pending_row or self.request)
        if "SELECT user_id FROM email_change_requests WHERE token_hash" in statement:
            if self.request and params[0] == self.request["token_hash"]:
                return _Result({"user_id": self.request["user_id"]})
            return _Result()
        if "SELECT id, proposed_email, expires_at, consumed_at, canceled_at" in statement:
            if self.request and params[0] == self.request["token_hash"]:
                return _Result(self.request)
            return _Result()
        if "UPDATE users SET email" in statement:
            self.email_updates.append(params)
            self.user["email"] = params[0]
            return _Result()
        if "UPDATE email_change_requests SET consumed_at" in statement:
            self.consumptions.append(params)
            self.request["consumed_at"] = params[0]
            return _Result()
        if "INSERT INTO mail_outbox" in statement:
            self.outbox.append(params)
            return _Result({"id": len(self.outbox) + 100})
        raise AssertionError(f"Unexpected query: {statement}")


def test_email_change_email_normalization_trims_and_lowercases():
    from backend.services.email_change import normalize_email

    assert normalize_email("  Person.Name+tag@Example.TEST  ") == "person.name+tag@example.test"


def test_email_change_token_hash_is_sha256_and_rejects_empty_tokens():
    import pytest

    from backend.services.email_change import hash_email_change_token

    assert hash_email_change_token("random-one-time-token") == hashlib.sha256(
        b"random-one-time-token"
    ).hexdigest()
    with pytest.raises(ValueError, match="token is invalid"):
        hash_email_change_token("")
    with pytest.raises(ValueError, match="token is invalid"):
        hash_email_change_token("x" * 201)


def test_request_keeps_current_email_and_stores_only_token_hash(monkeypatch):
    from cryptography.fernet import Fernet

    from backend.services.email_change import request_email_change
    from backend.services.mail_payloads import decrypt_mail_payload

    import backend.services.email_change as service

    monkeypatch.setattr(service.secrets, "token_urlsafe", lambda _size: "raw-change-token-fixture")
    key = Fernet.generate_key().decode("ascii")
    now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    connection = _Connection()

    result = request_email_change(
        connection,
        user_id=7,
        proposed_email=" New@Example.Test ",
        frontend_url="https://app.example.test",
        encryption_key=key,
        now=now,
    )

    assert result == {"status": "pending", "expires_at": "2030-01-02T04:04:05.000000Z"}
    assert connection.user["email"] == "old@example.test"
    assert connection.request["proposed_email"] == "new@example.test"
    assert connection.request["token_hash"] == hashlib.sha256(b"raw-change-token-fixture").hexdigest()
    assert "raw-change-token-fixture" not in str(connection.request)
    mail = connection.outbox[0]
    assert mail[1] == "email_change_verification"
    payload = decrypt_mail_payload(mail[3], key)
    assert "raw-change-token-fixture" in payload["verification_url"]
    assert "raw-change-token" not in str(mail)


def test_request_for_registered_email_returns_generic_unavailable_without_mail(monkeypatch):
    from cryptography.fernet import Fernet

    from backend.services.email_change import request_email_change

    connection = _Connection()
    connection.request = {
        "id": 70,
        "user_id": 7,
        "proposed_email": "pending@example.test",
        "token_hash": "existing-token-hash",
        "delivery_suppressed": False,
        "expires_at": "2030-01-02T01:00:00.000000Z",
        "consumed_at": None,
        "canceled_at": None,
    }
    connection.taken_user = {"id": 8}
    result = request_email_change(
        connection,
        user_id=7,
        proposed_email="taken@example.test",
        frontend_url="https://app.example.test",
        encryption_key=Fernet.generate_key().decode("ascii"),
        now=datetime(2030, 1, 2, tzinfo=timezone.utc),
    )
    assert result["status"] == "pending"
    assert connection.outbox == []
    assert connection.cancellations
    assert connection.request["proposed_email"] == "taken@example.test"
    assert connection.request["delivery_suppressed"] is True
    assert connection.request["token_hash"] != "raw-change-token"


def test_pending_request_exposes_only_masked_email_and_utc_expiry():
    from backend.services.email_change import get_pending_email_change
    from backend.temporal import serialize_instant

    connection = _Connection()
    expires_at = datetime(2030, 1, 2, 4, 0, tzinfo=timezone.utc)
    connection.pending_row = {
        "proposed_email": "person@example.test",
        "expires_at": serialize_instant(expires_at),
    }
    assert get_pending_email_change(
        connection,
        user_id=7,
        now=datetime(2030, 1, 2, 3, 0, tzinfo=timezone.utc),
    ) == {
        "status": "pending",
        "proposed_email": "p***@example.test",
        "expires_at": "2030-01-02T04:00:00.000000Z",
    }


def test_confirmation_updates_email_consumes_token_and_notifies_old_address():
    from cryptography.fernet import Fernet

    from backend.services.email_change import confirm_email_change
    from backend.services.mail_payloads import decrypt_mail_payload
    from backend.temporal import serialize_instant

    key = Fernet.generate_key().decode("ascii")
    now = datetime(2030, 1, 2, 3, 0, tzinfo=timezone.utc)
    connection = _Connection()
    connection.request = {
        "id": 81,
        "user_id": 7,
        "proposed_email": "new@example.test",
        "token_hash": hashlib.sha256(b"raw-change-token-fixture").hexdigest(),
        "delivery_suppressed": False,
        "expires_at": serialize_instant(now + timedelta(minutes=10)),
        "consumed_at": None,
        "canceled_at": None,
    }

    result = confirm_email_change(
        connection,
        token="raw-change-token-fixture",
        encryption_key=key,
        now=now,
    )

    assert result == {"email": "new@example.test"}
    assert connection.email_updates == [("new@example.test", 7)]
    assert connection.request["consumed_at"] == serialize_instant(now)
    assert connection.outbox[0][1:3] == ("email_changed_notice", "old@example.test")
    assert decrypt_mail_payload(connection.outbox[0][3], key) == {"new_email": "new@example.test"}


def test_expired_confirmation_does_not_change_email_or_consume_request():
    from backend.services.email_change import EmailChangeFailure, confirm_email_change
    from backend.temporal import serialize_instant

    now = datetime(2030, 1, 2, 3, 0, tzinfo=timezone.utc)
    connection = _Connection()
    connection.request = {
        "id": 81,
        "user_id": 7,
        "proposed_email": "new@example.test",
        "token_hash": hashlib.sha256(b"raw-change-token-fixture").hexdigest(),
        "delivery_suppressed": False,
        "expires_at": serialize_instant(now - timedelta(seconds=1)),
        "consumed_at": None,
        "canceled_at": None,
    }

    with pytest.raises(EmailChangeFailure) as error:
        confirm_email_change(connection, token="raw-change-token-fixture", encryption_key="key", now=now)

    assert error.value.status_code == 400
    assert error.value.code == "invalid_email_change_token"
    assert connection.email_updates == []
    assert connection.consumptions == []


def test_non_deliverable_pending_placeholder_cannot_be_confirmed():
    from backend.services.email_change import EmailChangeFailure, confirm_email_change
    from backend.temporal import serialize_instant

    now = datetime(2030, 1, 2, 3, 0, tzinfo=timezone.utc)
    connection = _Connection()
    connection.request = {
        "id": 81,
        "user_id": 7,
        "proposed_email": "occupied@example.test",
        "token_hash": hashlib.sha256(b"raw-change-token-fixture").hexdigest(),
        "delivery_suppressed": True,
        "expires_at": serialize_instant(now + timedelta(minutes=10)),
        "consumed_at": None,
        "canceled_at": None,
    }
    with pytest.raises(EmailChangeFailure) as error:
        confirm_email_change(
            connection,
            token="raw-change-token-fixture",
            encryption_key="unused",
            now=now,
        )
    assert error.value.status_code == 400
    assert error.value.code == "invalid_email_change_token"
    assert connection.email_updates == []
