import pytest
pytest_plugins = ("regression_tests.postgres_fixtures",)
from cryptography.fernet import Fernet

from backend.services.platform_support_inbox import (
    decrypt_support_payload,
    encrypt_support_payload,
    normalize_email,
    safe_inbound_payload,
    sender_lookup_hash,
)


def test_support_payload_is_encrypted_and_round_trips():
    key = Fernet.generate_key().decode("ascii")
    payload = {"sender": "owner@example.com", "text": "please help"}
    encrypted = encrypt_support_payload(payload, key)
    assert b"owner@example.com" not in encrypted
    assert b"please help" not in encrypted
    assert decrypt_support_payload(encrypted, key) == payload


def test_sender_hash_uses_normalized_address():
    assert sender_lookup_hash("Owner <OWNER@example.com>") == sender_lookup_hash("owner@example.com")


def test_inbound_payload_keeps_only_thread_headers_and_encrypts_contact_data():
    key = Fernet.generate_key().decode("ascii")
    encrypted = safe_inbound_payload(
        sender="Owner <owner@example.com>", recipient="support@sparestracker.com",
        subject="Help", text="Part issue", headers={"Message-ID": "<one>", "X-Secret": "ignored"},
        attachments=[{"id": "a1", "filename": "photo.png"}], key=key,
    )
    assert b"owner@example.com" not in encrypted
    payload = decrypt_support_payload(encrypted, key)
    assert payload["headers"] == {"message-id": "<one>"}
    assert payload["attachments"][0]["filename"] == "photo.png"


@pytest.mark.parametrize("address", ["bad", "x@@example.com", "", "owner@example.com\nBcc:evil@example.com", "a@example.com,b@example.com"])
def test_email_normalizer_rejects_invalid_addresses(address):
    with pytest.raises(ValueError):
        normalize_email(address)


def test_support_audit_details_keep_only_safe_record_identifiers():
    from backend.services.platform_audit import safe_platform_audit_details

    assert safe_platform_audit_details("platform_support_reply_queued", {
        "conversation_id": 12, "message_id": 14, "email": "owner@example.com",
        "subject": "private", "text": "private body",
    }) == {"conversation_id": 12, "message_id": 14}


def test_received_email_is_idempotent_encrypted_and_threaded_by_sender(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from backend.services.platform_support_inbox import store_inbound_message

    conn, _schema = postgres_schema
    apply_postgres_migrations(conn)
    key = Fernet.generate_key().decode("ascii")
    first = {
        "from": "Owner <owner@example.com>", "to": ["support@sparestracker.com"],
        "subject": "Help", "text": "First request", "created_at": "2026-11-15T12:00:00Z",
        "message_id": "<incoming-1@example.com>", "headers": {"Message-ID": "<incoming-1@example.com>"},
        "attachments": [],
    }
    assert store_inbound_message(conn, event_id="event-1", provider_email_id="email-1",
        message=first, support_address="support@sparestracker.com", encryption_key=key)
    assert not store_inbound_message(conn, event_id="event-1", provider_email_id="email-1",
        message=first, support_address="support@sparestracker.com", encryption_key=key)
    conversation_id = conn.execute("SELECT id FROM platform_support_conversations").fetchone()["id"]
    encrypted = conn.execute("SELECT encrypted_payload FROM platform_support_messages WHERE direction='inbound'").fetchone()["encrypted_payload"]
    assert b"owner@example.com" not in bytes(encrypted)
    sent_payload = encrypt_support_payload({"text": "reply"}, key)
    conn.execute("""INSERT INTO platform_support_messages
        (conversation_id,direction,encrypted_payload,provider_message_id,delivery_status,created_at)
        VALUES (%s,'outbound',%s,'<sent-1@example.com>','sent','2026-11-15T12:01:00Z')""",
        (conversation_id, sent_payload))
    follow_up = {**first, "subject": "Re: Help", "text": "Follow-up",
        "created_at": "2026-11-15T12:02:00Z", "message_id": "<incoming-2@example.com>",
        "headers": {"Message-ID": "<incoming-2@example.com>", "In-Reply-To": "<sent-1@example.com>"}}
    assert store_inbound_message(conn, event_id="event-2", provider_email_id="email-2",
        message=follow_up, support_address="support@sparestracker.com", encryption_key=key)
    assert conn.execute("SELECT count(*) AS n FROM platform_support_conversations").fetchone()["n"] == 1
    wrong_sender = {**follow_up, "from": "other@example.com", "created_at": "2026-11-15T12:03:00Z"}
    assert store_inbound_message(conn, event_id="event-3", provider_email_id="email-3",
        message=wrong_sender, support_address="support@sparestracker.com", encryption_key=key)
    assert conn.execute("SELECT count(*) AS n FROM platform_support_conversations").fetchone()["n"] == 2
