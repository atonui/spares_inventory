"""Encrypted support inbox payload helpers and safe sender normalization."""

import hashlib
import re
from email.utils import getaddresses
from typing import Any

from backend.services.mail_payloads import decrypt_mail_payload, encrypt_mail_payload
from backend.temporal import parse_api_instant, serialize_instant

_EMAIL = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


def normalize_email(value: str) -> str:
    """Return a normalized mailbox address; reject display-name ambiguity."""
    if not isinstance(value, str) or len(value) > 320 or any(ord(char) < 32 for char in value):
        raise ValueError("Invalid email address")
    parsed = getaddresses([value])
    if len(parsed) != 1:
        raise ValueError("Invalid email address")
    _name, address = parsed[0]
    address = address.strip().casefold()
    if not _EMAIL.fullmatch(address):
        raise ValueError("Invalid email address")
    return address


def sender_lookup_hash(address: str) -> str:
    return hashlib.sha256(normalize_email(address).encode("utf-8")).hexdigest()


def encrypt_support_payload(payload: dict[str, Any], key: str) -> bytes:
    """Encrypt all message/contact metadata before persistence."""
    if not isinstance(payload, dict):
        raise TypeError("support payload must be an object")
    return encrypt_mail_payload(payload, key).encode("ascii")


def decrypt_support_payload(ciphertext: bytes, key: str) -> dict[str, Any]:
    if not isinstance(ciphertext, bytes):
        raise TypeError("support payload must be bytes")
    return decrypt_mail_payload(ciphertext.decode("ascii"), key)


def safe_inbound_payload(*, sender: str, recipient: str, subject: str,
                         text: str, headers: dict[str, str], attachments: list[dict],
                         key: str) -> bytes:
    """Validate and encrypt inbound details; caller must never log this value."""
    sender = normalize_email(sender)
    recipient = normalize_email(recipient)
    if not isinstance(subject, str) or len(subject) > 998:
        raise ValueError("Invalid subject")
    if not isinstance(text, str) or len(text) > 1_000_000:
        raise ValueError("Invalid message body")
    if not isinstance(headers, dict) or len(headers) > 100:
        raise ValueError("Invalid message headers")
    if not isinstance(attachments, list) or len(attachments) > 50:
        raise ValueError("Invalid attachment metadata")
    normalized_headers = {}
    for name, value in headers.items():
        key_name = str(name).lower()
        if key_name not in {"message-id", "in-reply-to", "references"}:
            continue
        normalized = re.sub(r"\r?\n[ \t]+", " ", str(value))[:2000]
        if any(ord(char) < 32 and char != "\t" for char in normalized):
            continue
        normalized_headers[key_name] = normalized.strip()
    return encrypt_support_payload({
        "sender": sender, "recipient": recipient, "subject": subject,
        "text": text, "headers": normalized_headers, "attachments": attachments,
    }, key)


def store_inbound_message(conn, *, event_id: str, provider_email_id: str,
                          message: dict[str, Any], support_address: str,
                          encryption_key: str) -> bool:
    """Persist one received message; return False when the provider email is duplicate."""
    if not event_id or len(event_id) > 255 or not provider_email_id or len(provider_email_id) > 255:
        raise ValueError("Invalid provider event")
    recipient_values = message.get("to")
    if isinstance(recipient_values, str):
        recipient_values = [recipient_values]
    if not isinstance(recipient_values, list) or not any(
        normalize_email(item) == normalize_email(support_address)
        for item in recipient_values if isinstance(item, str)
    ):
        raise ValueError("Unexpected recipient")
    sender = normalize_email(message.get("from"))
    headers_raw = message.get("headers")
    headers = {}
    if isinstance(headers_raw, list):
        for item in headers_raw:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                headers[item["name"]] = str(item.get("value", ""))
    elif isinstance(headers_raw, dict):
        headers = headers_raw
    attachment_list = message.get("attachments")
    if not isinstance(attachment_list, list):
        attachment_list = []
    attachment_metadata = []
    for item in attachment_list[:50]:
        if isinstance(item, dict):
            attachment_metadata.append({key: item.get(key) for key in
                ("id", "filename", "content_type", "content_disposition", "content_id")})
    body = message.get("text")
    if not isinstance(body, str):
        body = ""
    encrypted = safe_inbound_payload(
        sender=sender, recipient=support_address, subject=message.get("subject") or "",
        text=body, headers=headers, attachments=attachment_metadata, key=encryption_key,
    )
    stamp = message.get("created_at")
    if not isinstance(stamp, str) or not stamp:
        raise ValueError("Invalid received timestamp")
    try:
        stamp = serialize_instant(parse_api_instant(stamp))
    except (TypeError, ValueError):
        raise ValueError("Invalid received timestamp") from None
    normalized_sender_hash = sender_lookup_hash(sender)

    # Provider email ID is the durable duplicate key even if a webhook retry has
    # a different event ID.
    inserted = conn.execute(
        """INSERT INTO platform_support_webhook_events (event_id,provider_email_id,received_at)
           VALUES (%s,%s,%s) ON CONFLICT (event_id) DO NOTHING RETURNING event_id""",
        (event_id, provider_email_id, stamp),
    ).fetchone()
    if inserted is None:
        return False
    if conn.execute("SELECT 1 FROM platform_support_messages WHERE provider_email_id=%s", (provider_email_id,)).fetchone():
        conn.execute("UPDATE platform_support_webhook_events SET processed_at=%s WHERE event_id=%s", (stamp,event_id))
        return False

    references = headers.get("In-Reply-To", headers.get("in-reply-to", ""))
    references = str(references) + " " + str(headers.get("References", headers.get("references", "")))
    candidate_ids = [part.strip() for part in references.split() if part.strip()]
    conversation = None
    if candidate_ids:
        matched = conn.execute(
            """SELECT c.id,c.original_sender_hash FROM platform_support_messages m
               JOIN platform_support_conversations c ON c.id=m.conversation_id
               WHERE m.direction='outbound' AND m.provider_message_id = ANY(%s)
               ORDER BY m.id DESC LIMIT 1""", (candidate_ids,),
        ).fetchone()
        if matched and matched["original_sender_hash"] == normalized_sender_hash:
            conversation = matched
    if conversation is None:
        conversation = conn.execute(
            """INSERT INTO platform_support_conversations
               (status,is_read,original_sender_hash,created_at,updated_at,latest_message_at)
               VALUES ('open',FALSE,%s,%s,%s,%s) RETURNING id""",
            (normalized_sender_hash,stamp,stamp,stamp),
        ).fetchone()
    conn.execute(
        """INSERT INTO platform_support_messages
           (conversation_id,direction,encrypted_payload,provider_email_id,provider_message_id,
            delivery_status,attachment_count,created_at)
           VALUES (%s,'inbound',%s,%s,%s,'unknown',%s,%s)""",
        (conversation["id"],encrypted,provider_email_id,message.get("message_id"),
         len(attachment_metadata),stamp),
    )
    conn.execute("UPDATE platform_support_conversations SET status='open',is_read=FALSE,latest_message_at=GREATEST(latest_message_at,%s),updated_at=%s WHERE id=%s",
                 (stamp,stamp,conversation["id"]))
    conn.execute("UPDATE platform_support_webhook_events SET processed_at=%s WHERE event_id=%s", (stamp,event_id))
    return True
