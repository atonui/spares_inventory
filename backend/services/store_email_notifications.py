"""Queue stock and transfer notices for the assignee of an affected store."""

import logging
from urllib.parse import urlencode, urlsplit, urlunsplit

from backend.services.mail_outbox import enqueue_mail
from backend.services.mail_payloads import encrypt_mail_payload

logger = logging.getLogger("backend.store_email_notifications")

_MESSAGE_TYPES = {
    "stock_added": "stock_added_notice",
    "transfer_dispatched": "transfer_dispatched_notice",
    "transfer_received": "transfer_completed_notice",
    "transfer_returned": "transfer_completed_notice",
}


def _positive_integer(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _application_url(frontend_url: str, query: dict[str, int]) -> str:
    parsed = urlsplit(frontend_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Application base URL must be an absolute HTTP URL")
    base_path = parsed.path.rstrip("/")
    if not base_path.endswith("/static"):
        base_path += "/static"
    return urlunsplit((parsed.scheme, parsed.netloc, base_path + "/index.html", urlencode(query), ""))


def _message_payload(event_type: str, payload: dict, frontend_url: str) -> dict:
    if event_type == "stock_added":
        fields = ("store_id", "inventory_id", "store_name", "part_number", "quantity")
        if not isinstance(payload, dict) or not all(field in payload for field in fields):
            raise ValueError("Stock notification fields are incomplete")
        if not all(_positive_integer(payload[field]) for field in ("store_id", "inventory_id", "quantity")):
            raise ValueError("Stock notification values are invalid")
        return {
            "store_id": payload["store_id"],
            "inventory_id": payload["inventory_id"],
            "store_name": payload["store_name"],
            "part_number": payload["part_number"],
            "quantity": payload["quantity"],
            "inventory_url": _application_url(frontend_url, {
                "store_id": payload["store_id"], "inventory_id": payload["inventory_id"],
            }),
        }
    if event_type == "transfer_dispatched":
        fields = (
            "transfer_id", "source_store_name", "destination_store_name",
            "part_number", "quantity", "destination_store_id",
        )
        if not isinstance(payload, dict) or not all(field in payload for field in fields):
            raise ValueError("Transfer notification fields are incomplete")
        if not all(_positive_integer(payload[field]) for field in ("transfer_id", "destination_store_id", "quantity")):
            raise ValueError("Transfer notification values are invalid")
        return {
            "transfer_id": payload["transfer_id"],
            "source_store_name": payload["source_store_name"],
            "destination_store_name": payload["destination_store_name"],
            "part_number": payload["part_number"],
            "quantity": payload["quantity"],
            "transfer_url": _application_url(frontend_url, {"transfer_id": payload["transfer_id"]}),
        }
    fields = (
        "transfer_id", "source_store_name", "destination_store_name",
        "part_number", "quantity", "source_store_id",
    )
    if not isinstance(payload, dict) or not all(field in payload for field in fields):
        raise ValueError("Transfer notification fields are incomplete")
    if not all(_positive_integer(payload[field]) for field in ("transfer_id", "source_store_id", "quantity")):
        raise ValueError("Transfer notification values are invalid")
    return {
        "transfer_id": payload["transfer_id"],
        "action": "received" if event_type == "transfer_received" else "returned",
        "source_store_name": payload["source_store_name"],
        "destination_store_name": payload["destination_store_name"],
        "part_number": payload["part_number"],
        "quantity": payload["quantity"],
        "store_url": _application_url(frontend_url, {"store_id": payload["source_store_id"]}),
    }


def enqueue_store_notification(
    conn, *, event_type: str, organization_id, store_id: int, actor_user_id: int,
    event_id: int, payload: dict, frontend_url: str, encryption_key: str | None,
) -> bool:
    """Best-effort enqueue to the active assignee, omitting self-notifications."""
    message_type = _MESSAGE_TYPES.get(event_type)
    if message_type is None or not _positive_integer(event_id):
        raise ValueError("Store notification event is invalid")
    if not _positive_integer(store_id):
        raise ValueError("Store notification target is invalid")
    if not encryption_key:
        logger.warning("store email notification skipped (event=%s)", event_type)
        return False

    try:
        # This nested transaction is a savepoint inside the stock write. A mail
        # queue failure must not roll back a successfully recorded stock change.
        with conn.transaction():
            recipient = conn.execute(
                """SELECT u.id, u.email
                   FROM stores s
                   JOIN users u ON u.id = s.assigned_user_id AND u.archived_at IS NULL
                   JOIN organization_memberships membership
                     ON membership.user_id = u.id
                    AND membership.organization_id = s.organization_id
                    AND membership.is_active = TRUE
                   WHERE s.id = %s AND s.organization_id = %s
                     AND s.archived_at IS NULL""",
                (store_id, organization_id),
            ).fetchone()
            if recipient is None or recipient["id"] == actor_user_id:
                return False
            message_payload = _message_payload(event_type, payload, frontend_url)
            ciphertext = encrypt_mail_payload(message_payload, encryption_key)
            enqueue_mail(
                conn,
                organization_id=organization_id,
                message_type=message_type,
                recipient_email=recipient["email"],
                encrypted_payload=ciphertext,
                idempotency_key=(
                    f"store-notice-{event_type}-{event_id}-{recipient['id']}"
                ),
            )
        return True
    except Exception:
        logger.warning("store email notification could not be queued (event=%s)", event_type)
        return False
