"""Signed opaque cursors for stable v1 inventory pagination."""

from __future__ import annotations

from dataclasses import dataclass

from itsdangerous import BadData, URLSafeTimedSerializer


_CURSOR_SALT = "inventory-v1-cursor-v1"
_MAX_CURSOR_LENGTH = 2048


@dataclass(frozen=True)
class InventoryCursor:
    inventory_id: int


def _serializer(secret: str) -> URLSafeTimedSerializer:
    if not secret:
        raise ValueError("Cursor signing secret is not configured")
    return URLSafeTimedSerializer(secret_key=secret, salt=_CURSOR_SALT)


def encode_inventory_cursor(
    secret: str,
    inventory_id: int,
) -> str:
    """Sign a row ID; current tenant-scoped data supplies the sort key."""
    if isinstance(inventory_id, bool) or not isinstance(inventory_id, int) or inventory_id < 1:
        raise ValueError("Invalid inventory cursor values")
    return _serializer(secret).dumps(
        {
            "v": 1,
            "inventory_id": inventory_id,
        }
    )


def decode_inventory_cursor(secret: str, cursor: str) -> InventoryCursor:
    """Validate a v1 inventory cursor and return its continuation values."""
    if not cursor or len(cursor) > _MAX_CURSOR_LENGTH:
        raise ValueError("Invalid inventory cursor")
    try:
        payload = _serializer(secret).loads(cursor)
    except BadData:
        raise ValueError("Invalid inventory cursor") from None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise ValueError("Invalid inventory cursor")
    inventory_id = payload.get("inventory_id")
    if (
        isinstance(inventory_id, bool)
        or not isinstance(inventory_id, int)
        or inventory_id < 1
    ):
        raise ValueError("Invalid inventory cursor")
    return InventoryCursor(inventory_id)
