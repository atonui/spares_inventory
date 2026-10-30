"""Purpose-bound keyset cursors for native store and pending-transfer reads."""
from itsdangerous import BadData, URLSafeTimedSerializer


def encode_list_cursor(secret: str, kind: str, last_id: int) -> str:
    return URLSafeTimedSerializer(secret, salt=f'mobile-list-{kind}-v1').dumps({'v': 1, 'id': last_id})


def decode_list_cursor(secret: str, kind: str, cursor: str | None) -> int:
    if cursor is None:
        return 0
    if not cursor or len(cursor) > 2048:
        raise ValueError('Invalid continuation cursor')
    try:
        payload = URLSafeTimedSerializer(secret, salt=f'mobile-list-{kind}-v1').loads(cursor)
    except BadData:
        raise ValueError('Invalid continuation cursor') from None
    if not isinstance(payload, dict) or payload.get('v') != 1:
        raise ValueError('Invalid continuation cursor')
    value = payload.get('id')
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError('Invalid continuation cursor')
    return value
