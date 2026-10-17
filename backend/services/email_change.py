"""Transactional lifecycle for verified account email changes."""

import hashlib
import secrets
from datetime import datetime, timedelta

from backend.services.email_change_mail import (
    enqueue_email_change_verification,
    enqueue_email_changed_notice,
)
from backend.temporal import serialize_instant, utc_now
from backend.temporal_contract import stored_instant

EMAIL_CHANGE_TTL = timedelta(hours=1)


class EmailChangeFailure(Exception):
    """Safe email-change failure with an HTTP-compatible status and code."""

    def __init__(self, status_code: int, code: str):
        self.status_code = status_code
        self.code = code
        super().__init__(code)


def normalize_email(email: str) -> str:
    if not isinstance(email, str) or not email.strip():
        raise ValueError("Email address is required")
    return email.strip().lower()


def hash_email_change_token(token: str) -> str:
    if not isinstance(token, str) or len(token) < 20 or len(token) > 200:
        raise ValueError("Email-change token is invalid")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _lock_user(conn, user_id: int):
    user = conn.execute(
        "SELECT id, email FROM users WHERE id = %s AND archived_at IS NULL FOR UPDATE",
        (user_id,),
    ).fetchone()
    if user is None:
        raise EmailChangeFailure(404, "account_unavailable")
    return user


def _mask_email(email: str) -> str:
    local, separator, domain = email.partition("@")
    if not separator:
        return "***"
    visible = local[:1] if local else "*"
    return f"{visible}***@{domain}"


def request_email_change(
    conn, *, user_id: int, proposed_email: str, frontend_url: str,
    encryption_key: str | None, now: datetime | None = None,
) -> dict:
    """Create or replace the caller's pending request; caller owns the transaction."""
    normalized_email = normalize_email(proposed_email)
    current = now or utc_now()
    user = _lock_user(conn, user_id)
    if normalize_email(user["email"]) == normalized_email:
        raise EmailChangeFailure(422, "same_email")

    current_text = serialize_instant(current)
    conn.execute(
        """UPDATE email_change_requests SET canceled_at = %s
           WHERE user_id = %s AND consumed_at IS NULL AND canceled_at IS NULL""",
        (current_text, user_id),
    )
    existing = conn.execute(
        """SELECT id FROM users
           WHERE lower(btrim(email)) = %s AND id <> %s LIMIT 1""",
        (normalized_email, user_id),
    ).fetchone()

    token = secrets.token_urlsafe(32)
    expires_at = current + EMAIL_CHANGE_TTL
    conn.execute(
        """INSERT INTO email_change_requests
           (user_id, proposed_email, token_hash, delivery_suppressed, expires_at)
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (
            user_id,
            normalized_email,
            hash_email_change_token(token),
            existing is not None,
            serialize_instant(expires_at),
        ),
    ).fetchone()
    if existing is None:
        enqueue_email_change_verification(
            conn,
            email=normalized_email,
            token=token,
            frontend_url=frontend_url,
            encryption_key=encryption_key,
            expires_at=expires_at,
        )
    return {"status": "pending", "expires_at": serialize_instant(expires_at)}


def get_pending_email_change(
    conn, *, user_id: int, now: datetime | None = None,
) -> dict | None:
    current = now or utc_now()
    row = conn.execute(
        """SELECT proposed_email, expires_at FROM email_change_requests
           WHERE user_id = %s AND consumed_at IS NULL AND canceled_at IS NULL
           ORDER BY created_at DESC, id DESC LIMIT 1""",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    expires_at = stored_instant(row["expires_at"], "expires_at")
    if current >= expires_at:
        return None
    return {
        "status": "pending",
        "proposed_email": _mask_email(row["proposed_email"]),
        "expires_at": serialize_instant(expires_at),
    }


def cancel_email_change(
    conn, *, user_id: int, now: datetime | None = None,
) -> None:
    current_text = serialize_instant(now or utc_now())
    _lock_user(conn, user_id)
    conn.execute(
        """UPDATE email_change_requests SET canceled_at = %s
           WHERE user_id = %s AND consumed_at IS NULL AND canceled_at IS NULL""",
        (current_text, user_id),
    )


def confirm_email_change(
    conn, *, token: str, encryption_key: str | None, now: datetime | None = None,
) -> dict:
    """Consume the one-time token and queue the old-address notice atomically."""
    try:
        token_hash = hash_email_change_token(token)
    except ValueError:
        raise EmailChangeFailure(400, "invalid_email_change_token") from None
    # The RLS policy permits the unauthenticated confirmation transaction to
    # see only the single row addressed by this capability hash.
    conn.execute(
        "SELECT set_config('app.email_change_token_hash', %s, true)",
        (token_hash,),
    )
    current = now or utc_now()
    request_ref = conn.execute(
        "SELECT user_id FROM email_change_requests WHERE token_hash = %s",
        (token_hash,),
    ).fetchone()
    if request_ref is None:
        raise EmailChangeFailure(400, "invalid_email_change_token")

    user = _lock_user(conn, request_ref["user_id"])
    request_row = conn.execute(
        """SELECT id, proposed_email, expires_at, consumed_at, canceled_at, delivery_suppressed
           FROM email_change_requests
           WHERE token_hash = %s AND user_id = %s FOR UPDATE""",
        (token_hash, request_ref["user_id"]),
    ).fetchone()
    if (
        request_row is None
        or request_row["consumed_at"]
        or request_row["canceled_at"]
        or request_row["delivery_suppressed"]
    ):
        raise EmailChangeFailure(400, "invalid_email_change_token")

    expires_at = stored_instant(request_row["expires_at"], "expires_at")
    if current >= expires_at:
        raise EmailChangeFailure(400, "invalid_email_change_token")

    proposed_email = normalize_email(request_row["proposed_email"])
    existing = conn.execute(
        """SELECT id FROM users
           WHERE lower(btrim(email)) = %s AND id <> %s LIMIT 1""",
        (proposed_email, user["id"]),
    ).fetchone()
    if existing is not None:
        raise EmailChangeFailure(409, "email_change_unavailable")

    conn.execute("UPDATE users SET email = %s WHERE id = %s", (proposed_email, user["id"]))
    conn.execute(
        """UPDATE email_change_requests SET consumed_at = %s
           WHERE id = %s AND consumed_at IS NULL AND canceled_at IS NULL""",
        (serialize_instant(current), request_row["id"]),
    )
    enqueue_email_changed_notice(
        conn,
        old_email=user["email"],
        new_email=proposed_email,
        encryption_key=encryption_key,
    )
    return {"email": proposed_email}
