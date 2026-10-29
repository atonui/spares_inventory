"""Server-bound support authorization; caller input never supplies tenant context."""

from contextlib import contextmanager
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from fastapi import HTTPException

from backend.postgres_database import postgres_transaction
from backend.temporal import serialize_instant, utc_now
from .authorization import require_platform_admin
from .principals import resolve_principal
from .session_credentials import hash_session_credential
from .tenant_context import set_tenant_context
from .platform_audit import record_platform_audit_event

SUPPORT_SESSION_LIFETIME = timedelta(minutes=15)


def end_support_sessions(conn, *, actor_user_id: int, end_reason: str,
                        auth_session_ids=None, target_user_id: int | None = None) -> int:
    """End active support rows atomically with the caller's auth/admin change."""
    valid_reasons = {
        "user_logout", "password_changed", "sessions_revoked", "platform_admin_revoked", "expired",
        "membership_removed", "membership_deactivated",
    }
    if end_reason not in valid_reasons:
        raise ValueError("Unsupported support-session end reason")
    params = []
    predicates = ["ended_at IS NULL"]
    if target_user_id is None:
        predicates.append("actor_user_id=%s")
        params.append(actor_user_id)
    else:
        predicates.append("actor_user_id=%s")
        params.append(target_user_id)
    if auth_session_ids is not None:
        ids = list(auth_session_ids)
        if not ids:
            return 0
        predicates.append("auth_session_id = ANY(%s)")
        params.append(ids)
    rows = conn.execute(
        "SELECT id,actor_user_id,organization_id FROM platform_support_sessions WHERE "
        + " AND ".join(predicates) + " FOR UPDATE",
        tuple(params),
    ).fetchall()
    if not rows:
        return 0
    ended_at = serialize_instant(utc_now())
    for row in rows:
        conn.execute("UPDATE platform_support_sessions SET ended_at=%s WHERE id=%s AND ended_at IS NULL",
                     (ended_at, row["id"]))
        details = {
            "support_session_id": str(row["id"]), "operation": "end",
            "end_reason": end_reason, "request_id": str(uuid4()),
        }
        if row["actor_user_id"] != actor_user_id:
            details["target_user_id"] = row["actor_user_id"]
        record_platform_audit_event(
            conn, actor_user_id, "support_session_ended", "success",
            row["organization_id"], details,
        )
    return len(rows)


def create_support_session(conn, *, actor_user_id: int, auth_session_id: int,
                           organization_id: UUID, reason: str, now: datetime) -> dict:
    """Create within the caller's transaction after password confirmation.

    Locking the login row serializes concurrent starts, including expired-session
    replacement. The caller owns commit/rollback and the start audit event.
    """
    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
        raise HTTPException(status_code=422, detail="Reason must be 10–500 characters")
    auth = conn.execute(
        """SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id
           JOIN platform_admins pa ON pa.user_id=s.user_id
           WHERE s.id=%s AND s.user_id=%s AND s.is_active=TRUE
             AND s.expires_at::timestamptz>%s AND u.archived_at IS NULL
           FOR UPDATE OF s""", (auth_session_id, actor_user_id, serialize_instant(now)),
    ).fetchone()
    if auth is None:
        raise HTTPException(status_code=403, detail="Support access denied")
    if conn.execute('SELECT id FROM organizations WHERE id=%s', (organization_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    live = conn.execute(
        """SELECT id FROM platform_support_sessions
           WHERE actor_user_id=%s AND auth_session_id=%s
             AND ended_at IS NULL AND expires_at>%s""",
        (actor_user_id, auth_session_id, serialize_instant(now)),
    ).fetchone()
    if live:
        raise HTTPException(status_code=409, detail="An active support session already exists")
    return conn.execute(
        """INSERT INTO platform_support_sessions
           (id,actor_user_id,auth_session_id,organization_id,reason,created_at,expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
        (uuid4(), actor_user_id, auth_session_id, organization_id, reason.strip(),
         serialize_instant(now), serialize_instant(now + SUPPORT_SESSION_LIFETIME)),
    ).fetchone()


@contextmanager
def authenticated_support_transaction(get_connection, *, session_token: str | None,
                                      support_session_id: UUID,
                                      expected_user_id: int | None = None):
    """Yield a validated support scope in a write-capable audited-read transaction.

    Endpoints append their resource-specific read audit before this commits;
    audit insertion failure therefore rolls back the read transaction.
    """
    conn = get_connection()
    try:
        with postgres_transaction(conn, readonly=False):
            conn.execute("SELECT set_config('app.organization_id', '', true)")
            principal = resolve_principal(conn, session_token)
            require_platform_admin(principal)
            if expected_user_id is not None and principal.user_id != expected_user_id:
                raise HTTPException(status_code=401, detail="Invalid or expired session")
            auth = conn.execute(
                """SELECT id FROM sessions WHERE session_token_hash=%s
                   AND user_id=%s AND is_active=TRUE AND expires_at::timestamptz>%s
                   FOR SHARE""",
                (hash_session_credential(session_token), principal.user_id, serialize_instant(utc_now())),
            ).fetchone()
            now = utc_now()
            support = conn.execute(
                """SELECT s.* FROM platform_support_sessions s
                   JOIN organizations o ON o.id=s.organization_id
                   WHERE s.id=%s AND s.actor_user_id=%s AND s.auth_session_id=%s
                     AND s.ended_at IS NULL
                   FOR SHARE OF s""",
                (support_session_id, principal.user_id, auth['id'] if auth else None),
            ).fetchone()
            if support is None:
                raise HTTPException(status_code=404, detail="Support session unavailable")
            if support['expires_at'] <= serialize_instant(now):
                conn.execute("UPDATE platform_support_sessions SET ended_at=%s WHERE id=%s",
                             (serialize_instant(now), support_session_id))
                record_platform_audit_event(
                    conn, principal.user_id, "support_session_ended", "success",
                    support['organization_id'], {
                        "support_session_id": str(support_session_id), "operation": "end",
                        "end_reason": "expired", "request_id": str(uuid4()),
                    },
                )
                expired = True
            else:
                expired = False
                set_tenant_context(conn, support['organization_id'])
                yield conn, principal, support
        if expired:
            raise HTTPException(status_code=404, detail="Support session unavailable")
    finally:
        conn.close()
