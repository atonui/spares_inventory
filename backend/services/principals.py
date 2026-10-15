"""Server-derived authenticated identity and company membership."""

from dataclasses import dataclass
from uuid import UUID

import psycopg
from fastapi import HTTPException

from backend.temporal import parse_storage_instant, utc_now
from backend.temporal_manifest import TemporalField
from .session_credentials import hash_session_credential


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    user_id: int
    organization_id: UUID | None
    company_role: str | None
    is_platform_admin: bool


SESSION_EXPIRES_FIELD = TemporalField(
    table="sessions",
    column="expires_at",
    kind="instant",
    naive_policy=None,
    provenance="PostgreSQL sessions store canonical UTC instants",
)


def resolve_principal(conn: psycopg.Connection, session_token: str) -> AuthenticatedPrincipal:
    """Resolve the session's sole active company membership from trusted database state."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session_token_hash = hash_session_credential(session_token)
    row = conn.execute(
        """SELECT s.user_id, s.expires_at, u.archived_at,
                  om.organization_id, om.company_role, om.is_active AS membership_active,
                  (pa.user_id IS NOT NULL) AS is_platform_admin
           FROM sessions AS s
           JOIN users AS u ON u.id = s.user_id
           LEFT JOIN organization_memberships AS om ON om.user_id = u.id
           LEFT JOIN platform_admins AS pa ON pa.user_id = u.id
           WHERE s.session_token_hash = %s AND s.is_active = TRUE""",
        (session_token_hash,),
    ).fetchone()
    if row is None or row["archived_at"] is not None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    try:
        expires_at = parse_storage_instant(row["expires_at"], field=SESSION_EXPIRES_FIELD)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired session") from None
    if utc_now() >= expires_at:
        raise HTTPException(status_code=401, detail="Session expired")

    is_platform_admin = bool(row["is_platform_admin"])
    has_membership = row["organization_id"] is not None and bool(row["membership_active"])
    if not has_membership and not is_platform_admin:
        raise HTTPException(status_code=403, detail="Active company membership required")
    return AuthenticatedPrincipal(
        user_id=row["user_id"],
        organization_id=UUID(str(row["organization_id"])) if has_membership else None,
        company_role=row["company_role"] if has_membership else None,
        is_platform_admin=is_platform_admin,
    )
