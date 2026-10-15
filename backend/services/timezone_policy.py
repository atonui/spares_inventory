"""Single-organisation policy provider; no tenant-isolation claims."""
from dataclasses import dataclass
from uuid import UUID
from fastapi import HTTPException
from backend.database_sql import execute, is_postgres
from backend.temporal import validate_zone
from .principals import AuthenticatedPrincipal


@dataclass(frozen=True)
class BusinessTimeContext:
    organisation_id: int | UUID
    timezone: str
    revision: int


def resolve_business_context(conn, *, actor_id: int | AuthenticatedPrincipal) -> BusinessTimeContext:
    principal = actor_id if isinstance(actor_id, AuthenticatedPrincipal) else None
    user_id = principal.user_id if principal else actor_id
    if not execute(conn,'SELECT id FROM users WHERE id=? AND archived_at IS NULL',(user_id,)).fetchone():
        raise HTTPException(403, 'Active account required')
    if is_postgres(conn):
        organization_id = principal.organization_id if principal else execute(
            conn, "SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid AS id"
        ).fetchone()["id"]
        if organization_id is None:
            raise HTTPException(403, 'Active company context required')
        row = execute(conn,
            'SELECT business_timezone,revision FROM organization_settings WHERE organization_id=?',
            (organization_id,),
        ).fetchone()
        timezone = row["business_timezone"] if row else None
        revision = row["revision"] if row else None
    else:
        organization_id = 1
        row=execute(conn,'SELECT business_timezone,revision FROM organisation_settings WHERE id=1').fetchone()
        timezone = row[0] if row else None
        revision = row[1] if row else None
    if not isinstance(revision,int) or revision<1:
        raise ValueError('Invalid organisation timezone configuration.')
    validate_zone(timezone)
    return BusinessTimeContext(organization_id,timezone,revision)


def resolve_display_zone(user_zone: str | None, context: BusinessTimeContext) -> str:
    zone=context.timezone if user_zone is None else user_zone
    validate_zone(zone)
    return zone
