"""Single-organisation policy provider; no tenant-isolation claims."""
from dataclasses import dataclass
from fastapi import HTTPException
from backend.temporal import validate_zone


@dataclass(frozen=True)
class BusinessTimeContext:
    organisation_id: int
    timezone: str
    revision: int


def resolve_business_context(conn, *, actor_id: int) -> BusinessTimeContext:
    if not conn.execute('SELECT id FROM users WHERE id=? AND archived_at IS NULL',(actor_id,)).fetchone():
        raise HTTPException(403, 'Active account required')
    row=conn.execute('SELECT business_timezone,revision FROM organisation_settings WHERE id=1').fetchone()
    if not row or not isinstance(row[1],int) or row[1]<1:
        raise ValueError('Invalid organisation timezone configuration.')
    validate_zone(row[0])
    return BusinessTimeContext(1,row[0],row[1])


def resolve_display_zone(user_zone: str | None, context: BusinessTimeContext) -> str:
    zone=context.timezone if user_zone is None else user_zone
    validate_zone(zone)
    return zone
