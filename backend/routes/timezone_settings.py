"""Authenticated timezone preferences, with revision-protected business changes."""
from backend.services.session_credentials import get_request_credential
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.timezone_settings import BusinessTimezoneUpdate
from backend.services.timezone_policy import resolve_business_context, resolve_display_zone
from backend.services.activity import record_activity
from backend.services.principals import AuthenticatedPrincipal
from backend.services.tenant_context import authenticated_database_transaction
from backend.database_sql import execute, is_postgres
from backend.temporal import serialize_instant, utc_now


def create_timezone_settings_router(*, get_connection, authenticated_writer, current_user, csrf_dependency):
    router=APIRouter()

    def response(conn, user_id, context):
        actor_id = user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
        preference=execute(conn,'SELECT display_timezone FROM users WHERE id=?',(actor_id,)).fetchone()
        preference = preference["display_timezone"] if isinstance(preference, dict) else preference[0]
        return {'organisation_id':context.organisation_id,'business_timezone':context.timezone,
                'display_timezone':resolve_display_zone(preference,context),'revision':context.revision}

    @router.get('/api/timezone-context')
    async def timezone_context(user_id: int=Depends(current_user), request: Request = None):
        with authenticated_database_transaction(
            get_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            context=resolve_business_context(conn,actor_id=principal)
            return response(conn,user_id,context)

    @router.put('/api/organisation/timezone')
    async def update_timezone(body: BusinessTimezoneUpdate, request: Request,
                              user_id: int=Depends(current_user), csrf_valid: bool=Depends(csrf_dependency)):
        with authenticated_writer(user_id,get_request_credential(request).value) as conn:
            context=resolve_business_context(conn,actor_id=user_id)
            actor_id = user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
            actor=execute(conn,'SELECT name FROM users WHERE id=?',(actor_id,)).fetchone()
            if isinstance(user_id, AuthenticatedPrincipal):
                allowed = user_id.organization_id is not None and user_id.company_role in {'owner', 'admin'}
            else:
                role = execute(conn,'SELECT role FROM users WHERE id=?',(actor_id,)).fetchone()
                allowed = bool(role and role['role'] in ('admin','superadmin'))
            if not allowed:
                raise HTTPException(403,'Admin access required')
            if body.expected_revision!=context.revision:
                raise HTTPException(409,'Timezone settings changed. Refresh before saving.')
            if is_postgres(conn):
                changed = execute(conn,'''UPDATE organization_settings SET business_timezone=?,revision=revision+1,
                            updated_at=?,updated_by=? WHERE organization_id=? AND revision=?''',
                         (body.timezone,serialize_instant(utc_now()),actor_id,context.organisation_id,body.expected_revision)).rowcount
            else:
                changed = execute(conn,'''UPDATE organisation_settings SET business_timezone=?,revision=revision+1,
                            updated_at=?,updated_by=? WHERE id=1 AND revision=?''',
                         (body.timezone,serialize_instant(utc_now()),actor_id,body.expected_revision)).rowcount
            if changed != 1:
                raise HTTPException(409,'Timezone settings changed. Refresh before saving.')
            record_activity(conn,user_id=user_id,username=actor['name'],action='update_business_timezone',
                            resource_type='organisation',resource_id=1,
                            details={'old_timezone':context.timezone,'new_timezone':body.timezone,
                                     'old_revision':context.revision,'new_revision':context.revision+1},
                            ip_address=request.client.host if request.client else None,
                            user_agent=request.headers.get('user-agent'))
            updated=resolve_business_context(conn,actor_id=user_id)
            return response(conn,user_id,updated)

    return router
