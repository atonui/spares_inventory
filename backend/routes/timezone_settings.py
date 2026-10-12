"""Authenticated timezone preferences, with revision-protected business changes."""
from contextlib import closing
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.timezone_settings import BusinessTimezoneUpdate
from backend.services.timezone_policy import resolve_business_context, resolve_display_zone
from backend.services.activity import record_activity
from backend.temporal import serialize_instant, utc_now


def create_timezone_settings_router(*, get_connection, authenticated_writer, current_user, csrf_dependency):
    router=APIRouter()

    def response(conn, user_id, context):
        preference=conn.execute('SELECT display_timezone FROM users WHERE id=?',(user_id,)).fetchone()[0]
        return {'organisation_id':context.organisation_id,'business_timezone':context.timezone,
                'display_timezone':resolve_display_zone(preference,context),'revision':context.revision}

    @router.get('/api/timezone-context')
    async def timezone_context(user_id: int=Depends(current_user)):
        with closing(get_connection()) as conn:
            conn.execute('BEGIN')
            context=resolve_business_context(conn,actor_id=user_id)
            return response(conn,user_id,context)

    @router.put('/api/organisation/timezone')
    async def update_timezone(body: BusinessTimezoneUpdate, request: Request,
                              user_id: int=Depends(current_user), csrf_valid: bool=Depends(csrf_dependency)):
        with authenticated_writer(user_id,request.cookies.get('session_token')) as conn:
            context=resolve_business_context(conn,actor_id=user_id)
            actor=conn.execute('SELECT role,name FROM users WHERE id=?',(user_id,)).fetchone()
            if actor['role'] not in ('admin','superadmin'):
                raise HTTPException(403,'Admin access required')
            if body.expected_revision!=context.revision:
                raise HTTPException(409,'Timezone settings changed. Refresh before saving.')
            conn.execute('''UPDATE organisation_settings SET business_timezone=?,revision=revision+1,
                            updated_at=?,updated_by=? WHERE id=1 AND revision=?''',
                         (body.timezone,serialize_instant(utc_now()),user_id,body.expected_revision))
            record_activity(conn,user_id=user_id,username=actor['name'],action='update_business_timezone',
                            resource_type='organisation',resource_id=1,
                            details={'old_timezone':context.timezone,'new_timezone':body.timezone,
                                     'old_revision':context.revision,'new_revision':context.revision+1},
                            ip_address=request.client.host if request.client else None,
                            user_agent=request.headers.get('user-agent'))
            updated=resolve_business_context(conn,actor_id=user_id)
            return response(conn,user_id,updated)

    return router
