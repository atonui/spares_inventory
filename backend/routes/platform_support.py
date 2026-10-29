"""Fixed, audited support reads scoped to a server-bound organization."""

from contextlib import contextmanager
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from backend.database_sql import is_postgres
from backend.services.platform_audit import record_platform_audit_event
from backend.services.platform_support import authenticated_support_transaction, create_support_session
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.session_credentials import get_request_credential, hash_session_credential
from backend.temporal import serialize_instant, utc_now


class SupportSessionStart(BaseModel):
    organization_id: UUID
    reason: str = Field(min_length=10, max_length=500)
    current_password: str = Field(min_length=1, max_length=1024, repr=False)

    @field_validator('reason')
    @classmethod
    def validate_reason(cls, value):
        value = value.strip()
        if not 10 <= len(value) <= 500:
            raise ValueError('Reason must be 10–500 characters')
        return value


# Every query is fixed and explicitly selects its response fields. No SELECT *,
# user-selected columns, arbitrary filters, or unfiltered tenant lists.
_LOOKUPS = {
    'accounts': """SELECT u.id AS user_id,u.name,u.email,u.archived_at,
        om.company_role AS role,om.is_active AS membership_active,
        u.failed_login_attempts,u.account_locked_until,u.last_login
        FROM organization_memberships om JOIN users u ON u.id=om.user_id
        WHERE om.organization_id=%s AND lower(u.email)=lower(%s)
        ORDER BY u.id LIMIT 25""",
    'inventory': """SELECT p.part_number,p.description,p.category,
        s.name AS store_name,s.type AS store_type,s.location AS store_location,
        i.quantity,i.min_threshold,i.updated_at,w.work_order_number,w.status AS work_order_status
        FROM parts p LEFT JOIN inventory i ON i.part_id=p.id AND i.organization_id=p.organization_id
        LEFT JOIN stores s ON s.id=i.store_id AND s.organization_id=p.organization_id
        LEFT JOIN work_orders w ON w.id=i.work_order_id AND w.organization_id=p.organization_id
        WHERE p.organization_id=%s AND p.part_number=%s
        ORDER BY p.id,i.id LIMIT 25""",
    'work-orders': """SELECT w.work_order_number,w.status,w.created_at,
        u.name AS assigned_staff_name
        FROM work_orders w LEFT JOIN organization_memberships om
          ON om.user_id=w.assigned_engineer_id AND om.organization_id=w.organization_id
        LEFT JOIN users u ON u.id=om.user_id
        WHERE w.organization_id=%s AND w.work_order_number=%s
        ORDER BY w.id LIMIT 25""",
    'equipment': """SELECT e.equipment_name,e.make,e.model,e.serial_number,e.status,
        e.calibration_cert_number,e.calibration_authority,e.calibration_date,e.next_calibration_date,
        u.name AS assigned_staff_name
        FROM equipment e LEFT JOIN organization_memberships om
          ON om.user_id=e.assigned_user_id AND om.organization_id=e.organization_id
        LEFT JOIN users u ON u.id=om.user_id
        WHERE e.organization_id=%s AND e.serial_number=%s
        ORDER BY e.id LIMIT 25""",
    'equipment-history': """SELECT e.serial_number,h.action,h.calibration_date,h.created_at,
        fu.name AS from_staff_name,tu.name AS to_staff_name,cu.name AS created_by_staff_name
        FROM equipment_history h JOIN equipment e
          ON e.id=h.equipment_id AND e.organization_id=h.organization_id
        LEFT JOIN organization_memberships fm ON fm.user_id=h.from_user_id AND fm.organization_id=h.organization_id
        LEFT JOIN users fu ON fu.id=fm.user_id
        LEFT JOIN organization_memberships tm ON tm.user_id=h.to_user_id AND tm.organization_id=h.organization_id
        LEFT JOIN users tu ON tu.id=tm.user_id
        LEFT JOIN organization_memberships cm ON cm.user_id=h.created_by AND cm.organization_id=h.organization_id
        LEFT JOIN users cu ON cu.id=cm.user_id
        WHERE h.organization_id=%s AND e.serial_number=%s
        ORDER BY h.created_at DESC,h.id DESC LIMIT 25""",
    'movements': """SELECT m.movement_type,p.part_number,m.quantity,
        fs.name AS source_store,ts.name AS destination_store,w.work_order_number,
        m.created_at,t.status AS transfer_status,t.completed_at,
        au.name AS created_by_staff_name,cu.name AS completed_by_staff_name
        FROM movements m JOIN parts p ON p.id=m.part_id AND p.organization_id=m.organization_id
        LEFT JOIN stores fs ON fs.id=m.from_store_id AND fs.organization_id=m.organization_id
        LEFT JOIN stores ts ON ts.id=m.to_store_id AND ts.organization_id=m.organization_id
        LEFT JOIN work_orders w ON w.id=m.work_order_id AND w.organization_id=m.organization_id
        LEFT JOIN stock_transfers t ON t.movement_id=m.id AND t.organization_id=m.organization_id
        LEFT JOIN organization_memberships am ON am.user_id=m.created_by AND am.organization_id=m.organization_id
        LEFT JOIN users au ON au.id=am.user_id
        LEFT JOIN organization_memberships cm ON cm.user_id=t.completed_by AND cm.organization_id=m.organization_id
        LEFT JOIN users cu ON cu.id=cm.user_id
        WHERE m.organization_id=%s AND p.part_number=%s
        ORDER BY m.created_at DESC,m.id DESC LIMIT 25""",
}


def create_platform_support_router(*, get_connection, current_user, csrf_dependency,
                                   password_verify, limiter) -> APIRouter:
    router = APIRouter(prefix='/api/platform/support-sessions', tags=['platform'])

    def require_postgres():
        conn = get_connection()
        try:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail='Platform administration requires PostgreSQL')
        finally:
            conn.close()

    def platform(request, actor, *, readonly=False):
        return authenticated_platform_transaction(
            get_connection, session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, 'user_id', actor), readonly=readonly)

    def auth_session_id(conn, request, principal):
        row = conn.execute(
            """SELECT id FROM sessions WHERE user_id=%s AND session_token_hash=%s
               AND is_active=TRUE AND expires_at::timestamptz>%s FOR UPDATE""",
            (principal.user_id, hash_session_credential(get_request_credential(request).value), serialize_instant(utc_now())),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail='Invalid or expired session')
        return row['id']

    def session_payload(conn, support):
        org = conn.execute('SELECT id,name,slug,is_active FROM organizations WHERE id=%s',
                           (support['organization_id'],)).fetchone()
        if org is None:
            raise HTTPException(status_code=404, detail='Support session unavailable')
        organization = dict(org)
        organization['id'] = str(organization['id'])
        return {'support_session_id':str(support['id']), 'organization':organization,
                'reason':support['reason'], 'expires_at':support['expires_at']}

    def denied(request, actor, *, request_id, resource, operation,
               support_session_id=None, organization_id=None):
        # Reauthenticate independently after the failed request has rolled back.
        # Do not discover another actor's support scope or audit anonymous callers.
        with platform(request, actor) as (conn, principal):
            if support_session_id is not None:
                row = conn.execute('SELECT organization_id FROM platform_support_sessions WHERE id=%s AND actor_user_id=%s',
                                   (support_session_id, principal.user_id)).fetchone()
                organization_id = row['organization_id'] if row else None
            elif organization_id is not None:
                row = conn.execute('SELECT id FROM organizations WHERE id=%s', (organization_id,)).fetchone()
                organization_id = row['id'] if row else None
            if organization_id is not None:
                details = {'request_id':request_id,'resource':resource,'operation':operation}
                if support_session_id is not None:
                    details['support_session_id'] = str(support_session_id)
                record_platform_audit_event(conn, principal.user_id, 'support_access_denied', 'denied', organization_id, details)

    @contextmanager
    def audited_scope(request, actor, support_session_id, resource, request_id):
        try:
            with authenticated_support_transaction(
                get_connection, session_token=get_request_credential(request).value,
                support_session_id=support_session_id, expected_user_id=getattr(actor,'user_id',actor),
            ) as scope:
                yield scope
        except HTTPException:
            try:
                denied(request, actor, request_id=request_id, resource=resource, operation='lookup',
                       support_session_id=support_session_id)
            except HTTPException:
                pass  # The caller no longer has platform authority; preserve generic denial.
            raise

    @router.post('')
    @limiter.limit('5/minute')
    async def start_session(body: SupportSessionStart, request: Request,
                            actor=Depends(current_user), csrf_valid=Depends(csrf_dependency)):
        require_postgres()
        request_id = str(uuid4())
        try:
            with platform(request, actor) as (conn, principal):
                auth_id = auth_session_id(conn, request, principal)
                user = conn.execute('SELECT password_hash FROM users WHERE id=%s', (principal.user_id,)).fetchone()
                if not user or not password_verify(body.current_password, user['password_hash']):
                    raise HTTPException(status_code=403, detail='Support access denied')
                support = create_support_session(conn, actor_user_id=principal.user_id, auth_session_id=auth_id,
                    organization_id=body.organization_id, reason=body.reason, now=utc_now())
                record_platform_audit_event(conn, principal.user_id, 'support_session_started', 'success',
                    support['organization_id'], {'support_session_id':str(support['id']), 'reason':support['reason'],
                                                'request_id':request_id,'operation':'start'})
                return session_payload(conn, support)
        except HTTPException:
            try:
                denied(request, actor, request_id=request_id,resource='session',operation='start',organization_id=body.organization_id)
            except HTTPException:
                pass
            raise

    @router.get('/current')
    async def current_session(request: Request, actor=Depends(current_user)):
        require_postgres()
        with platform(request, actor, readonly=True) as (conn, principal):
            # No row locks in this read-only metadata transaction.
            row = conn.execute(
                """SELECT s.* FROM platform_support_sessions s JOIN sessions a ON a.id=s.auth_session_id
                   JOIN organizations o ON o.id=s.organization_id
                   WHERE s.actor_user_id=%s AND a.session_token_hash=%s AND a.is_active=TRUE
                     AND a.expires_at::timestamptz>%s AND s.ended_at IS NULL AND s.expires_at>%s
                   ORDER BY s.created_at DESC LIMIT 1""",
                (principal.user_id,hash_session_credential(get_request_credential(request).value),
                 serialize_instant(utc_now()),serialize_instant(utc_now())),
            ).fetchone()
            return session_payload(conn,row) if row else None

    @router.delete('/{support_session_id}')
    async def end_session(support_session_id: UUID, request: Request,
                          actor=Depends(current_user), csrf_valid=Depends(csrf_dependency)):
        require_postgres()
        request_id = str(uuid4())
        try:
            with platform(request, actor) as (conn, principal):
                auth_id = auth_session_id(conn,request,principal)
                support = conn.execute(
                    """UPDATE platform_support_sessions SET ended_at=%s
                       WHERE id=%s AND actor_user_id=%s AND auth_session_id=%s AND ended_at IS NULL
                       RETURNING organization_id""",
                    (serialize_instant(utc_now()),support_session_id,principal.user_id,auth_id),
                ).fetchone()
                if support is None:
                    raise HTTPException(status_code=404, detail='Support session unavailable')
                record_platform_audit_event(conn,principal.user_id,'support_session_ended','success',support['organization_id'],
                    {'support_session_id':str(support_session_id),'request_id':request_id,'operation':'end'})
                return {'success':True}
        except HTTPException:
            try:
                denied(request,actor,request_id=request_id,resource='session',operation='end',support_session_id=support_session_id)
            except HTTPException:
                pass
            raise

    def lookup(request, actor, support_session_id, resource, value):
        require_postgres()
        request_id = str(uuid4())
        with audited_scope(request,actor,support_session_id,resource,request_id) as (conn,principal,support):
            if not isinstance(value,str) or not 1 <= len(value.strip()) <= (254 if resource == 'accounts' else 100):
                raise HTTPException(status_code=422,detail='A bounded lookup value is required')
            rows = conn.execute(_LOOKUPS[resource],(support['organization_id'],value.strip())).fetchall()
            record_platform_audit_event(conn,principal.user_id,'support_data_read','success',support['organization_id'],
                {'support_session_id':str(support['id']),'resource':resource,'operation':'lookup','request_id':request_id})
            return {'rows':[dict(row) for row in rows]}

    @router.get('/{support_session_id}/accounts')
    async def accounts(support_session_id: UUID, email: str, request: Request, actor=Depends(current_user)):
        return lookup(request,actor,support_session_id,'accounts',email)

    @router.get('/{support_session_id}/inventory')
    async def inventory(support_session_id: UUID, query: str, request: Request, actor=Depends(current_user)):
        return lookup(request,actor,support_session_id,'inventory',query)

    @router.get('/{support_session_id}/work-orders')
    async def work_orders(support_session_id: UUID, query: str, request: Request, actor=Depends(current_user)):
        return lookup(request,actor,support_session_id,'work-orders',query)

    @router.get('/{support_session_id}/equipment')
    async def equipment(support_session_id: UUID, query: str, request: Request, actor=Depends(current_user)):
        return lookup(request,actor,support_session_id,'equipment',query)

    @router.get('/{support_session_id}/equipment-history')
    async def equipment_history(support_session_id: UUID, query: str, request: Request, actor=Depends(current_user)):
        return lookup(request,actor,support_session_id,'equipment-history',query)

    @router.get('/{support_session_id}/movements')
    async def movements(support_session_id: UUID, query: str, request: Request, actor=Depends(current_user)):
        return lookup(request,actor,support_session_id,'movements',query)

    return router
