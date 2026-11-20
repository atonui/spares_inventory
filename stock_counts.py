"""Physical counting over existing inventory rows; no reservation redistribution."""
from stock_audit import balance_snapshot, change_after, record_stock_audit
from backend.database_sql import execute, is_postgres
from backend.services.principals import AuthenticatedPrincipal
from backend.services.session_credentials import get_request_credential
from backend.services.tenant_context import authenticated_database_transaction
from backend.temporal import serialize_instant, utc_now
import hashlib
import json

from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field

COUNT_TOKEN_MAX_LENGTH = 8_000_000


class CountRow(BaseModel):
    inventory_id: int = Field(gt=0, strict=True)
    counted_quantity: int = Field(ge=0, le=2147483647, strict=True)
    reason: str = Field(default='', max_length=1000)


class CountPreviewRequest(BaseModel):
    sheet_token: str = Field(max_length=COUNT_TOKEN_MAX_LENGTH)
    rows: list[CountRow] = Field(min_length=1, max_length=1000)


class CountConfirmRequest(BaseModel):
    preview_token: str = Field(max_length=COUNT_TOKEN_MAX_LENGTH)
    confirmed: bool = Field(strict=True)


def actor_id(user):
    """Plain user ID for tokens, audit and created_by, from a principal or a legacy ID."""
    return user.user_id if isinstance(user, AuthenticatedPrincipal) else user


def store_snapshot(conn, store_id):
    """Detect row changes and movements, including a balance changed then restored."""
    rows = execute(conn, '''
        SELECT i.id AS inventory_id,i.part_id,i.work_order_id,i.quantity,
               i.min_threshold,i.updated_at,p.part_number,p.description,
               wo.work_order_number AS work_order
        FROM inventory i JOIN parts p ON p.id=i.part_id
        LEFT JOIN work_orders wo ON wo.id=i.work_order_id
        WHERE i.store_id=? AND p.archived_at IS NULL
        ORDER BY p.part_number,i.id
    ''', (store_id,)).fetchall()
    movements = tuple(execute(conn, 'SELECT COALESCE(MAX(id),0) AS last_id,COUNT(*) AS total FROM movements WHERE from_store_id=? OR to_store_id=?', (store_id,store_id)).fetchone().values()) \
        if is_postgres(conn) else tuple(execute(conn, 'SELECT COALESCE(MAX(id),0),COUNT(*) FROM movements WHERE from_store_id=? OR to_store_id=?', (store_id,store_id)).fetchone())
    counts_sql = "SELECT COALESCE(MAX(id),0) AS last_id,COUNT(*) AS total FROM activity_logs WHERE action='confirm_stock_count' AND resource_type='stock_count' AND resource_id=?"
    counts = tuple(execute(conn, counts_sql, (store_id,)).fetchone().values()) \
        if is_postgres(conn) else tuple(execute(conn, counts_sql, (store_id,)).fetchone())
    payload = {'rows':[dict(row) for row in rows], 'movements':movements, 'counts':counts}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return payload['rows'],digest


def register_stock_count_routes(app, *, get_connection, write_transaction,
                                require_active, require_access, current_user,
                                verify_csrf, secret):
    signer = URLSafeTimedSerializer(secret, salt='inventory-physical-count-v1')

    def read_token(token, stage, user_id):
        try:
            data = signer.loads(token, max_age=1800)
        except (BadSignature, SignatureExpired):
            raise HTTPException(400, 'Count preview is invalid or expired; start a fresh count')
        if data.get('stage') != stage:
            raise HTTPException(400, 'Wrong count token; start a fresh count')
        if data.get('user_id') != user_id:
            raise HTTPException(403, 'This count belongs to another user')
        return data

    def permitted_store(conn, store_id, user):
        require_active(conn,'users',actor_id(user))
        require_active(conn,'stores',store_id)
        store = execute(conn, 'SELECT name,type,assigned_user_id,{} FROM stores WHERE id=?'.format(
            'organization_id' if is_postgres(conn) else 'NULL AS organization_id'), (store_id,)).fetchone()
        require_access(conn,user,store['type'],store['assigned_user_id'],
                       store_organization_id=store['organization_id'])
        return store

    def read_transaction(user, request):
        # Tenant RLS on PostgreSQL; the validated SQLite path otherwise.
        return authenticated_database_transaction(
            get_connection, principal_or_user=user,
            session_token=get_request_credential(request).value, readonly=True)

    def fresh_snapshot(conn, data):
        rows,digest = store_snapshot(conn,data['store_id'])
        if digest != data['snapshot']:
            raise HTTPException(409, 'Stock changed during counting; start a fresh count and recount affected stock')
        return rows

    @app.get('/api/inventory/count-sheet/{store_id}')
    async def count_sheet(store_id: int, request: Request, user_id: int = Depends(current_user)):
        with read_transaction(user_id, request) as (conn, _principal):
            store = permitted_store(conn,store_id,user_id)
            rows,digest = store_snapshot(conn,store_id)
            token = signer.dumps({'stage':'sheet','user_id':actor_id(user_id),'store_id':store_id,'snapshot':digest})
            return {'store_id':store_id,'store_name':store['name'],'sheet_token':token,'rows':rows}

    @app.post('/api/inventory/count-preview')
    async def count_preview(body: CountPreviewRequest, request: Request,
                            user_id: int = Depends(current_user), csrf_valid: bool = Depends(verify_csrf)):
        data = read_token(body.sheet_token,'sheet',actor_id(user_id))
        with read_transaction(user_id, request) as (conn, _principal):
            store = permitted_store(conn,data['store_id'],user_id)
            inventory = {row['inventory_id']:row for row in fresh_snapshot(conn,data)}
            selected,seen = [],set()
            for entry in body.rows:
                if entry.inventory_id in seen:
                    raise HTTPException(400, 'Each inventory allocation can be counted only once')
                seen.add(entry.inventory_id)
                row = inventory.get(entry.inventory_id)
                if not row:
                    raise HTTPException(400, 'Count row does not belong to this active store')
                difference = entry.counted_quantity-row['quantity']
                reason = entry.reason.strip()
                if difference and not reason:
                    raise HTTPException(400, 'A reason is required for every stock correction')
                selected.append({'inventory_id':entry.inventory_id,'part_id':row['part_id'],
                                 'part_number':row['part_number'],'description':row['description'],
                                 'work_order_id':row['work_order_id'],'work_order':row['work_order'],
                                 'before_quantity':row['quantity'],'counted_quantity':entry.counted_quantity,
                                 'difference':difference,'reason':reason})
            token = signer.dumps({**data,'stage':'preview','rows':selected})
            if len(token) > COUNT_TOKEN_MAX_LENGTH:
                raise HTTPException(400, 'Count preview is too large; count fewer rows in this batch')
            return {'store_name':store['name'],'rows':selected,'preview_token':token}

    @app.post('/api/inventory/count-confirm')
    async def count_confirm(body: CountConfirmRequest, request: Request,
                            user_id: int = Depends(current_user), csrf_valid: bool = Depends(verify_csrf)):
        if not body.confirmed:
            raise HTTPException(400, 'Confirm that these are the physical counts before saving')
        data = read_token(body.preview_token,'preview',actor_id(user_id))
        with write_transaction(user_id, get_request_credential(request).value) as conn:
            store = permitted_store(conn,data['store_id'],user_id)
            fresh_snapshot(conn,data)
            changed = 0
            audit_changes, movement_ids = [], []
            for row in data['rows']:
                before = balance_snapshot(conn,data['store_id'],row['part_id'],row['work_order_id'])
                if not row['difference']:
                    audit_changes.append(change_after(conn,before))
                    continue
                changed += 1
                execute(conn, "UPDATE inventory SET quantity=?,updated_at=? WHERE id=?",
                        (row['counted_quantity'],serialize_instant(utc_now()),row['inventory_id']))
                values = (data['store_id'],row['part_id'],abs(row['difference']),
                          'add' if row['difference']>0 else 'remove',row['work_order_id'],actor_id(user_id),
                          f"Physical stock count: {row['before_quantity']} → {row['counted_quantity']}. {row['reason']}")
                if is_postgres(conn):
                    movement = execute(conn, '''INSERT INTO movements(organization_id,to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes)
                        VALUES(?,?,?,?,?,?,?,?) RETURNING id''', (store['organization_id'], *values)).fetchone()['id']
                else:
                    movement = execute(conn, '''INSERT INTO movements(to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes)
                        VALUES(?,?,?,?,?,?,?) RETURNING id''', values).fetchone()[0]
                movement_ids.append(movement)
                audit_changes.append(change_after(conn,before))
            # Count evidence must commit with every balance/movement, including unchanged counts.
            record_stock_audit(conn,user_id,'confirm_stock_count',audit_changes,movement_ids,
                resource_id=data['store_id'],resource_type='stock_count',request=request,
                extra={'store_name':store['name'],'rows':data['rows']})
            return {'success':True,'changed':changed,'unchanged':len(data['rows'])-changed}
