"""Stock evidence written with the balance transaction, without capturing credentials."""
import json
from fastapi import HTTPException
from backend.database_sql import execute, is_postgres
from backend.services.principals import AuthenticatedPrincipal
from backend.services.activity import record_activity

STOCK_AUDIT_ACTIONS = frozenset({'add_stock','consume_stock','update_stock','import_stock_balances',
    'transfer_stock','receive_transfer','return_transfer','confirm_stock_count','set_stock_minimum'})
PROTECTED_AUDIT_SQL = '(' + ','.join("'"+name+"'" for name in sorted(STOCK_AUDIT_ACTIONS)) + ')'


def balance_snapshot(conn, store_id, part_id, work_order_id):
    metadata = execute(conn, '''SELECT s.name AS store_name,p.part_number,p.description
        FROM stores s CROSS JOIN parts p WHERE s.id=? AND p.id=?''',(store_id,part_id)).fetchone()
    if not metadata:
        raise HTTPException(400,'Store or part does not exist')
    identity = 'work_order_id IS NOT DISTINCT FROM ?' if is_postgres(conn) else 'CAST(work_order_id AS NUMERIC) IS CAST(? AS NUMERIC)'
    row = execute(conn, f'''SELECT id,quantity,min_threshold FROM inventory WHERE store_id=? AND part_id=?
        AND {identity}''',(store_id,part_id,work_order_id)).fetchone()
    work_order = execute(conn,'SELECT id,work_order_number FROM work_orders WHERE id=CAST(? AS NUMERIC)',(work_order_id,)).fetchone() if work_order_id is not None else None
    return {'inventory_id':row['id'] if row else None,'store_id':store_id,'part_id':part_id,
        'store_name':metadata['store_name'],'part_number':metadata['part_number'],'description':metadata['description'],
        'work_order_id':work_order['id'] if work_order else None,'work_order':work_order['work_order_number'] if work_order else None,
        'quantity':row['quantity'] if row else 0,'min_threshold':row['min_threshold'] if row else 0}


def record_stock_audit(conn, user_id, action, changes, movement_ids=(), *, resource_id=None,
                       resource_type='inventory', request=None, extra=None):
    in_transaction = (
        conn.info.transaction_status.name != "IDLE"
        if is_postgres(conn)
        else conn.in_transaction
    )
    if not in_transaction:
        raise RuntimeError('Stock audit requires an active write transaction')
    actor_id = user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
    actor = execute(conn,'SELECT name FROM users WHERE id=? AND archived_at IS NULL',(actor_id,)).fetchone()
    if not actor:
        raise HTTPException(403,'Active user required for stock changes')
    details = dict(extra or {})
    details.update(schema_version=1,balance_changes=changes,movement_ids=list(movement_ids))
    record_activity(
        conn,
        user_id=user_id,
        username=actor['name'],
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        status='success',
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get('user-agent','')[:200] if request else None,
    )


def change_after(conn, before):
    return {'before':before,'after':balance_snapshot(conn,before['store_id'],before['part_id'],before['work_order_id'])}
