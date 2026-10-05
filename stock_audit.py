"""Stock evidence written with the balance transaction, without capturing credentials."""
import json
from fastapi import HTTPException

STOCK_AUDIT_ACTIONS = frozenset({'add_stock','consume_stock','update_stock','import_stock_balances',
    'transfer_stock','receive_transfer','return_transfer','confirm_stock_count','set_stock_minimum'})
PROTECTED_AUDIT_SQL = '(' + ','.join("'"+name+"'" for name in sorted(STOCK_AUDIT_ACTIONS)) + ')'


def balance_snapshot(conn, store_id, part_id, work_order_id):
    metadata = conn.execute('''SELECT s.name AS store_name,p.part_number,p.description
        FROM stores s CROSS JOIN parts p WHERE s.id=? AND p.id=?''',(store_id,part_id)).fetchone()
    if not metadata:
        raise HTTPException(400,'Store or part does not exist')
    row = conn.execute('''SELECT id,quantity,min_threshold FROM inventory WHERE store_id=? AND part_id=?
        AND CAST(work_order_id AS NUMERIC) IS CAST(? AS NUMERIC)''',(store_id,part_id,work_order_id)).fetchone()
    work_order = conn.execute('SELECT id,work_order_number FROM work_orders WHERE id=CAST(? AS NUMERIC)',(work_order_id,)).fetchone() if work_order_id is not None else None
    return {'inventory_id':row['id'] if row else None,'store_id':store_id,'part_id':part_id,
        'store_name':metadata['store_name'],'part_number':metadata['part_number'],'description':metadata['description'],
        'work_order_id':work_order['id'] if work_order else None,'work_order':work_order['work_order_number'] if work_order else None,
        'quantity':row['quantity'] if row else 0,'min_threshold':row['min_threshold'] if row else 0}


def record_stock_audit(conn, user_id, action, changes, movement_ids=(), *, resource_id=None,
                       resource_type='inventory', request=None, extra=None):
    if not conn.in_transaction:
        raise RuntimeError('Stock audit requires an active write transaction')
    actor = conn.execute('SELECT name FROM users WHERE id=? AND archived_at IS NULL',(user_id,)).fetchone()
    if not actor:
        raise HTTPException(403,'Active user required for stock changes')
    details = dict(extra or {})
    details.update(schema_version=1,balance_changes=changes,movement_ids=list(movement_ids))
    conn.execute('''INSERT INTO activity_logs(user_id,username,action,resource_type,resource_id,details,status,ip_address,user_agent)
        VALUES(?,?,?,?,?,?,'success',?,?)''',(user_id,actor['name'],action,resource_type,resource_id,json.dumps(details),
        request.client.host if request and request.client else None,request.headers.get('user-agent','')[:200] if request else None))


def change_after(conn, before):
    return {'before':before,'after':balance_snapshot(conn,before['store_id'],before['part_id'],before['work_order_id'])}
