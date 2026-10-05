"""Minimum settings and a read-only, globally allocated replenishment plan."""
import json
from contextlib import closing
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from stock_audit import balance_snapshot, change_after, record_stock_audit

class MinimumRequest(BaseModel):
    store_id: int = Field(gt=0, strict=True)
    part_id: int = Field(gt=0, strict=True)
    min_threshold: int = Field(ge=0, le=2147483647, strict=True)
    expected_minimum: int = Field(ge=0, le=2147483647, strict=True)

def build_plan(conn, user_id):
    actor = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
    def permitted(row):
        return bool(actor and (actor['role'] in ('admin','superadmin') or row['store_owner']==user_id or row['store_type']=='central'))
    stock = [dict(r) for r in conn.execute('''SELECT i.id AS inventory_id,i.store_id,i.part_id,i.quantity,i.min_threshold,
        s.name AS store_name,s.type AS store_type,s.assigned_user_id AS store_owner,p.part_number,p.description
        FROM inventory i JOIN stores s ON s.id=i.store_id JOIN parts p ON p.id=i.part_id
        WHERE i.work_order_id IS NULL AND s.archived_at IS NULL AND p.archived_at IS NULL
        ORDER BY s.name,s.id,p.part_number,i.id''')]
    incoming = {(r['store_id'],r['part_id']):r['quantity'] for r in conn.execute('''SELECT m.to_store_id AS store_id,m.part_id,SUM(m.quantity) AS quantity
        FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
        WHERE t.status='in_transit' AND m.work_order_id IS NULL GROUP BY m.to_store_id,m.part_id''')}
    donors = sorted(stock, key=lambda r:(r['store_type']!='central',r['store_name'],r['store_id'],r['inventory_id']))
    capacity = {r['inventory_id']:max(r['quantity']-r['min_threshold'],0) for r in donors}
    rows = []
    for target in stock:
        shortage = max(target['min_threshold']-target['quantity'],0)
        if not shortage:
            continue
        row = dict(target)
        row['can_set_minimum'] = permitted(target)
        row['shortage'] = shortage
        row['incoming_quantity'] = incoming.get((target['store_id'],target['part_id']),0)
        needed = max(shortage-row['incoming_quantity'],0)
        row['suggestions'] = []
        for donor in donors:
            if donor['part_id']!=target['part_id'] or donor['store_id']==target['store_id']:
                continue
            amount = min(needed,capacity[donor['inventory_id']])
            if amount:
                row['suggestions'].append({'inventory_id':donor['inventory_id'],'store_id':donor['store_id'],
                    'store_name':donor['store_name'],'quantity':amount,'can_dispatch':permitted(donor)})
                capacity[donor['inventory_id']] -= amount
                needed -= amount
            if not needed:
                break
        row['internal_quantity'] = sum(s['quantity'] for s in row['suggestions'])
        row['purchase_quantity'] = needed
        rows.append(row)
    return {'rows':rows}

def require_planned_dispatch(conn, user_id, inventory_id, to_store_id, quantity):
    plan = build_plan(conn,user_id)
    allowed = next((s['quantity'] for r in plan['rows'] if r['store_id']==to_store_id
                    for s in r['suggestions'] if s['inventory_id']==inventory_id),0)
    if quantity > allowed:
        raise HTTPException(409,'Replenishment plan changed; refresh and review the suggested transfer')

def register_replenishment_routes(app, *, get_connection, write_transaction, require_active, require_access, current_user, verify_csrf):
    @app.get('/api/inventory/replenishment')
    async def replenishment(user_id: int = Depends(current_user)):
        with closing(get_connection()) as conn:
            conn.execute('BEGIN')
            require_active(conn,'users',user_id)
            return build_plan(conn,user_id)

    @app.put('/api/inventory/minimum')
    async def minimum(data: MinimumRequest, user_id: int = Depends(current_user), csrf_valid: bool = Depends(verify_csrf), request: Request = None):
        with write_transaction(user_id, request.cookies.get('session_token')) as conn:
            require_active(conn,'users',user_id)
            require_active(conn,'stores',data.store_id)
            require_active(conn,'parts',data.part_id)
            store = conn.execute('SELECT type,assigned_user_id FROM stores WHERE id=?',(data.store_id,)).fetchone()
            require_access(conn,user_id,store['type'],store['assigned_user_id'])
            before_balance = balance_snapshot(conn,data.store_id,data.part_id,None)
            item = conn.execute('SELECT id,min_threshold FROM inventory WHERE store_id=? AND part_id=? AND work_order_id IS NULL',(data.store_id,data.part_id)).fetchone()
            before = item['min_threshold'] if item else 0
            if before != data.expected_minimum:
                raise HTTPException(409,'Minimum stock changed; reload before saving')
            if item:
                identifier = item['id']
                conn.execute('UPDATE inventory SET min_threshold=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(data.min_threshold,identifier))
            elif data.min_threshold:
                identifier = conn.execute('INSERT INTO inventory(store_id,part_id,quantity,min_threshold) VALUES(?,?,0,?)',(data.store_id,data.part_id,data.min_threshold)).lastrowid
            else:
                identifier = None
            # A later physical return must honor minimum edits made during transit.
            conn.execute('''UPDATE stock_transfers SET source_min_threshold=? WHERE status='in_transit'
                AND movement_id IN (SELECT id FROM movements WHERE from_store_id=? AND part_id=? AND work_order_id IS NULL)''',
                (data.min_threshold,data.store_id,data.part_id))
            record_stock_audit(conn,user_id,'set_stock_minimum',[change_after(conn,before_balance)],
                resource_id=identifier,request=request,extra={'store_id':data.store_id,'part_id':data.part_id,'before_minimum':before,'after_minimum':data.min_threshold})
            return {'success':True,'id':identifier,'message':'Minimum stock saved'}
