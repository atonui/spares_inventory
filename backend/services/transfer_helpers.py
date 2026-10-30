"""Transfer permissions, pending-record guards, and atomic completion."""

from fastapi import HTTPException
from backend.database_sql import execute, is_postgres
from .principals import AuthenticatedPrincipal
from backend.temporal import serialize_instant, utc_now


def require_no_pending_transfer(conn, kind, identifier):
    predicates={'part':'m.part_id=?','store':'(m.from_store_id=? OR m.to_store_id=?)',
                'user':'(m.created_by=? OR s1.assigned_user_id=? OR s2.assigned_user_id=?)'}
    values=(identifier,)*(1 if kind=='part' else 2 if kind=='store' else 3)
    row=execute(conn,"SELECT 1 FROM stock_transfers t JOIN movements m ON m.id=t.movement_id JOIN stores s1 ON s1.id=m.from_store_id JOIN stores s2 ON s2.id=m.to_store_id WHERE t.status='in_transit' AND "+predicates[kind]+" LIMIT 1",values).fetchone()
    if row:
        raise HTTPException(status_code=400,detail='Cannot delete a record used by an in-transit transfer. Complete the receipt or physical return first')


def transfer_permissions(actor, row, user_id):
    if isinstance(actor, AuthenticatedPrincipal):
        admin = actor.organization_id is not None and actor.company_role in ('owner', 'admin')
    else:
        admin = actor and actor['role'] in ('admin', 'superadmin')
    receive=bool(admin or row['dest_owner']==user_id or (row['dest_owner'] is None and row['dest_type']=='central'))
    returned=bool(admin or row['created_by']==user_id or row['source_owner']==user_id)
    return receive,returned




def complete_transfer(transfer_id, data, user_id, action, request=None, *, session_token,
                      authenticated_write_transaction, permission_checker,
                      balance_snapshot, add_inventory_quantity,
                      record_stock_audit, change_after, notification_enqueuer=None):
    if not data.confirmed:
        raise HTTPException(status_code=400,detail='Physical receipt or return must be confirmed')
    with authenticated_write_transaction(user_id, session_token, busy_detail="Stock is busy; no changes saved. Try again") as conn:
        actor_id = user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
        query = """SELECT m.*,t.status,t.source_min_threshold,s1.assigned_user_id AS source_owner,
            s2.assigned_user_id AS dest_owner,s2.type AS dest_type,
            s1.name AS source_store_name,s2.name AS destination_store_name,p.part_number
            FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
            JOIN stores s1 ON s1.id=m.from_store_id JOIN stores s2 ON s2.id=m.to_store_id
            JOIN parts p ON p.id=m.part_id
            WHERE t.movement_id=?"""
        if is_postgres(conn):
            query += " FOR UPDATE OF t"
        row=execute(conn, query, (transfer_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404,detail='Pending transfer not found')
        actor = user_id if isinstance(user_id, AuthenticatedPrincipal) else execute(
            conn, 'SELECT role FROM users WHERE id=?', (actor_id,)
        ).fetchone()
        receive,returned=permission_checker(actor,row,actor_id)
        if not (receive if action=='received' else returned):
            raise HTTPException(status_code=403,detail='Permission denied for this confirmation')
        if row['status']!='in_transit':
            raise HTTPException(status_code=409,detail='Transfer is already completed; stock was not changed')
        store_id=row['to_store_id'] if action=='received' else row['from_store_id']
        before=balance_snapshot(conn,store_id,row['part_id'],row['work_order_id'])
        inventory_id=add_inventory_quantity(conn,store_id,row['part_id'],row['quantity'],row['work_order_id'])
        if action=='returned':
            # Ordinary restocking may have recreated the row with its default 0.
            # Retain any nonzero threshold configured since dispatch.
            execute(conn, 'UPDATE inventory SET min_threshold=? WHERE id=? AND min_threshold=0',
                         (row['source_min_threshold'],inventory_id))
        execute(conn, "UPDATE stock_transfers SET status=?,completed_by=?,completed_at=?,completion_note=? WHERE movement_id=?",
                (action,actor_id,serialize_instant(utc_now()),data.notes,transfer_id))
        if action=='returned':
            values=(store_id,row['part_id'],row['quantity'],row['work_order_id'],actor_id,
                    f'Physical return confirmed for transfer #{transfer_id}')
            if is_postgres(conn):
                movement_id=execute(conn,"""INSERT INTO movements
                    (organization_id,to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes)
                    VALUES((SELECT NULLIF(current_setting('app.organization_id',true),'')::uuid),?,?,?,'return',?,?,?)
                    RETURNING id""",values).fetchone()["id"]
            else:
                movement_id=execute(conn,"""INSERT INTO movements
                    (to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes)
                    VALUES(?,?,?,'return',?,?,?)""",values).lastrowid
        else:
            movement_id=None
        movement_ids=[transfer_id]
        if movement_id is not None: movement_ids.append(movement_id)
        record_stock_audit(conn,user_id,'receive_transfer' if action=='received' else 'return_transfer',[change_after(conn,before)],movement_ids,resource_id=inventory_id,request=request,extra={'transfer_id':transfer_id,'before_status':'in_transit','after_status':action,'notes':data.notes})
        if is_postgres(conn) and notification_enqueuer:
            organization_id = (
                user_id.organization_id if isinstance(user_id, AuthenticatedPrincipal)
                else conn.execute(
                    "SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid AS id"
                ).fetchone()["id"]
            )
            notification_enqueuer(
                conn,
                event_type="transfer_received" if action == "received" else "transfer_returned",
                organization_id=organization_id,
                store_id=row["from_store_id"],
                actor_user_id=actor_id,
                event_id=transfer_id,
                payload={
                    "transfer_id": transfer_id,
                    "source_store_id": row["from_store_id"],
                    "destination_store_id": row["to_store_id"],
                    "source_store_name": row["source_store_name"],
                    "destination_store_name": row["destination_store_name"],
                    "part_number": row["part_number"],
                    "quantity": row["quantity"],
                },
            )
        return {'success':True,'message':'Receipt confirmed; destination stock is available' if action=='received' else 'Physical return confirmed; source stock restored'}

