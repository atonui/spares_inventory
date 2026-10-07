"""Transfer permissions, pending-record guards, and atomic completion."""

from fastapi import HTTPException


def require_no_pending_transfer(conn, kind, identifier):
    predicates={'part':'m.part_id=?','store':'(m.from_store_id=? OR m.to_store_id=?)',
                'user':'(m.created_by=? OR s1.assigned_user_id=? OR s2.assigned_user_id=?)'}
    values=(identifier,)*(1 if kind=='part' else 2 if kind=='store' else 3)
    row=conn.execute("SELECT 1 FROM stock_transfers t JOIN movements m ON m.id=t.movement_id JOIN stores s1 ON s1.id=m.from_store_id JOIN stores s2 ON s2.id=m.to_store_id WHERE t.status='in_transit' AND "+predicates[kind]+" LIMIT 1",values).fetchone()
    if row:
        raise HTTPException(status_code=400,detail='Cannot delete a record used by an in-transit transfer. Complete the receipt or physical return first')


def transfer_permissions(actor, row, user_id):
    admin=actor and actor['role'] in ('admin','superadmin')
    receive=bool(admin or row['dest_owner']==user_id or (row['dest_owner'] is None and row['dest_type']=='central'))
    returned=bool(admin or row['created_by']==user_id or row['source_owner']==user_id)
    return receive,returned




def complete_transfer(transfer_id, data, user_id, action, request=None, *, session_token,
                      authenticated_write_transaction, permission_checker,
                      balance_snapshot, add_inventory_quantity,
                      record_stock_audit, change_after):
    if not data.confirmed:
        raise HTTPException(status_code=400,detail='Physical receipt or return must be confirmed')
    with authenticated_write_transaction(user_id, session_token, busy_detail="Stock is busy; no changes saved. Try again") as conn:
        row=conn.execute("""SELECT m.*,t.status,t.source_min_threshold,s1.assigned_user_id AS source_owner,
            s2.assigned_user_id AS dest_owner,s2.type AS dest_type
            FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
            JOIN stores s1 ON s1.id=m.from_store_id JOIN stores s2 ON s2.id=m.to_store_id
            WHERE t.movement_id=?""",(transfer_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404,detail='Pending transfer not found')
        actor=conn.execute('SELECT role FROM users WHERE id=?',(user_id,)).fetchone()
        receive,returned=permission_checker(actor,row,user_id)
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
            conn.execute('UPDATE inventory SET min_threshold=? WHERE id=? AND min_threshold=0',
                         (row['source_min_threshold'],inventory_id))
        conn.execute('UPDATE stock_transfers SET status=?,completed_by=?,completed_at=CURRENT_TIMESTAMP,completion_note=? WHERE movement_id=?',
                     (action,user_id,data.notes,transfer_id))
        if action=='returned':
            conn.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes) VALUES(?,?,?,'return',?,?,?)",
                         (store_id,row['part_id'],row['quantity'],row['work_order_id'],user_id,f'Physical return confirmed for transfer #{transfer_id}'))
        movement_ids=[transfer_id]
        if action=='returned': movement_ids.append(conn.execute('SELECT last_insert_rowid()').fetchone()[0])
        record_stock_audit(conn,user_id,'receive_transfer' if action=='received' else 'return_transfer',[change_after(conn,before)],movement_ids,resource_id=inventory_id,request=request,extra={'transfer_id':transfer_id,'before_status':'in_transit','after_status':action,'notes':data.notes})
        return {'success':True,'message':'Receipt confirmed; destination stock is available' if action=='received' else 'Physical return confirmed; source stock restored'}

