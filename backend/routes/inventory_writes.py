"""Stock-changing inventory routes with explicit application dependencies."""
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.inventory_writes import (
    AddStockRequest,
    ImportBalancesRequest,
    UpdateStockRequest,
    TransferConfirmationRequest,
    TransferStockRequest,
    ConsumeStockRequest,
)


def create_inventory_write_router(*, current_user, csrf_dependency, endpoint_log,
                                  authenticated_writer, stock_access_guard,
                                  active_record_guard, balance_reader,
                                  inventory_adder, stock_audit,
                                  stock_change_reader,
                                  planned_dispatch_guard,
                                  transfer_completion) -> APIRouter:
    router = APIRouter()
    get_current_user = current_user
    verify_csrf = csrf_dependency
    log_endpoint = endpoint_log
    authenticated_write_transaction = authenticated_writer
    require_stock_access = stock_access_guard
    require_active_record = active_record_guard
    balance_snapshot = balance_reader
    add_inventory_quantity = inventory_adder
    record_stock_audit = stock_audit
    change_after = stock_change_reader
    require_planned_dispatch = planned_dispatch_guard
    complete_transfer = transfer_completion

    @router.post("/api/inventory/consume")
    @log_endpoint(action="consume_stock", resource_type="inventory", transactional=True)
    async def consume_stock(
        request_data: ConsumeStockRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Consume stock from inventory (requires work order)"""
        with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
            cursor = conn.cursor()

            # Get inventory item
            cursor.execute(
                """
                SELECT i.*, s.type, s.assigned_user_id, s.name as store_name,
                       p.part_number, p.description
                FROM inventory i
                JOIN stores s ON i.store_id = s.id
                JOIN parts p ON i.part_id = p.id
                WHERE i.id = ?
            """,
                (request_data.inventory_id,),
            )
            item = cursor.fetchone()

            if not item:
                raise HTTPException(status_code=404, detail="Inventory item not found")

            require_stock_access(conn, user_id, item["type"], item["assigned_user_id"])
            require_active_record(conn,"stores",item["store_id"])
            require_active_record(conn,"parts",item["part_id"])

            before = balance_snapshot(conn,item["store_id"],item["part_id"],item["work_order_id"])

            # Check sufficient quantity
            if item["quantity"] < request_data.quantity:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient quantity. Available: {item['quantity']}, Requested: {request_data.quantity}",
                )

            # Validate work order number
            if not request_data.work_order_number or not request_data.work_order_number.strip():
                raise HTTPException(status_code=400, detail="Work order number is required")

            # Get or create work order
            cursor.execute(
                "SELECT id FROM work_orders WHERE work_order_number = ?",
                (request_data.work_order_number,),
            )
            wo = cursor.fetchone()

            if wo:
                work_order_id = wo["id"]
            else:
                cursor.execute(
                    """
                    INSERT INTO work_orders (work_order_number, assigned_engineer_id, status)
                    VALUES (?, ?, 'in_progress')
                """,
                    (request_data.work_order_number, user_id),
                )
                work_order_id = cursor.lastrowid

            # Update inventory
            new_quantity = item["quantity"] - request_data.quantity

            if new_quantity == 0 and not item["min_threshold"]:
                cursor.execute(
                    "DELETE FROM inventory WHERE id = ?", (request_data.inventory_id,)
                )
            else:
                cursor.execute(
                    """
                    UPDATE inventory
                    SET quantity = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (new_quantity, request_data.inventory_id),
                )

            # Log movement
            cursor.execute(
                """
                INSERT INTO movements (
                    from_store_id, part_id, quantity, movement_type,
                    work_order_id, created_by, notes
                ) VALUES (?, ?, ?, 'consume', ?, ?, ?)
            """,
                (
                    item["store_id"],
                    item["part_id"],
                    request_data.quantity,
                    work_order_id,
                    user_id,
                    request_data.notes,
                ),
            )

            record_stock_audit(conn,user_id,"consume_stock",[change_after(conn,before)],[cursor.lastrowid],resource_id=item["id"],request=request,extra={"consumed_work_order_id":work_order_id,"consumed_work_order":request_data.work_order_number,"notes":request_data.notes})

            return {
                "success": True,
                "message": f"Consumed {request_data.quantity} x {item['part_number']} for WO #{request_data.work_order_number}",
                "remaining_quantity": new_quantity,
            }

    @router.post("/api/inventory/import-balances")
    @log_endpoint(action="import_stock_balances", resource_type="inventory", transactional=True)
    async def import_stock_balances(
        request_data: ImportBalancesRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Set previewed unallocated stock balances as one transaction."""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token'),
                busy_detail='Database busy; no balances saved. Try again') as conn:
            store = conn.execute("SELECT type,assigned_user_id FROM stores WHERE id=?",
                                 (request_data.store_id,)).fetchone()
            if not store:
                raise HTTPException(status_code=404, detail="Store not found")
            require_stock_access(conn, user_id, store["type"], store["assigned_user_id"])
            require_active_record(conn,"stores",request_data.store_id)
            seen, changes = set(), []
            for row in request_data.rows:
                number = row.part_number.strip()
                if not number or number in seen:
                    raise HTTPException(status_code=400, detail="Resolve duplicate part numbers before importing")
                seen.add(number)
                part = conn.execute("SELECT id FROM parts WHERE part_number=? AND archived_at IS NULL", (number,)).fetchone()
                if not part:
                    raise HTTPException(status_code=400, detail=f"Part {number} not found in catalog")
                stock = conn.execute("SELECT id,quantity FROM inventory WHERE store_id=? AND part_id=? AND work_order_id IS NULL",
                                     (request_data.store_id, part["id"])).fetchall()
                if len(stock) > 1:
                    raise HTTPException(status_code=409, detail=f"Existing duplicate stock for {number}; reconcile it first")
                current = stock[0]["quantity"] if stock else None
                if current != row.expected_quantity:
                    raise HTTPException(status_code=409, detail=f"Stock changed for {number}. Cancel and upload again to refresh the preview")
                changes.append((row, part["id"], stock[0] if stock else None))
            audit_changes, movement_ids = [], []
            added = updated = unchanged = 0
            for row, part_id, stock in changes:
                before = balance_snapshot(conn,request_data.store_id,part_id,None)
                old = stock["quantity"] if stock else 0
                if stock:
                    if old == row.quantity:
                        unchanged += 1
                        continue
                    conn.execute("UPDATE inventory SET quantity=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                                 (row.quantity, stock["id"]))
                    updated += 1
                else:
                    conn.execute("INSERT INTO inventory(store_id,part_id,quantity) VALUES(?,?,?)",
                                 (request_data.store_id, part_id, row.quantity))
                    added += 1
                delta = row.quantity - old
                if delta:
                    conn.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,created_by,notes) VALUES(?,?,?,?,?,?)",
                                 (request_data.store_id, part_id, abs(delta), "add" if delta > 0 else "remove",
                                  user_id, f"CSV balance import: {old} -> {row.quantity}"))
                    movement_ids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                audit_changes.append(change_after(conn,before))
            record_stock_audit(conn,user_id,"import_stock_balances",audit_changes,movement_ids,resource_id=request_data.store_id,resource_type="store",request=request,extra={"added":added,"updated":updated,"unchanged":unchanged})
            return {"success": True, "added": added, "updated": updated, "unchanged": unchanged}

    @router.post("/api/inventory/add")
    @log_endpoint(action="add_stock", resource_type="inventory", transactional=True)
    async def add_stock(
        request_data: AddStockRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Add stock to inventory"""
        with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
            cursor = conn.cursor()

            # Check if user can edit this store
            cursor.execute(
                """
                SELECT type, assigned_user_id FROM stores WHERE id = ?
            """,
                (request_data.store_id,),
            )
            store = cursor.fetchone()

            if not store:
                raise HTTPException(status_code=404, detail="Store not found")

            require_stock_access(conn, user_id, store["type"], store["assigned_user_id"])

            # Get work order ID if provided
            work_order_id = None
            if request_data.work_order_number:
                cursor.execute(
                    "SELECT id FROM work_orders WHERE work_order_number = ?",
                    (request_data.work_order_number,),
                )
                wo = cursor.fetchone()
                if wo:
                    work_order_id = wo["id"]
                else:
                    # Create new work order
                    cursor.execute(
                        """
                        INSERT INTO work_orders (work_order_number, assigned_engineer_id)
                        VALUES (?, ?)
                    """,
                        (request_data.work_order_number, user_id),
                    )
                    work_order_id = cursor.lastrowid

            before = balance_snapshot(conn,request_data.store_id,request_data.part_id,work_order_id)
            inventory_id = add_inventory_quantity(
                conn, request_data.store_id, request_data.part_id,
                request_data.quantity, work_order_id,
            )

            # Log movement
            cursor.execute(
                """
                INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
                VALUES (?, ?, ?, 'add', ?, ?)
            """,
                (
                    request_data.store_id,
                    request_data.part_id,
                    request_data.quantity,
                    work_order_id,
                    user_id,
                ),
            )

            record_stock_audit(conn,user_id,"add_stock",[change_after(conn,before)],[cursor.lastrowid],resource_id=inventory_id,request=request)
            return {
                "success": True,
                "id": inventory_id,
                "part_id": request_data.part_id,
                "quantity": request_data.quantity,
            }

    @router.put("/api/inventory/update")
    @log_endpoint(action="update_stock", resource_type="inventory", transactional=True)
    async def update_stock(
        request_data: UpdateStockRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update inventory quantity"""
        with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
            cursor = conn.cursor()

            # Get inventory item
            cursor.execute(
                """
                SELECT i.*, s.type, s.assigned_user_id, p.part_number
                FROM inventory i
                JOIN stores s ON i.store_id = s.id
                JOIN parts p ON i.part_id = p.id
                WHERE i.id = ?
            """,
                (request_data.inventory_id,),
            )
            item = cursor.fetchone()

            if not item:
                raise HTTPException(status_code=404, detail="Inventory item not found")

            require_stock_access(conn, user_id, item["type"], item["assigned_user_id"])
            require_active_record(conn,"stores",item["store_id"])
            require_active_record(conn,"parts",item["part_id"])

            before = balance_snapshot(conn,item["store_id"],item["part_id"],item["work_order_id"])
            old_quantity = item["quantity"]
            quantity_change = request_data.new_quantity - old_quantity

            # Update inventory
            cursor.execute(
                """
                UPDATE inventory
                SET quantity = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (request_data.new_quantity, request_data.inventory_id),
            )

            # Log movement
            movement_type = "add" if quantity_change > 0 else "remove"
            cursor.execute(
                """
                INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    item["store_id"],
                    item["part_id"],
                    abs(quantity_change),
                    movement_type,
                    item["work_order_id"],
                    user_id,
                ),
            )

            record_stock_audit(conn,user_id,"update_stock",[change_after(conn,before)],[cursor.lastrowid],resource_id=item["id"],request=request)

            return {
                "success": True,
                "message": f"Updated {item['part_number']} quantity from {old_quantity} to {request_data.new_quantity}",
            }

    @router.post("/api/inventory/transfer")
    @log_endpoint(action="transfer_stock", resource_type="inventory", transactional=True)
    async def transfer_stock(
        request_data: TransferStockRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Dispatch stock; destination stock becomes available only on receipt."""
        with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
            item = conn.execute("SELECT i.*,s.type,s.assigned_user_id,p.part_number FROM inventory i JOIN stores s ON s.id=i.store_id JOIN parts p ON p.id=i.part_id WHERE i.id=?",
                                (request_data.inventory_id,)).fetchone()
            if not item:
                raise HTTPException(status_code=404, detail="Source inventory item not found")
            require_stock_access(conn,user_id,item['type'],item['assigned_user_id'])
            if item['store_id']==request_data.to_store_id:
                raise HTTPException(status_code=400, detail="Source and destination stores must differ")
            if item['quantity']<request_data.quantity:
                raise HTTPException(status_code=400, detail="Insufficient quantity in source store")
            if not conn.execute('SELECT id FROM stores WHERE id=?',(request_data.to_store_id,)).fetchone():
                raise HTTPException(status_code=404, detail="Destination store not found")
            require_active_record(conn,'stores',request_data.to_store_id)
            require_active_record(conn,'stores',item['store_id'])
            require_active_record(conn,'parts',item['part_id'])
            if request_data.replenishment:
                require_planned_dispatch(conn,user_id,item['id'],request_data.to_store_id,request_data.quantity)
            before=balance_snapshot(conn,item['store_id'],item['part_id'],item['work_order_id'])
            remaining=item['quantity']-request_data.quantity
            if remaining or item['min_threshold']:
                conn.execute('UPDATE inventory SET quantity=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(remaining,item['id']))
            else:
                conn.execute('DELETE FROM inventory WHERE id=?',(item['id'],))
            mid=conn.execute("INSERT INTO movements(from_store_id,to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes) VALUES(?,?,?,?,'transfer',?,?,?)",
                             (item['store_id'],request_data.to_store_id,item['part_id'],request_data.quantity,item['work_order_id'],user_id,'Dispatched; awaiting receipt')).lastrowid
            conn.execute('INSERT INTO stock_transfers(movement_id,source_min_threshold) VALUES(?,?)',(mid,item['min_threshold'] or 0))
            record_stock_audit(conn,user_id,'transfer_stock',[change_after(conn,before)],[mid],resource_id=item['id'],request=request,extra={'transfer_id':mid,'before_status':None,'after_status':'in_transit','to_store_id':request_data.to_store_id,'to_store_name':conn.execute('SELECT name FROM stores WHERE id=?',(request_data.to_store_id,)).fetchone()['name']})
            return {'success':True,'transfer_id':mid,'message':f"Dispatched {request_data.quantity} {item['part_number']}; awaiting receipt"}

    @router.post('/api/inventory/transfers/{transfer_id}/receive')
    @log_endpoint(action='receive_transfer',resource_type='inventory', transactional=True)
    async def receive_transfer(transfer_id: int,data: TransferConfirmationRequest,
        user_id: int = Depends(get_current_user),csrf_valid: bool = Depends(verify_csrf),request: Request = None):
        return complete_transfer(transfer_id,data,user_id,'received',request,session_token=request.cookies.get('session_token'))

    @router.post('/api/inventory/transfers/{transfer_id}/return')
    @log_endpoint(action='return_transfer',resource_type='inventory', transactional=True)
    async def return_transfer(transfer_id: int,data: TransferConfirmationRequest,
        user_id: int = Depends(get_current_user),csrf_valid: bool = Depends(verify_csrf),request: Request = None):
        return complete_transfer(transfer_id,data,user_id,'returned',request,session_token=request.cookies.get('session_token'))

    router.consume_stock = consume_stock
    router.import_stock_balances = import_stock_balances
    router.add_stock = add_stock
    router.update_stock = update_stock
    router.transfer_stock = transfer_stock
    router.receive_transfer = receive_transfer
    router.return_transfer = return_transfer
    return router
