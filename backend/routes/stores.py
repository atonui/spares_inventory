"""Store administration routes composed with application dependencies."""
import csv
import io
from contextlib import closing
from typing import List
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from backend.schemas.stores import (
    StoreResponse, StoreTypeResponse, CreateStoreTypeRequest, UpdateStoreTypeRequest,
    CreateStoreRequest, UpdateStoreRequest,
)


def create_stores_router(*, get_connection, authenticated_writer, current_user,
                         csrf_dependency, admin_guard, active_record_guard,
                         archive_admin_guard, archive_service, endpoint_log,
                         mutation_activity) -> APIRouter:
    """Register existing flows without owning database, permissions or audit state."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    check_admin = admin_guard
    require_active_record = active_record_guard
    require_archive_admin = archive_admin_guard
    archive_record = archive_service
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    @router.get("/api/stores", response_model=List[StoreResponse])
    async def get_stores(include_archived: bool = False, user_id: int = Depends(get_current_user), request: Request = None):
        with closing(get_db_connection()) as conn:
            if include_archived or 'stores' == 'users':
                require_archive_admin(conn,user_id)
            where='' if include_archived else ' WHERE archived_at IS NULL'
            rows=conn.execute('SELECT id, name, type, location, assigned_user_id, archived_at FROM stores'+where+' ORDER BY name').fetchall()
            return [dict(row) for row in rows]


    @router.post('/api/stores/{store_id}/restore')
    async def restore_stores(store_id: int, user_id: int = Depends(get_current_user), csrf_valid: bool = Depends(verify_csrf), request: Request = None):
        return archive_record('stores',store_id,user_id,restore=True,session_token=request.cookies.get('session_token'))


    @router.post("/api/stores")
    @log_endpoint(action="create_store", resource_type="store", transactional=True)
    async def create_store(
        request_data: CreateStoreRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Create new store (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            if request_data.assigned_user_id is not None:
                require_active_record(conn,"users",request_data.assigned_user_id)

            # Check if current user is admin
            if check_admin(user_id, conn) is False:
                raise HTTPException(status_code=403, detail="Admin access required")

            # Validate store type from database
            cursor.execute(
                """ SELECT id, is_active FROM store_types WHERE type_code = ? """,
                (request_data.type,),
            )

            store_type = cursor.fetchone()
            if not store_type:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid store type '{request_data.type}'. Please select from available store types.",
                )

            if not store_type["is_active"]:
                raise HTTPException(
                    status_code=400,
                    detail=f"Store type '{request_data.type}' is inactive. Please select an active store type.",
                )

            # Create store
            cursor.execute(
                """
                INSERT INTO stores (name, type, location, assigned_user_id)
                VALUES (?, ?, ?, ?)
            """,
                (
                    request_data.name,
                    request_data.type,
                    request_data.location,
                    request_data.assigned_user_id,
                ),
            )

            store_id = cursor.lastrowid


            _result = {
                "success": True,
                "id": store_id,
                "message": f"Store {request_data.name} created successfully",
            }

            _record_mutation_activity(conn, user_id, 'create_store', 'store', _result, request)
            return _result


    @router.post("/api/stores/bulk-import")
    @log_endpoint(action="bulk_import_stores", resource_type="store", transactional=True)
    async def bulk_import_stores(
        file: UploadFile = File(...),
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Bulk import stores from a CSV file (admin only)"""
        content = await file.read()
        reader = list(csv.DictReader(io.StringIO(content.decode())))
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()
            # Check if current user is admin
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")


            added, skipped = 0, 0
            # this should be moved from hardcoded to a db table in future
            valid_types = [
                "office",
                "customer_site",
                "engineer",
                "fe_consignment",
                "self",
                "admin",
                "manager",
                "warehouse",
            ]
            for row in reader:
                try:
                    # Validate type
                    if row["type"] not in valid_types:
                        skipped += 1
                        continue
                    # assigned_user_id can be empty
                    assigned_user_id = (
                        int(row["assigned_user_id"]) if row.get("assigned_user_id") else None
                    )
                    if assigned_user_id is not None:
                        require_active_record(conn,"users",assigned_user_id)
                    cursor.execute(
                        "INSERT INTO stores (name, type, location, assigned_user_id) VALUES (?, ?, ?, ?)",
                        (row["name"], row["type"], row.get("location"), assigned_user_id),
                    )
                    added += 1
                except Exception as e:
                    skipped += 1
                    continue
            _result = {"success": True, "added": added, "skipped": skipped}

            _record_mutation_activity(conn, user_id, 'bulk_import_stores', 'store', _result, request)
            return _result


    @router.put("/api/stores/{store_id}")
    @log_endpoint(action="update_store", resource_type="store", transactional=True)
    async def update_store(
        store_id: int,
        request_data: UpdateStoreRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update store (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            require_active_record(conn,"stores",store_id)
            if request_data.assigned_user_id is not None:
                require_active_record(conn,"users",request_data.assigned_user_id)

            # Check if current user is admin
            if check_admin(user_id, conn) is False:
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if store exists
            cursor.execute("SELECT id FROM stores WHERE id = ?", (store_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Store not found")

            # Build update query dynamically
            updates = []
            values = []

            if request_data.name is not None:
                updates.append("name = ?")
                values.append(request_data.name)

            if request_data.type is not None:
                # validate store type from the database
                cursor.execute(
                    """
                    SELECT id, is_active
                    FROM store_types
                    WHERE type_code = ?
                """,
                    (request_data.type,),
                )

                store_type = cursor.fetchone()
                if not store_type:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid store type '{request_data.type}'. Please select from available store types.",
                    )

                if not store_type["is_active"]:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Store type '{request_data.type}' is inactive. Please select an active store type.",
                    )

                updates.append("type = ?")
                values.append(request_data.type)

            if request_data.location is not None:
                updates.append("location = ?")
                values.append(request_data.location)

            if request_data.assigned_user_id is not None:
                updates.append("assigned_user_id = ?")
                values.append(request_data.assigned_user_id)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            values.append(store_id)

            cursor.execute(f"UPDATE stores SET {', '.join(updates)} WHERE id = ?", values)


            _result = {"success": True, "message": "Store updated successfully"}

            _record_mutation_activity(conn, user_id, 'update_store', 'store', _result, request)
            return _result


    @router.delete("/api/stores/{store_id}")
    @log_endpoint(action="archive_store", resource_type="store", transactional=True)
    async def delete_store(
        store_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        return archive_record("stores", store_id, user_id, session_token=request.cookies.get("session_token"))


    @router.get("/api/store-types", response_model=List[StoreTypeResponse])
    async def get_store_types(
        include_inactive: bool = False,
        user_id: int = Depends(get_current_user),
        request: Request = None,
    ):
        """Get all store types"""
        conn = get_db_connection()
        cursor = conn.cursor()

        if include_inactive:
            cursor.execute("""
                SELECT id, type_code, type_name, description, is_active, display_order
                FROM store_types
                ORDER BY display_order, type_name
            """)
        else:
            cursor.execute("""
                SELECT id, type_code, type_name, description, is_active, display_order
                FROM store_types
                WHERE is_active = 1
                ORDER BY display_order, type_name
            """)

        types = cursor.fetchall()
        conn.close()

        return [dict(t) for t in types]


    @router.post("/api/store-types")
    @log_endpoint(action="create_store_type", resource_type="store_type", transactional=True)
    async def create_store_type(
        request_data: CreateStoreTypeRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Create new store type (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if user is admin
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if type_code already exists
            cursor.execute(
                "SELECT id FROM store_types WHERE type_code = ?", (request_data.type_code,)
            )
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Store type code already exists")

            try:
                cursor.execute(
                    """
                    INSERT INTO store_types (type_code, type_name, description, display_order)
                    VALUES (?, ?, ?, ?)
                """,
                    (
                        request_data.type_code,
                        request_data.type_name,
                        request_data.description,
                        request_data.display_order,
                    ),
                )

                store_type_id = cursor.lastrowid

                _result = {
                    "success": True,
                    "id": store_type_id,
                    "message": f"Store type '{request_data.type_name}' created successfully",
                    "type_code": request_data.type_code,
                    "type_name": request_data.type_name,
                }

                _record_mutation_activity(conn, user_id, 'create_store_type', 'store_type', _result, request)
                return _result
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))


    @router.put("/api/store-types/{type_id}")
    @log_endpoint(action="update_store_type", resource_type="store_type", transactional=True)
    async def update_store_type(
        type_id: int,
        request_data: UpdateStoreTypeRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update store type (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if store type exists
            cursor.execute(
                "SELECT type_code, type_name FROM store_types WHERE id = ?", (type_id,)
            )
            store_type = cursor.fetchone()
            if not store_type:
                raise HTTPException(status_code=404, detail="Store type not found")

            # Build update query
            updates = []
            values = []

            if request_data.type_name is not None:
                updates.append("type_name = ?")
                values.append(request_data.type_name)

            if request_data.description is not None:
                updates.append("description = ?")
                values.append(request_data.description)

            if request_data.is_active is not None:
                updates.append("is_active = ?")
                values.append(1 if request_data.is_active else 0)

            if request_data.display_order is not None:
                updates.append("display_order = ?")
                values.append(request_data.display_order)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            updates.append("updated_at = CURRENT_TIMESTAMP")
            values.append(type_id)

            cursor.execute(f"UPDATE store_types SET {', '.join(updates)} WHERE id = ?", values)


            _result = {
                "success": True,
                "message": "Store type updated successfully",
                "id": type_id,
                "type_code": store_type["type_code"],
            }

            _record_mutation_activity(conn, user_id, 'update_store_type', 'store_type', _result, request)
            return _result


    @router.delete("/api/store-types/{type_id}")
    @log_endpoint(action="delete_store_type", resource_type="store_type", transactional=True)
    async def delete_store_type(
        type_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Delete/deactivate store type (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if store type exists
            cursor.execute(
                "SELECT type_code, type_name FROM store_types WHERE id = ?", (type_id,)
            )
            store_type = cursor.fetchone()
            if not store_type:
                raise HTTPException(status_code=404, detail="Store type not found")

            # Check if any stores are using this type
            cursor.execute(
                """
                SELECT COUNT(*) as count
                FROM stores
                WHERE type = ?
            """,
                (store_type["type_code"],),
            )
            store_count = cursor.fetchone()["count"]

            if store_count > 0:
                # Soft delete - just deactivate
                cursor.execute(
                    """
                    UPDATE store_types
                    SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (type_id,),
                )


                _result = {
                    "success": True,
                    "message": f"Store type '{store_type['type_name']}' deactivated (in use by {store_count} stores)",
                    "deactivated": True,
                    "stores_affected": store_count,
                }

                _record_mutation_activity(conn, user_id, 'delete_store_type', 'store_type', _result, request)
                return _result
            else:
                # Hard delete - no stores using it
                cursor.execute("DELETE FROM store_types WHERE id = ?", (type_id,))


                _result = {
                    "success": True,
                    "message": f"Store type '{store_type['type_name']}' deleted successfully",
                    "deactivated": False,
                }

                _record_mutation_activity(conn, user_id, 'delete_store_type', 'store_type', _result, request)
                return _result


    @router.get("/api/store-types/validate/{type_code}")
    async def validate_store_type(
        type_code: str, user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Validate if a store type code exists and is active"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, type_name, is_active
            FROM store_types
            WHERE type_code = ?
        """,
            (type_code,),
        )

        store_type = cursor.fetchone()
        conn.close()

        if not store_type:
            raise HTTPException(status_code=404, detail="Store type not found")

        return {
            "valid": True,
            "is_active": bool(store_type["is_active"]),
            "type_name": store_type["type_name"],
        }

    return router
