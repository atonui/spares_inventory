"""Equipment administration routes with explicit application dependencies."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.equipment import (
    EquipmentResponse, CreateEquipmentRequest, UpdateEquipmentRequest,
    TransferEquipmentRequest, UpdateCalibrationRequest, EquipmentStatsResponse,
)


def create_equipment_router(*, get_connection, authenticated_writer, current_user,
                            csrf_dependency, admin_guard, active_record_guard,
                            endpoint_log, mutation_activity) -> APIRouter:
    """Register existing flows without owning database or audit infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    check_admin = admin_guard
    require_active_record = active_record_guard
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    @router.get("/api/equipment/statistics", response_model=EquipmentStatsResponse)
    @log_endpoint(action="view_equipment_stats", resource_type="equipment")
    async def get_equipment_stats(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get equipment statistics"""
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user role
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        # Total equipment
        cursor.execute("SELECT COUNT(*) as count FROM equipment WHERE status = 'active'")
        total_equipment = cursor.fetchone()["count"]

        # My equipment
        cursor.execute(
            """
            SELECT COUNT(*) as count FROM equipment
            WHERE status = 'active' AND assigned_user_id = ?
        """,
            (user_id,),
        )
        my_equipment = cursor.fetchone()["count"]

        # Get calibration reminder days
        cursor.execute("""
            SELECT setting_value FROM system_settings
            WHERE setting_key = 'calibration_reminder_days'
        """)
        reminder_setting = cursor.fetchone()
        reminder_days = int(reminder_setting["setting_value"]) if reminder_setting else 30

        # Equipment due soon
        from datetime import datetime, timedelta

        check_date = (datetime.now() + timedelta(days=reminder_days)).strftime("%Y-%m-%d")

        if user["role"] in ("admin", "superadmin"):
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM equipment
                WHERE status = 'active'
                AND next_calibration_date IS NOT NULL
                AND next_calibration_date <= ?
                AND next_calibration_date >= date('now')
            """,
                (check_date,),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM equipment
                WHERE status = 'active'
                AND assigned_user_id = ?
                AND next_calibration_date IS NOT NULL
                AND next_calibration_date <= ?
                AND next_calibration_date >= date('now')
            """,
                (user_id, check_date),
            )

        due_soon = cursor.fetchone()["count"]

        # Overdue equipment
        if user["role"] in ("admin", "superadmin"):
            cursor.execute("""
                SELECT COUNT(*) as count FROM equipment
                WHERE status = 'active'
                AND next_calibration_date IS NOT NULL
                AND next_calibration_date < date('now')
            """)
        else:
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM equipment
                WHERE status = 'active'
                AND assigned_user_id = ?
                AND next_calibration_date IS NOT NULL
                AND next_calibration_date < date('now')
            """,
                (user_id,),
            )

        overdue = cursor.fetchone()["count"]

        conn.close()

        return {
            "total_equipment": total_equipment,
            "my_equipment": my_equipment,
            "due_soon": due_soon,
            "overdue": overdue,
        }


    @router.get("/api/equipment", response_model=List[EquipmentResponse])
    @log_endpoint(action="view_equipment", resource_type="equipment")
    async def get_equipment(
        user_id: int = Depends(get_current_user),
        show_all: bool = False,
        request: Request = None,
    ):
        """Get equipment list"""
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user role
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        query = """
            SELECT
                e.*,
                u.name as assigned_user_name,
                CAST(julianday(e.next_calibration_date) - julianday('now') AS INTEGER) as days_until_calibration
            FROM equipment e
            LEFT JOIN users u ON e.assigned_user_id = u.id
            WHERE e.status = 'active'
        """

        if not show_all and user["role"] != "admin":
            query += " AND e.assigned_user_id = ?"
            cursor.execute(query + " ORDER BY e.next_calibration_date", (user_id,))
        else:
            cursor.execute(query + " ORDER BY e.next_calibration_date")

        equipment = cursor.fetchall()
        conn.close()

        return [dict(eq) for eq in equipment]


    @router.post("/api/equipment")
    @log_endpoint(action="create_equipment", resource_type="equipment", transactional=True)
    async def create_equipment(
        request_data: CreateEquipmentRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Create new equipment (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            if request_data.assigned_user_id is not None:
                require_active_record(conn,"users",request_data.assigned_user_id)

            # Check if user is admin
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if serial number already exists
            cursor.execute(
                "SELECT id FROM equipment WHERE serial_number = ?",
                (request_data.serial_number,),
            )
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Serial number already exists")

            cursor.execute(
                """
                INSERT INTO equipment (
                    equipment_name, make, model, serial_number, assigned_user_id,
                    calibration_cert_number, calibration_authority, calibration_date,
                    next_calibration_date, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    request_data.equipment_name,
                    request_data.make,
                    request_data.model,
                    request_data.serial_number,
                    request_data.assigned_user_id,
                    request_data.calibration_cert_number,
                    request_data.calibration_authority,
                    request_data.calibration_date,
                    request_data.next_calibration_date,
                    request_data.notes,
                ),
            )

            equipment_id = cursor.lastrowid

            # Log history
            cursor.execute(
                """
                INSERT INTO equipment_history (equipment_id, action, to_user_id, created_by)
                VALUES (?, 'created', ?, ?)
            """,
                (equipment_id, request_data.assigned_user_id, user_id),
            )


            _result = {
                "success": True,
                "id": equipment_id,
                "message": "Equipment created successfully",
            }

            _record_mutation_activity(conn, user_id, 'create_equipment', 'equipment', _result, request)
            return _result


    @router.put("/api/equipment/{equipment_id}")
    @log_endpoint(action="update_equipment", resource_type="equipment", transactional=True)
    async def update_equipment(
        equipment_id: int,
        request_data: UpdateEquipmentRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update equipment (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            if request_data.assigned_user_id is not None:
                require_active_record(conn,"users",request_data.assigned_user_id)

            # Check if equipment exists
            cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")

            # Build update query
            updates = []
            values = []

            for field, value in request_data.model_dump(exclude_unset=True).items():
                updates.append(f"{field} = ?")
                values.append(value)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            updates.append("updated_at = CURRENT_TIMESTAMP")
            values.append(equipment_id)

            cursor.execute(f"UPDATE equipment SET {', '.join(updates)} WHERE id = ?", values)

            # Log history if assignment changed
            if (
                request_data.assigned_user_id is not None
                and request_data.assigned_user_id != equipment["assigned_user_id"]
            ):
                cursor.execute(
                    """
                    INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, created_by)
                    VALUES (?, 'transferred', ?, ?, ?)
                """,
                    (
                        equipment_id,
                        equipment["assigned_user_id"],
                        request_data.assigned_user_id,
                        user_id,
                    ),
                )


            _result = {"success": True, "message": "Equipment updated successfully"}

            _record_mutation_activity(conn, user_id, 'update_equipment', 'equipment', _result, request)
            return _result


    @router.post("/api/equipment/{equipment_id}/transfer")
    @log_endpoint(action="transfer_equipment", resource_type="equipment", transactional=True)
    async def transfer_equipment(
        equipment_id: int,
        request_data: TransferEquipmentRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Transfer equipment to another user"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            require_active_record(conn,"users",request_data.to_user_id)

            # Get equipment
            cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")

            # Check permissions
            if not check_admin(user_id, conn) and equipment["assigned_user_id"] != user_id:
                raise HTTPException(status_code=403, detail="Permission denied")

            # Update equipment
            cursor.execute(
                """
                UPDATE equipment
                SET assigned_user_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (request_data.to_user_id, equipment_id),
            )

            # Log history
            cursor.execute(
                """
                INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, notes, created_by)
                VALUES (?, 'transferred', ?, ?, ?, ?)
            """,
                (
                    equipment_id,
                    equipment["assigned_user_id"],
                    request_data.to_user_id,
                    request_data.notes,
                    user_id,
                ),
            )


            _result = {"success": True, "message": "Equipment transferred successfully"}

            _record_mutation_activity(conn, user_id, 'transfer_equipment', 'equipment', _result, request)
            return _result


    @router.post("/api/equipment/{equipment_id}/calibrate")
    @log_endpoint(action="calibrate_equipment", resource_type="equipment", transactional=True)
    async def update_calibration(
        equipment_id: int,
        request_data: UpdateCalibrationRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update equipment calibration"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Get equipment
            cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")

            # Check permissions - admin or assigned user
            if not check_admin(user_id, conn) and equipment["assigned_user_id"] != user_id:
                raise HTTPException(status_code=403, detail="Permission denied")

            # Update calibration
            cursor.execute(
                """
                UPDATE equipment
                SET calibration_cert_number = ?,
                    calibration_authority = ?,
                    calibration_date = ?,
                    next_calibration_date = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (
                    request_data.calibration_cert_number,
                    request_data.calibration_authority,
                    request_data.calibration_date,
                    request_data.next_calibration_date,
                    equipment_id,
                ),
            )

            # Log history
            cursor.execute(
                """
                INSERT INTO equipment_history (
                    equipment_id, action, calibration_date, notes, created_by
                ) VALUES (?, 'calibrated', ?, ?, ?)
            """,
                (equipment_id, request_data.calibration_date, request_data.notes, user_id),
            )


            _result = {"success": True, "message": "Calibration updated successfully"}

            _record_mutation_activity(conn, user_id, 'calibrate_equipment', 'equipment', _result, request)
            return _result


    @router.delete("/api/equipment/{equipment_id}")
    @log_endpoint(action="delete_equipment", resource_type="equipment", transactional=True)
    async def delete_equipment(
        equipment_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Delete/deactivate equipment (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Get equipment
            cursor.execute("SELECT equipment_name FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")

            # Soft delete
            cursor.execute(
                """
                UPDATE equipment
                SET status = 'deleted', updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (equipment_id,),
            )

            # Log history
            cursor.execute(
                """
                INSERT INTO equipment_history (equipment_id, action, created_by)
                VALUES (?, 'deleted', ?)
            """,
                (equipment_id, user_id),
            )


            _result = {
                "success": True,
                "message": f"Equipment {equipment['equipment_name']} deleted successfully",
            }

            _record_mutation_activity(conn, user_id, 'delete_equipment', 'equipment', _result, request)
            return _result


    @router.get("/api/equipment/{equipment_id}/history")
    @log_endpoint(action="view_equipment_history", resource_type="equipment")
    async def get_equipment_history(
        equipment_id: int, user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get equipment history"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                eh.*,
                u1.name as from_user_name,
                u2.name as to_user_name,
                u3.name as created_by_name
            FROM equipment_history eh
            LEFT JOIN users u1 ON eh.from_user_id = u1.id
            LEFT JOIN users u2 ON eh.to_user_id = u2.id
            LEFT JOIN users u3 ON eh.created_by = u3.id
            WHERE eh.equipment_id = ?
            ORDER BY eh.created_at DESC
        """,
            (equipment_id,),
        )

        history = cursor.fetchall()
        conn.close()

        return [dict(h) for h in history]


    @router.get("/api/settings/calibration-reminder-days")
    @log_endpoint(action="view_calibration_settings", resource_type="settings")
    async def get_calibration_reminder_days(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get calibration reminder days setting"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT setting_value FROM system_settings
            WHERE setting_key = 'calibration_reminder_days'
        """)
        result = cursor.fetchone()
        conn.close()

        return {"days": int(result["setting_value"]) if result else 30}


    @router.put("/api/settings/calibration-reminder-days")
    @log_endpoint(action="update_calibration_settings", resource_type="settings", transactional=True)
    async def update_calibration_reminder_days(
        days: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update calibration reminder days setting (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            if days < 1 or days > 365:
                raise HTTPException(status_code=400, detail="Days must be between 1 and 365")

            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            cursor.execute(
                """
                UPDATE system_settings
                SET setting_value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
                WHERE setting_key = 'calibration_reminder_days'
            """,
                (str(days), user_id),
            )


            _result = {"success": True, "message": f"Calibration reminder set to {days} days"}

            _record_mutation_activity(conn, user_id, 'update_calibration_settings', 'settings', _result, request)
            return _result

    return router
