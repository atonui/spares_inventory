"""Equipment administration routes with explicit application dependencies."""
from backend.services.session_credentials import get_request_credential
from backend.temporal_contract import register_instant_comparison
from backend.temporal_contract import instant_response
from typing import List
from datetime import timedelta
from backend.temporal import utc_now, validate_zone
from backend.services.timezone_policy import resolve_business_context
from backend.services.tenant_context import authenticated_database_transaction
from backend.services.principals import AuthenticatedPrincipal
from backend.database_sql import execute, execute_cursor, is_postgres
from backend.temporal import serialize_instant
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.equipment import (
    EquipmentResponse, CreateEquipmentRequest, UpdateEquipmentRequest,
    TransferEquipmentRequest, UpdateCalibrationRequest, EquipmentStatsResponse,
)


def _actor_id(user):
    return user.user_id if isinstance(user, AuthenticatedPrincipal) else user


def _organization_id(conn, user):
    if isinstance(user, AuthenticatedPrincipal):
        return user.organization_id
    if is_postgres(conn):
        return execute(
            conn,
            "SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid AS id",
        ).fetchone()["id"]
    return None


def _require_company_user(conn, actor, target_user_id):
    if target_user_id is None or not is_postgres(conn):
        return
    organization_id = _organization_id(conn, actor)
    member = execute(
        conn,
        "SELECT 1 FROM organization_memberships WHERE organization_id=? AND user_id=? AND is_active=TRUE",
        (organization_id, target_user_id),
    ).fetchone()
    if not member:
        raise HTTPException(status_code=400, detail="Assigned user must belong to this company")


def _require_active_equipment(equipment):
    if equipment["status"] != "active":
        raise HTTPException(status_code=409, detail="Equipment is archived; restore it before making changes")


def _equipment_history_insert(conn, cursor, user, sql, values):
    if is_postgres(conn):
        sql = sql.replace("INSERT INTO equipment_history (", "INSERT INTO equipment_history (organization_id, ")
        marker = "VALUES ("
        sql = sql.replace(marker, "VALUES (?, ", 1)
        values = (_organization_id(conn, user), *values)
    return execute_cursor(conn, cursor, sql, values)


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
    @instant_response
    @log_endpoint(action="view_equipment_stats", resource_type="equipment")
    async def get_equipment_stats(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get equipment statistics"""
        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            context=resolve_business_context(conn,actor_id=principal)
            today=utc_now().astimezone(validate_zone(context.timezone)).date().isoformat()
            actor_id = principal.user_id if isinstance(principal, AuthenticatedPrincipal) else principal
            if isinstance(principal, AuthenticatedPrincipal):
                is_admin = principal.company_role in {"owner", "admin"}
            else:
                user = execute(conn, "SELECT role FROM users WHERE id = ?", (actor_id,)).fetchone()
                is_admin = bool(user and user["role"] in ("admin", "superadmin"))

            # Total equipment
            total_equipment = execute(conn, "SELECT COUNT(*) as count FROM equipment WHERE status = 'active'").fetchone()["count"]

            # My equipment
            my_equipment = execute(conn,
                """
                SELECT COUNT(*) as count FROM equipment
                WHERE status = 'active' AND assigned_user_id = ?
            """,
                (actor_id,),
            ).fetchone()["count"]

            # Get calibration reminder days
            reminder_setting = execute(conn, """
                SELECT setting_value FROM system_settings
                WHERE setting_key = 'calibration_reminder_days'
            """).fetchone()
            reminder_days = int(reminder_setting["setting_value"]) if reminder_setting else 30

            # Equipment due soon
            from datetime import date
            check_date = (date.fromisoformat(today) + timedelta(days=reminder_days)).isoformat()

            if is_admin:
                due_soon = execute(conn,
                    """
                    SELECT COUNT(*) as count FROM equipment
                    WHERE status = 'active'
                    AND next_calibration_date IS NOT NULL
                    AND next_calibration_date <= ?
                    AND next_calibration_date >= ?
                """,
                    (check_date,today),
                ).fetchone()["count"]
            else:
                due_soon = execute(conn,
                    """
                    SELECT COUNT(*) as count FROM equipment
                    WHERE status = 'active'
                    AND assigned_user_id = ?
                    AND next_calibration_date IS NOT NULL
                    AND next_calibration_date <= ?
                    AND next_calibration_date >= ?
                """,
                    (actor_id, check_date,today),
                ).fetchone()["count"]


            # Overdue equipment
            if is_admin:
                overdue = execute(conn, """
                    SELECT COUNT(*) as count FROM equipment
                    WHERE status = 'active'
                    AND next_calibration_date IS NOT NULL
                    AND next_calibration_date < ?
                """, (today,)).fetchone()["count"]
            else:
                overdue = execute(conn,
                    """
                    SELECT COUNT(*) as count FROM equipment
                    WHERE status = 'active'
                    AND assigned_user_id = ?
                    AND next_calibration_date IS NOT NULL
                    AND next_calibration_date < ?
                """,
                    (actor_id,today),
                ).fetchone()["count"]


            return {
                "total_equipment": total_equipment,
                "my_equipment": my_equipment,
                "due_soon": due_soon,
                "overdue": overdue,
            }


    @router.get("/api/equipment", response_model=List[EquipmentResponse])
    @instant_response
    @log_endpoint(action="view_equipment", resource_type="equipment")
    async def get_equipment(
        user_id: int = Depends(get_current_user),
        show_all: bool = False,
        include_archived: bool = False,
        request: Request = None,
    ):
        """Get equipment list"""
        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, principal):
            context=resolve_business_context(conn,actor_id=principal)
            today=utc_now().astimezone(validate_zone(context.timezone)).date().isoformat()
            actor_id = principal.user_id if isinstance(principal, AuthenticatedPrincipal) else principal
            if isinstance(principal, AuthenticatedPrincipal):
                can_see_all = principal.company_role in {"owner", "admin"}
            else:
                user = execute(conn, "SELECT role FROM users WHERE id = ?", (actor_id,)).fetchone()
                can_see_all = bool(user and user["role"] == "admin")

            if include_archived and not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            delta = "CAST(CAST(e.next_calibration_date AS date) - CAST(? AS date) AS integer)" if is_postgres(conn) else "CAST(julianday(e.next_calibration_date) - julianday(?) AS INTEGER)"
            query = f"""
                SELECT
                    e.*,
                    u.name as assigned_user_name,
                    {delta} as days_until_calibration
                FROM equipment e
                LEFT JOIN users u ON e.assigned_user_id = u.id
                WHERE e.status = 'active'
            """

            if include_archived:
                query = query.replace("WHERE e.status = 'active'", "WHERE e.status IN ('active', 'deleted')")

            if not show_all and not can_see_all:
                query += " AND e.assigned_user_id = ?"
                equipment = execute(conn, query + " ORDER BY e.next_calibration_date", (today,actor_id)).fetchall()
            else:
                equipment = execute(conn, query + " ORDER BY e.next_calibration_date",(today,)).fetchall()

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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            if request_data.assigned_user_id is not None:
                require_active_record(conn,"users",request_data.assigned_user_id)
                _require_company_user(conn, user_id, request_data.assigned_user_id)

            # Check if user is admin
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if serial number already exists
            execute_cursor(conn, cursor,
                "SELECT id FROM equipment WHERE serial_number = ?",
                (request_data.serial_number,),
            )
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Serial number already exists")

            values = (
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
            )
            if is_postgres(conn):
                execute_cursor(conn, cursor, """INSERT INTO equipment (
                    organization_id, equipment_name, make, model, serial_number, assigned_user_id,
                    calibration_cert_number, calibration_authority, calibration_date,
                    next_calibration_date, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
                    (_organization_id(conn, user_id), *values))
            else:
                execute_cursor(conn, cursor, """
                INSERT INTO equipment (
                    equipment_name, make, model, serial_number, assigned_user_id,
                    calibration_cert_number, calibration_authority, calibration_date,
                    next_calibration_date, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                    values)

            equipment_id = cursor.fetchone()["id"] if is_postgres(conn) else cursor.lastrowid

            # Log history
            _equipment_history_insert(conn, cursor, user_id,
                """
                INSERT INTO equipment_history (equipment_id, action, to_user_id, created_by)
                VALUES (?, 'created', ?, ?)
            """,
                (equipment_id, request_data.assigned_user_id, _actor_id(user_id)))


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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            if request_data.assigned_user_id is not None:
                require_active_record(conn,"users",request_data.assigned_user_id)
                _require_company_user(conn, user_id, request_data.assigned_user_id)

            # Check if equipment exists
            execute_cursor(conn, cursor, "SELECT * FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")
            _require_active_equipment(equipment)

            # Build update query
            updates = []
            values = []

            for field, value in request_data.model_dump(exclude_unset=True).items():
                updates.append(f"{field} = ?")
                values.append(value)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            updates.append("updated_at = ?")
            values.append(serialize_instant(utc_now()))
            values.append(equipment_id)

            execute_cursor(conn, cursor, f"UPDATE equipment SET {', '.join(updates)} WHERE id = ?", values)

            # Log history if assignment changed
            if (
                request_data.assigned_user_id is not None
                and request_data.assigned_user_id != equipment["assigned_user_id"]
            ):
                _equipment_history_insert(conn, cursor, user_id,
                    """
                    INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, created_by)
                    VALUES (?, 'transferred', ?, ?, ?)
                """,
                    (
                        equipment_id,
                        equipment["assigned_user_id"],
                        request_data.assigned_user_id,
                        _actor_id(user_id),
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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            require_active_record(conn,"users",request_data.to_user_id)
            _require_company_user(conn, user_id, request_data.to_user_id)

            # Get equipment
            execute_cursor(conn, cursor, "SELECT * FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")
            _require_active_equipment(equipment)

            # Check permissions
            if not check_admin(user_id, conn) and equipment["assigned_user_id"] != _actor_id(user_id):
                raise HTTPException(status_code=403, detail="Permission denied")

            # Update equipment
            execute_cursor(conn, cursor,
                """
                UPDATE equipment
                SET assigned_user_id = ?, updated_at = ?
                WHERE id = ?
            """,
                (request_data.to_user_id, serialize_instant(utc_now()), equipment_id))

            # Log history
            _equipment_history_insert(conn, cursor, user_id,
                """
                INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, notes, created_by)
                VALUES (?, 'transferred', ?, ?, ?, ?)
            """,
                (
                    equipment_id,
                    equipment["assigned_user_id"],
                    request_data.to_user_id,
                    request_data.notes,
                    _actor_id(user_id),
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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            # Get equipment
            execute_cursor(conn, cursor, "SELECT * FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")
            _require_active_equipment(equipment)

            # Check permissions - admin or assigned user
            if not check_admin(user_id, conn) and equipment["assigned_user_id"] != _actor_id(user_id):
                raise HTTPException(status_code=403, detail="Permission denied")

            # Update calibration
            execute_cursor(conn, cursor,
                """
                UPDATE equipment
                SET calibration_cert_number = ?,
                    calibration_authority = ?,
                    calibration_date = ?,
                    next_calibration_date = ?,
                    updated_at = ?
                WHERE id = ?
            """,
                (
                    request_data.calibration_cert_number,
                    request_data.calibration_authority,
                    request_data.calibration_date,
                    request_data.next_calibration_date,
                    serialize_instant(utc_now()),
                    equipment_id,
                ),
            )

            # Log history
            _equipment_history_insert(conn, cursor, user_id,
                """
                INSERT INTO equipment_history (
                    equipment_id, action, calibration_date, notes, created_by
                ) VALUES (?, 'calibrated', ?, ?, ?)
            """,
                (equipment_id, request_data.calibration_date, request_data.notes, _actor_id(user_id)))


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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Get equipment
            execute_cursor(conn, cursor, "SELECT equipment_name, status FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")
            if equipment["status"] != "active":
                raise HTTPException(status_code=409, detail="Equipment is already archived")

            # Soft delete
            execute_cursor(conn, cursor,
                """
                UPDATE equipment
                SET status = 'deleted', updated_at = ?
                WHERE id = ?
            """,
                (serialize_instant(utc_now()), equipment_id))

            # Log history
            _equipment_history_insert(conn, cursor, user_id,
                """
                INSERT INTO equipment_history (equipment_id, action, created_by)
                VALUES (?, 'deleted', ?)
            """,
                (equipment_id, _actor_id(user_id)))


            _result = {
                "success": True,
                "message": f"Equipment {equipment['equipment_name']} archived; history preserved",
            }

            _record_mutation_activity(conn, user_id, 'delete_equipment', 'equipment', _result, request)
            return _result


    @router.post("/api/equipment/{equipment_id}/restore")
    @log_endpoint(action="restore_equipment", resource_type="equipment", transactional=True)
    async def restore_equipment(
        equipment_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Restore archived equipment to active use (admin only)."""
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            cursor = conn.cursor()
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            execute_cursor(conn, cursor, "SELECT equipment_name, status FROM equipment WHERE id = ?", (equipment_id,))
            equipment = cursor.fetchone()
            if not equipment:
                raise HTTPException(status_code=404, detail="Equipment not found")
            if equipment["status"] != "deleted":
                raise HTTPException(status_code=409, detail="Equipment is already active")

            execute_cursor(conn, cursor,
                "UPDATE equipment SET status = 'active', updated_at = ? WHERE id = ?",
                (serialize_instant(utc_now()), equipment_id))
            _equipment_history_insert(conn, cursor, user_id,
                "INSERT INTO equipment_history (equipment_id, action, created_by) VALUES (?, 'restored', ?)",
                (equipment_id, _actor_id(user_id)))
            result = {
                "success": True,
                "message": f"Equipment {equipment['equipment_name']} restored; history preserved",
            }
            _record_mutation_activity(conn, user_id, "restore_equipment", "equipment", result, request)
            return result


    @router.get("/api/equipment/{equipment_id}/history")
    @instant_response
    @log_endpoint(action="view_equipment_history", resource_type="equipment")
    async def get_equipment_history(
        equipment_id: int, user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get equipment history"""
        with authenticated_database_transaction(
            get_db_connection,
            principal_or_user=user_id,
            session_token=get_request_credential(request).value if request else None,
            readonly=True,
        ) as (conn, _principal):
            if not is_postgres(conn):
                register_instant_comparison(conn)
            history = execute(conn, """
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
            ORDER BY eh.created_at DESC, eh.id DESC
        """, (equipment_id,)).fetchall()

        return [dict(h) for h in history]


    @router.get("/api/settings/calibration-reminder-days")
    @instant_response
    @log_endpoint(action="view_calibration_settings", resource_type="settings")
    async def get_calibration_reminder_days(
        user_id: int = Depends(get_current_user), request: Request = None
    ):
        """Get calibration reminder days setting"""
        conn = get_db_connection()
        if not is_postgres(conn):
            register_instant_comparison(conn)
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
        with authenticated_write_transaction(user_id, get_request_credential(request).value) as conn:
            if days < 1 or days > 365:
                raise HTTPException(status_code=400, detail="Days must be between 1 and 365")

            cursor = conn.cursor()

            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            cursor.execute(
                """
                UPDATE system_settings
                SET setting_value = ?, updated_by = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%f000Z','now')
                WHERE setting_key = 'calibration_reminder_days'
            """,
                (str(days), user_id),
            )


            _result = {"success": True, "message": f"Calibration reminder set to {days} days"}

            _record_mutation_activity(conn, user_id, 'update_calibration_settings', 'settings', _result, request)
            return _result

    return router
