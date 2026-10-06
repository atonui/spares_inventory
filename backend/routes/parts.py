"""Parts administration routes with explicit application dependencies."""
import csv
import io
from contextlib import closing
from typing import List
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from backend.schemas.parts import PartResponse, CreatePartRequest, UpdatePartRequest


def create_parts_router(*, get_connection, authenticated_writer, current_user,
                        csrf_dependency, admin_guard, archive_admin_guard,
                        archive_service, endpoint_log, mutation_activity) -> APIRouter:
    """Register existing flows without owning database or audit infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    check_admin = admin_guard
    require_archive_admin = archive_admin_guard
    archive_record = archive_service
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    @router.get("/api/parts", response_model=List[PartResponse])
    @log_endpoint(action="view_parts", resource_type="parts")
    async def get_parts(include_archived: bool = False, user_id: int = Depends(get_current_user), request: Request = None):
        with closing(get_db_connection()) as conn:
            if include_archived or 'parts' == 'users':
                require_archive_admin(conn,user_id)
            where='' if include_archived else ' WHERE archived_at IS NULL'
            rows=conn.execute('SELECT id, part_number, description, category, unit_cost, archived_at FROM parts'+where+' ORDER BY part_number').fetchall()
            return [dict(row) for row in rows]


    @router.post('/api/parts/{part_id}/restore')
    async def restore_parts(part_id: int, user_id: int = Depends(get_current_user), csrf_valid: bool = Depends(verify_csrf), request: Request = None):
        return archive_record('parts',part_id,user_id,restore=True,session_token=request.cookies.get('session_token'))


    @router.post("/api/parts")
    @log_endpoint(action="create_part", resource_type="part", transactional=True)
    async def create_part(
        request_data: CreatePartRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Create new part (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if current user is admin
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if part number already exists
            cursor.execute(
                "SELECT id FROM parts WHERE part_number = ?", (request_data.part_number,)
            )
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Part number already exists")

            # Create part
            cursor.execute(
                """
                INSERT INTO parts (part_number, description, category, unit_cost)
                VALUES (?, ?, ?, ?)
            """,
                (
                    request_data.part_number,
                    request_data.description,
                    request_data.category,
                    request_data.unit_cost,
                ),
            )


            _result = {
                "success": True,
                "message": f"Part {request_data.part_number} created successfully",
            }

            _record_mutation_activity(conn, user_id, 'create_part', 'part', _result, request)
            return _result


    @router.post("/api/parts/bulk-import")
    @log_endpoint(action="bulk_import_parts", resource_type="part", transactional=True)
    async def bulk_import_parts(
        file: UploadFile = File(...),
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Bulk import parts from a CSV file (admin only)"""
        content = await file.read()
        # Try UTF-8 first, then fall back to other encodings
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = content.decode("utf-8-sig")  # UTF-8 with BOM
            except UnicodeDecodeError:
                try:
                    text = content.decode("latin-1")  # Fallback
                except UnicodeDecodeError:
                    raise HTTPException(
                        status_code=400,
                        detail="Unable to decode CSV file. Please ensure it's UTF-8 encoded.",
                    )

        reader = list(csv.DictReader(io.StringIO(text)))

        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if current user is admin
            if not check_admin(user_id, conn):
                raise HTTPException(status_code=403, detail="Admin access required")


            added, skipped = 0, 0
            skipped_details = []  # keep track of skipped parts with reasons
            # these should be moved from hardcoded to a db table in future and mapped to dropdown in frontend as well as validation on backend
            for row in reader:
                try:
                    # Validate required fields
                    if not row.get("part_number") or not row.get("description"):
                        skipped += 1
                        skipped_details.append(f"Row missing required fields: {row}")
                        continue

                    # Check if part_number already exists
                    cursor.execute(
                        "SELECT id FROM parts WHERE part_number = ?", (row["part_number"],)
                    )
                    if cursor.fetchone():
                        skipped += 1
                        skipped_details.append(f"Part {row['part_number']} already exists")
                        continue

                    cursor.execute(
                        "INSERT INTO parts (part_number, description, category, unit_cost) VALUES (?, ?, ?, ?)",
                        (
                            row["part_number"],
                            row["description"],
                            row.get("category", ""),
                            float(row.get("unit_cost", 0)),
                        ),
                    )
                    added += 1
                except Exception as e:
                    skipped += 1
                    skipped_details.append(
                        f"Error with {row.get('part_number', 'unknown')}: {str(e)}"
                    )
                    continue
            _result = {
                "success": True,
                "added": added,
                "skipped": skipped,
                "skipped_details": skipped_details,
            }

            _record_mutation_activity(conn, user_id, 'bulk_import_parts', 'part', _result, request)
            return _result


    @router.put("/api/parts/{part_id}")
    @log_endpoint(action="update_part", resource_type="part", transactional=True)
    async def update_part(
        part_id: int,
        request_data: UpdatePartRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update part (admin only)"""
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if current user is admin
            cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

            if user["role"] != "admin":
                raise HTTPException(status_code=403, detail="Admin access required")

            # Check if part exists
            cursor.execute("SELECT id FROM parts WHERE id = ?", (part_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Part not found")

            # Build update query dynamically
            updates = []
            values = []

            if request_data.part_number is not None:
                # Check if new part number already exists
                cursor.execute(
                    "SELECT id FROM parts WHERE part_number = ? AND id != ?",
                    (request_data.part_number, part_id),
                )
                if cursor.fetchone():
                    raise HTTPException(status_code=400, detail="Part number already exists")
                updates.append("part_number = ?")
                values.append(request_data.part_number)

            if request_data.description is not None:
                updates.append("description = ?")
                values.append(request_data.description)

            if request_data.category is not None:
                updates.append("category = ?")
                values.append(request_data.category)

            if request_data.unit_cost is not None:
                updates.append("unit_cost = ?")
                values.append(request_data.unit_cost)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            values.append(part_id)

            cursor.execute(f"UPDATE parts SET {', '.join(updates)} WHERE id = ?", values)


            _result = {"success": True, "message": "Part updated successfully"}

            _record_mutation_activity(conn, user_id, 'update_part', 'part', _result, request)
            return _result


    @router.delete("/api/parts/{part_id}")
    @log_endpoint(action="archive_part", resource_type="part", transactional=True)
    async def delete_part(
        part_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        return archive_record("parts", part_id, user_id, session_token=request.cookies.get("session_token"))

    return router
