"""User administration routes with explicit application dependencies."""
from backend.temporal_contract import instant_response
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from backend.schemas.auth import UserResponse
from backend.schemas.users import CreateUserRequest, UpdateUserRequest
from backend.services.principals import AuthenticatedPrincipal
from backend.services.tenant_context import authenticated_database_transaction
from backend.database_sql import execute, is_postgres


def create_users_router(*, get_connection, authenticated_writer, current_user,
                        csrf_dependency, user_management_guard, archive_admin_guard,
                        archive_service, password_hash, endpoint_log,
                        mutation_activity) -> APIRouter:
    """Register existing flows without owning database or audit infrastructure."""
    router = APIRouter()
    get_db_connection = get_connection
    authenticated_write_transaction = authenticated_writer
    get_current_user = current_user
    verify_csrf = csrf_dependency
    require_user_management = user_management_guard
    require_archive_admin = archive_admin_guard
    archive_record = archive_service
    hash_password = password_hash
    log_endpoint = endpoint_log
    _record_mutation_activity = mutation_activity

    @router.post('/api/users/{target_user_id}/restore')
    async def restore_users(target_user_id: int, user_id: int = Depends(get_current_user), csrf_valid: bool = Depends(verify_csrf), request: Request = None):
        return archive_record('users',target_user_id,user_id,restore=True,session_token=request.cookies.get('session_token'))


    @router.get("/api/users", response_model=List[UserResponse])
    @instant_response
    @log_endpoint(action="view_users", resource_type="user")
    async def get_users(include_archived: bool = False, user_id: int = Depends(get_current_user), request: Request = None):
        with authenticated_database_transaction(
            get_db_connection, principal_or_user=user_id,
            session_token=request.cookies.get('session_token') if request else None, readonly=True,
        ) as (conn, principal):
            require_archive_admin(conn,principal)
            if is_postgres(conn):
                where = "om.organization_id = ?"
                if not include_archived:
                    where += " AND om.is_active = TRUE AND u.archived_at IS NULL"
                rows = execute(conn,
                    """SELECT u.id,u.email,u.name,om.company_role AS role,u.territory,u.archived_at
                       FROM users AS u JOIN organization_memberships AS om ON om.user_id=u.id
                       WHERE """ + where + " ORDER BY u.name,u.id",
                    (principal.organization_id,),
                ).fetchall()
            else:
                where='' if include_archived else ' WHERE archived_at IS NULL'
                rows=execute(conn,'SELECT id, email, name, role, territory, archived_at FROM users'+where+' ORDER BY name').fetchall()
            return [dict(row) for row in rows]


    @router.post("/api/users")
    @log_endpoint(action="create_user", resource_type="user", transactional=True)
    async def create_user(
        request_data: CreateUserRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Create new user (admin only)"""
        password_hash = hash_password(request_data.password)
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if current user is admin
            try:
                require_user_management(user_id, requested_role=request_data.role, conn=conn)
            except HTTPException:
                raise

            # Check if email already exists
            cursor.execute("SELECT id FROM users WHERE email = ?", (request_data.email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Email already exists")

            # Create user
            cursor.execute(
                """
                INSERT INTO users (email, name, password_hash, role, territory)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    request_data.email,
                    request_data.name,
                    password_hash,
                    request_data.role,
                    request_data.territory,
                ),
            )


            _result = {
                "success": True,
                "message": f"User {request_data.name} created successfully",
            }

            _record_mutation_activity(conn, user_id, 'create_user', 'user', _result, request)
            return _result



    @router.put("/api/users/{target_user_id}")
    @log_endpoint(action="update_user", resource_type="user", transactional=True)
    async def update_user(
        target_user_id: int,
        request_data: UpdateUserRequest,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        """Update user (admin only)"""
        password_hash = hash_password(request_data.password) if request_data.password is not None else None
        with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
            cursor = conn.cursor()

            # Check if current user is admin
            try:
                require_user_management(user_id, requested_role=request_data.role, target_user_id=target_user_id, conn=conn)
            except HTTPException:
                raise

            # Check if target user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (target_user_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            # Build update query dynamically
            updates = []
            values = []

            if request_data.name is not None:
                updates.append("name = ?")
                values.append(request_data.name)

            if request_data.role is not None:
                updates.append("role = ?")
                values.append(request_data.role)

            if request_data.territory is not None:
                updates.append("territory = ?")
                values.append(request_data.territory)

            if request_data.password is not None:
                updates.append("password_hash = ?")
                values.append(password_hash)

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            values.append(target_user_id)

            cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)

            if request_data.password is not None:
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (target_user_id,))


            _result = {"success": True, "message": "User updated successfully"}

            _record_mutation_activity(conn, user_id, 'update_user', 'user', _result, request)
            return _result



    @router.delete("/api/users/{target_user_id}")
    @log_endpoint(action="archive_user", resource_type="user", transactional=True)
    async def delete_user(
        target_user_id: int,
        user_id: int = Depends(get_current_user),
        csrf_valid: bool = Depends(verify_csrf),
        request: Request = None,
    ):
        return archive_record("users", target_user_id, user_id, session_token=request.cookies.get("session_token"))

    return router
