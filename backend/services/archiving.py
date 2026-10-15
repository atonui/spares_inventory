"""Archive and restore records within one authenticated tenant transaction."""

from backend.database_sql import execute, is_postgres
from backend.temporal import serialize_instant, utc_now
from .principals import AuthenticatedPrincipal
from fastapi import HTTPException


def archive_record(table, identifier, user_id, restore=False, *, session_token,
                   authenticated_write_transaction, require_archive_admin,
                   require_user_management, require_no_pending_transfer,
                   require_active_record):
    if table not in ("users", "stores", "parts"):
        raise ValueError("Unsupported archive type")
    with authenticated_write_transaction(
        user_id,
        session_token,
        busy_detail="Stock is busy; no changes saved. Try again",
    ) as conn:
        is_pg = is_postgres(conn)
        actor_id = user_id.user_id if isinstance(user_id, AuthenticatedPrincipal) else user_id
        require_archive_admin(conn, user_id)
        if table == "users":
            require_user_management(actor_id, target_user_id=identifier, conn=conn)
            if identifier == actor_id and not restore:
                raise HTTPException(status_code=400, detail="Cannot archive your own account")

        row = execute(conn, f"SELECT * FROM {table} WHERE id = ?", (identifier,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Record not found")
        if bool(row["archived_at"]) != restore:
            message = "Record is already active" if restore else "Record is already archived"
            raise HTTPException(status_code=409, detail=message)

        if not restore:
            require_no_pending_transfer(conn, {"users": "user", "stores": "store", "parts": "part"}[table], identifier)
            if table in ("parts", "stores"):
                column = "part_id" if table == "parts" else "store_id"
                if execute(
                    conn,
                    f"SELECT 1 FROM inventory WHERE {column} = ? AND quantity > 0 LIMIT 1",
                    (identifier,),
                ).fetchone():
                    raise HTTPException(
                        status_code=400,
                        detail="Cannot archive a record with stock; transfer or consume it first",
                    )
            if table == "users":
                has_assignments = execute(
                    conn,
                    "SELECT 1 FROM stores WHERE assigned_user_id = ? AND archived_at IS NULL LIMIT 1",
                    (identifier,),
                ).fetchone() or execute(
                    conn,
                    "SELECT 1 FROM equipment WHERE assigned_user_id = ? LIMIT 1",
                    (identifier,),
                ).fetchone()
                if has_assignments:
                    raise HTTPException(status_code=400, detail="Reassign stores and equipment before archiving this user")
                execute(conn, "UPDATE sessions SET is_active = FALSE WHERE user_id = ?", (identifier,))
                execute(conn, """UPDATE users SET session_token = NULL, session_expires = NULL,
                             reset_token = NULL, reset_token_expires = NULL WHERE id = ?""", (identifier,))
        elif table == "stores" and row["assigned_user_id"] is not None:
            require_active_record(conn, "users", row["assigned_user_id"])

        if table == "users" and restore:
            execute(conn, "UPDATE sessions SET is_active = FALSE WHERE user_id = ?", (identifier,))
            execute(conn, """UPDATE users SET session_token = NULL, session_expires = NULL,
                         reset_token = NULL, reset_token_expires = NULL WHERE id = ?""", (identifier,))

        archived_at = None if restore else serialize_instant(utc_now())
        execute(conn, f"UPDATE {table} SET archived_at = ? WHERE id = ?", (archived_at, identifier))
        action = "restore" if restore else "archive"
        if is_pg:
            execute(
                conn,
                """INSERT INTO activity_logs
                   (organization_id, user_id, username, action, resource_type, resource_id)
                   SELECT %s, id, name, %s, %s, %s FROM users WHERE id = %s""",
                (user_id.organization_id, action, table, identifier, actor_id),
            )
        else:
            execute(
                conn,
                """INSERT INTO activity_logs(user_id, username, action, resource_type, resource_id)
                   SELECT id, name, ?, ?, ? FROM users WHERE id = ?""",
                (action, table, identifier, actor_id),
            )
        return {
            "success": True,
            "message": f'Record {"restored" if restore else "archived"}; history preserved',
        }
