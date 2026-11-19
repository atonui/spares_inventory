"""Platform database maintenance: read-only table statistics and old-log purge.

Deliberately excludes arbitrary SQL, file restore, and VACUUM. Backups and
storage maintenance belong to the hosting provider, not the web runtime role.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from backend.database_sql import is_postgres
from backend.services.platform_audit import record_platform_audit_event
from backend.services.platform_transactions import authenticated_platform_transaction
from backend.services.session_credentials import get_request_credential
from backend.services.tenant_context import set_tenant_context
from backend.temporal import serialize_instant, utc_now
from stock_audit import PROTECTED_AUDIT_SQL

MIN_LOG_RETENTION_DAYS = 30
MAX_LOG_RETENTION_DAYS = 3650

# Metadata only: names, estimated row counts, and on-disk sizes. No table data.
_TABLE_STATS = """SELECT c.relname AS table_name,
       COALESCE(s.n_live_tup, 0) AS estimated_rows,
       pg_total_relation_size(c.oid) AS total_bytes
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
    WHERE c.relkind IN ('r', 'p') AND n.nspname = current_schema()
    ORDER BY total_bytes DESC, table_name
    LIMIT 100"""


def create_platform_database_router(*, get_connection, current_user, csrf_dependency) -> APIRouter:
    router = APIRouter(prefix="/api/platform/database", tags=["platform"])

    def require_postgres():
        conn = get_connection()
        try:
            if not is_postgres(conn):
                raise HTTPException(status_code=503, detail="Platform administration requires PostgreSQL")
        finally:
            conn.close()

    def platform(request, actor, *, readonly=False):
        return authenticated_platform_transaction(
            get_connection,
            session_token=get_request_credential(request).value,
            expected_user_id=getattr(actor, "user_id", actor),
            readonly=readonly,
        )

    @router.get("/tables")
    async def table_statistics(request: Request, response: Response, actor=Depends(current_user)):
        require_postgres()
        # Not read-only: the audit row must commit with the read.
        with platform(request, actor) as (conn, principal):
            tables = [dict(row) for row in conn.execute(_TABLE_STATS).fetchall()]
            database_bytes = conn.execute(
                "SELECT pg_database_size(current_database()) AS bytes"
            ).fetchone()["bytes"]
            record_platform_audit_event(
                conn, principal.user_id, "platform_database_stats_read", "success",
                details={"result_count": len(tables)},
            )
        response.headers["Cache-Control"] = "no-store"
        return {"database_bytes": database_bytes, "tables": tables}

    @router.delete("/logs")
    async def purge_old_logs(
        request: Request,
        older_than_days: int = Query(ge=MIN_LOG_RETENTION_DAYS, le=MAX_LOG_RETENTION_DAYS),
        actor=Depends(current_user),
        csrf_valid=Depends(csrf_dependency),
    ):
        """Delete unprotected activity logs and system logs older than the cutoff.

        Stock audit actions and the platform audit trail are never deleted.
        """
        require_postgres()
        cutoff = serialize_instant(utc_now() - timedelta(days=older_than_days))
        with platform(request, actor) as (conn, principal):
            activity_deleted = 0
            organizations = conn.execute("SELECT id FROM organizations ORDER BY id").fetchall()
            # activity_logs is tenant-scoped by row-level security, so purge one tenant at a time.
            for organization in organizations:
                set_tenant_context(conn, organization["id"])
                activity_deleted += conn.execute(
                    f"""DELETE FROM activity_logs
                        WHERE organization_id = %s AND action NOT IN {PROTECTED_AUDIT_SQL}
                          AND created_at < %s""",
                    (organization["id"], cutoff),
                ).rowcount
            conn.execute("SELECT set_config('app.organization_id', '', true)")
            system_deleted = conn.execute(
                "DELETE FROM system_logs WHERE created_at < %s", (cutoff,)
            ).rowcount
            record_platform_audit_event(
                conn, principal.user_id, "platform_logs_purged", "success",
                details={
                    "older_than_days": older_than_days,
                    "activity_logs_deleted": activity_deleted,
                    "system_logs_deleted": system_deleted,
                },
            )
        return {
            "success": True,
            "older_than_days": older_than_days,
            "activity_logs_deleted": activity_deleted,
            "system_logs_deleted": system_deleted,
        }

    return router
