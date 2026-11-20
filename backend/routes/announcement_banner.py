"""Public site-wide announcement banner (PostgreSQL).

Served at the legacy /api/superadmin/announcement path, which every page's
banner script requests. Platform admins manage the notice through
/api/platform/announcement. Dismissal is kept in the viewer's browser.
"""
from contextlib import closing

from fastapi import APIRouter, HTTPException, Request

from backend.services import announcements as notices
from backend.services.principals import resolve_principal
from backend.services.session_credentials import get_optional_request_credential
from backend.temporal_contract import instant_response


def create_announcement_banner_router(*, get_connection) -> APIRouter:
    router = APIRouter(prefix="/api/superadmin", tags=["announcements"])

    @router.get("/announcement")
    @instant_response
    async def get_announcement(request: Request):
        with closing(get_connection()) as conn:
            conn.execute("BEGIN")
            viewer = None
            credential = get_optional_request_credential(request)
            if credential:
                try:
                    principal = resolve_principal(conn, credential.value)
                except HTTPException as error:
                    if error.status_code != 401:
                        raise
                else:
                    role = principal.company_role or ("superadmin" if principal.is_platform_admin else None)
                    viewer = {"user_id": principal.user_id, "role": role}
            notice = notices.eligible_notice(
                conn, notices.load_notice(conn), viewer=viewer, now=notices.utc_now(), check_dismissal=False,
            )
            return {
                "announcement": notice,
                "dismissal_mode": "browser",
                "viewer_key": "user:" + str(viewer["user_id"]) if viewer else "anonymous",
            }

    return router
