"""Administrative invalidations must identify actor/target and commit truthfully."""

import asyncio

import psycopg
import pytest
from fastapi import HTTPException

from regression_tests.test_tenant_user_administration import tenant_user_api, _request
from regression_tests.test_platform_organizations import platform_api

pytest_plugins = ("regression_tests.postgres_fixtures",)


def test_admin_revocation_writer_retains_only_safe_positive_target_and_reason():
    from backend.services.security_events import safe_security_event_details

    assert safe_security_event_details(
        "session_revoked",
        {
            "target_user_id": 5,
            "session_count": 2,
            "reason": "membership_removed",
            "email": "private@example.com",
        },
    ) == {"target_user_id": 5, "session_count": 2, "reason": "membership_removed"}
    assert (
        safe_security_event_details(
            "session_revoked", {"target_user_id": True, "reason": "private-payload"}
        )
        == {}
    )
    assert safe_security_event_details("login_failed", {"target_user_id": 5}) == {}


def invoke_member_change(api, operation, target=None):
    endpoint = (
        api.endpoint("POST", "/api/users/{target_user_id}/remove")
        if operation == "remove"
        else api.endpoint("DELETE", "/api/users/{target_user_id}")
    )
    return asyncio.run(
        endpoint(
            target_user_id=target or api.manager_id,
            user_id=api.principal(api.owner_id),
            csrf_valid=True,
            request=_request(api.owner_token),
        )
    )


@pytest.mark.parametrize("operation", ["remove", "deactivate"])
@pytest.mark.parametrize(
    "mode", ["success", "rollback", "no_active_sessions", "foreign"]
)
def test_admin_invalidation_records_only_committed_active_sessions(
    tenant_user_api, operation, mode
):
    from backend.services.session_credentials import hash_session_credential

    api = tenant_user_api
    api.connection.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at,is_mobile) VALUES(%s,%s,'2099-01-01T00:00:00.000000Z',TRUE)",
        (api.manager_id, hash_session_credential("private-mobile-token")),
    )
    api.connection.execute(
        "INSERT INTO sessions(user_id,session_token_hash,expires_at,is_active) VALUES(%s,%s,'2099-01-01T00:00:00.000000Z',FALSE)",
        (api.manager_id, hash_session_credential("private-inactive-token")),
    )
    if mode == "no_active_sessions":
        api.connection.execute(
            "UPDATE sessions SET is_active=FALSE WHERE user_id=%s", (api.manager_id,)
        )
    if mode == "rollback":
        api.connection.execute(
            "CREATE FUNCTION reject_member_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit guard'; END $$"
        )
        api.connection.execute(
            "CREATE CONSTRAINT TRIGGER reject_member_commit AFTER UPDATE OR DELETE ON organization_memberships DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_member_commit()"
        )
    api.connection.commit()
    if mode == "rollback":
        with pytest.raises(psycopg.errors.RaiseException):
            invoke_member_change(api, operation)
    elif mode == "foreign":
        with pytest.raises(HTTPException) as error:
            invoke_member_change(api, operation, api.foreign_id)
        assert error.value.status_code == 404
    else:
        assert invoke_member_change(api, operation)["success"] is True
    events = api.connection.execute(
        "SELECT event,outcome,actor_user_id,details FROM platform_security_events"
    ).fetchall()
    if mode == "success":
        assert events == [
            {
                "event": "session_revoked",
                "outcome": "success",
                "actor_user_id": api.owner_id,
                "details": {
                    "target_user_id": api.manager_id,
                    "session_count": 2,
                    "reason": (
                        "membership_removed"
                        if operation == "remove"
                        else "membership_deactivated"
                    ),
                },
            }
        ]
        assert all(
            secret not in str(events)
            for secret in [
                "private-mobile-token",
                "private-inactive-token",
                "manager@example.test",
            ]
        )
        assert (
            api.connection.execute(
                "SELECT count(*) AS n FROM sessions WHERE user_id=%s AND is_active=TRUE",
                (api.manager_id,),
            ).fetchone()["n"]
            == 0
        )
    else:
        assert events == []
        if mode in {"rollback", "foreign"}:
            assert (
                api.connection.execute(
                    "SELECT count(*) AS n FROM sessions WHERE user_id=%s AND is_active=TRUE",
                    (api.manager_id,),
                ).fetchone()["n"]
                == 2
            )
            assert (
                api.connection.execute(
                    "SELECT is_active FROM organization_memberships WHERE user_id=%s",
                    (api.manager_id,),
                ).fetchone()["is_active"]
                is True
            )


@pytest.mark.parametrize("role", ["manager", "engineer"])
def test_unchanged_platform_company_role_does_not_duplicate_audit(platform_api, role):
    from backend.schemas.platform_organizations import PlatformCompanyRoleUpdateRequest

    api = platform_api
    # The fixture's member already has manager role. Authorization must still run,
    # but no mutation/audit event should be fabricated for the same role.
    call = api.endpoint(
        "PUT", "/api/platform/organizations/{organization_id}/members/{user_id}/role"
    )
    for _ in range(2):
        result = asyncio.run(
            call(
                organization_id=str(api.org_id),
                user_id=api.member_id,
                body=PlatformCompanyRoleUpdateRequest(
                    role=role, reason="Confirmed intended role"
                ),
                request=api.request,
                actor=api.principal,
                csrf_valid=True,
            )
        )
        assert result == {"success": True}
    assert api.admin.execute(
        "SELECT count(*) AS n FROM platform_audit_events WHERE action='company_role_changed'"
    ).fetchone()["n"] == (0 if role == "manager" else 1)
