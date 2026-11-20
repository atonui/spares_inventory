from contextlib import closing

import pytest
from fastapi import HTTPException


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_company_admin_guard_accepts_only_owner_and_admin(role):
    from uuid import uuid4

    from backend.services.authorization import require_company_admin
    from backend.services.principals import AuthenticatedPrincipal

    principal = AuthenticatedPrincipal(1, uuid4(), role, False)
    assert require_company_admin(principal) is principal


@pytest.mark.parametrize("role", ["manager", "engineer", None])
def test_company_admin_guard_rejects_non_admin_and_platform_only(role):
    from uuid import uuid4

    from backend.services.authorization import require_company_admin
    from backend.services.principals import AuthenticatedPrincipal

    principal = AuthenticatedPrincipal(1, uuid4() if role else None, role, True)
    with pytest.raises(HTTPException) as error:
        require_company_admin(principal)
    assert error.value.status_code == 403


def test_company_admin_guard_rejects_suspended_organization():
    from uuid import uuid4

    from backend.services.authorization import require_company_admin
    from backend.services.principals import AuthenticatedPrincipal

    principal = AuthenticatedPrincipal(1, uuid4(), "owner", False, organization_is_active=False)
    with pytest.raises(HTTPException) as error:
        require_company_admin(principal)
    assert error.value.status_code == 403


def test_platform_admin_status_is_independent_of_company_role():
    from uuid import uuid4

    from backend.services.authorization import require_platform_admin
    from backend.services.principals import AuthenticatedPrincipal

    platform_only = AuthenticatedPrincipal(1, None, None, True)
    member_only = AuthenticatedPrincipal(2, uuid4(), "owner", False)
    assert require_platform_admin(platform_only) is platform_only
    with pytest.raises(HTTPException) as error:
        require_platform_admin(member_only)
    assert error.value.status_code == 403


def test_superadmin_guard_uses_platform_admin_membership_on_principal():
    from backend.services.authorization import require_superadmin
    from backend.services.principals import AuthenticatedPrincipal

    principal = AuthenticatedPrincipal(41, None, None, True)
    assert require_superadmin(principal) is None
    with pytest.raises(HTTPException) as error:
        require_superadmin(AuthenticatedPrincipal(42, None, None, False))
    assert error.value.status_code == 403


def test_legacy_admin_guards_fail_closed_for_integer_identity_on_postgres(monkeypatch):
    import backend.services.authorization as authorization

    class ConnectionThatMustNotBeQueried:
        def execute(self, *_args, **_kwargs):
            raise AssertionError("legacy users.role guard queried on PostgreSQL")

    conn = ConnectionThatMustNotBeQueried()

    assert authorization.check_admin(1, conn=conn) is False
    for guard in (
        lambda: authorization.require_archive_admin(conn, 1),
        lambda: authorization.require_user_management(1, conn=conn),
    ):
        with pytest.raises(HTTPException) as error:
            guard()
        assert error.value.status_code == 403

