from contextlib import closing
import sqlite3

import pytest
from fastapi import HTTPException

from backend.database import connect_database
from regression_tests.session_fixtures import session_database


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


@pytest.mark.parametrize('actor,expected', [(1, True), (2, True), (3, False), (99, False)])
def test_admin_check_borrows_connection(tmp_path, actor, expected):
    from backend.services.authorization import check_admin

    with closing(connect_database(session_database(tmp_path / 'roles.db'))) as conn:
        assert check_admin(actor, conn=conn) is expected
        assert conn.execute('SELECT 1').fetchone()[0] == 1


@pytest.mark.parametrize('actor,requested,target,detail', [
    (3, None, None, 'Admin access required'),
    (1, 'superadmin', None, 'Superadmin access required'),
    (1, None, 2, 'Superadmin access required'),
])
def test_user_management_preserves_privileged_role_protection(tmp_path, actor, requested, target, detail):
    from backend.services.authorization import require_user_management

    with closing(connect_database(session_database(tmp_path / 'roles.db'))) as conn:
        with pytest.raises(HTTPException) as error:
            require_user_management(actor, requested, target, conn=conn)
        assert (error.value.status_code, error.value.detail) == (403, detail)


def test_superadmin_can_manage_superadmin_accounts(tmp_path):
    from backend.services.authorization import require_user_management, require_superadmin

    with closing(connect_database(session_database(tmp_path / 'roles.db'))) as conn:
        conn.row_factory = None
        require_superadmin(2, conn=conn)
        conn.row_factory = sqlite3.Row
        require_user_management(2, 'superadmin', 2, conn=conn)


def test_archived_admin_cannot_archive_records(tmp_path):
    from backend.services.authorization import require_archive_admin

    with closing(connect_database(session_database(tmp_path / 'roles.db'))) as conn:
        conn.execute("UPDATE users SET archived_at='2000-01-01' WHERE id=1")
        with pytest.raises(HTTPException) as error:
            require_archive_admin(conn, 1)
        assert error.value.detail == 'Admin access required'


@pytest.mark.parametrize('guard,actor,denied', [
    ('check_admin', 1, False), ('require_superadmin', 2, False),
    ('require_superadmin', 3, True), ('require_user_management', 1, False),
    ('require_user_management', 3, True),
])
def test_main_guards_use_current_factory_and_close_owned_connections(tmp_path, monkeypatch, guard, actor, denied):
    import main

    conn = connect_database(session_database(tmp_path / 'roles.db'))
    monkeypatch.setattr(main, 'get_db_connection', lambda: conn)
    if denied:
        with pytest.raises(HTTPException):
            getattr(main, guard)(actor)
    else:
        getattr(main, guard)(actor)
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        conn.execute('SELECT 1')
