"""The legacy superadmin API must not run against PostgreSQL."""
import pytest

import main
from fastapi.routing import APIRoute
from regression_tests.test_session_write_routes import session_api


PREFIX = "/api/superadmin"
SQLITE_ONLY_OPERATIONS = {
    ("POST", "/users/{target_id}/reset-password"),
    ("GET", "/dashboard"),
    ("GET", "/locked-accounts"),
    ("POST", "/unlock-account"),
    ("POST", "/unlock-accounts/bulk"),
    ("GET", "/sessions"),
    ("POST", "/sessions/force-logout"),
    ("POST", "/sessions/force-logout-all"),
    ("GET", "/security-config"),
    ("PUT", "/security-config/{key}"),
    ("GET", "/users"),
    ("PUT", "/users/{target_id}/role"),
    ("GET", "/database/tables"),
    ("POST", "/database/query"),
    ("GET", "/database/backup"),
    ("POST", "/database/restore"),
    ("POST", "/database/vacuum"),
    ("DELETE", "/database/logs/purge"),
    ("POST", "/announcement"),
    ("DELETE", "/announcement"),
    ("GET", "/announcement/manage"),
    ("POST", "/announcement/dismiss"),
    ("GET", "/audit-log"),
}
PUBLIC_COMPATIBILITY_OPERATIONS = {("GET", "/announcement")}
EXPECTED_OPERATIONS = SQLITE_ONLY_OPERATIONS | PUBLIC_COMPATIBILITY_OPERATIONS


@pytest.fixture
def superadmin_api(session_api):
    client, path, control = session_api
    client.cookies.set("session_token", "root-token")
    return client, path, control


def _route_operations():
    routes = [
        route
        for route in main.app.routes
        if isinstance(route, APIRoute) and route.path.startswith(PREFIX + "/")
    ]
    return routes, {
        (method, route.path.removeprefix(PREFIX))
        for route in routes
        for method in route.methods
        if method in {"GET", "POST", "PUT", "DELETE"}
    }


def test_legacy_superadmin_routes_are_classified_and_guarded():
    routes, operations = _route_operations()
    assert operations == EXPECTED_OPERATIONS

    for route in routes:
        operation = next(
            (method, route.path.removeprefix(PREFIX))
            for method in route.methods
            if method in {"GET", "POST", "PUT", "DELETE"}
        )
        dependency_names = {dependency.call.__name__ for dependency in route.dependant.dependencies}
        if operation in SQLITE_ONLY_OPERATIONS:
            assert "require_legacy_sqlite_mode" in dependency_names, operation
        else:
            assert "require_legacy_sqlite_mode" not in dependency_names, operation


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("GET", "/database/tables", {}),
        ("POST", "/database/query", {"json": {"sql": "SELECT 1"}}),
        ("GET", "/database/backup", {}),
        ("POST", "/database/restore", {"files": {"file": ("backup.db", b"sqlite")}}),
        ("POST", "/database/vacuum", {}),
    ],
)
def test_sqlite_only_database_operations_fail_closed_in_postgres_mode(
    superadmin_api, monkeypatch, method, path, kwargs
):
    from backend.routes import superadmin as superadmin_routes

    client, _, _ = superadmin_api
    monkeypatch.setattr(superadmin_routes, "is_postgres", lambda _conn: True, raising=False)

    response = client.request(method, PREFIX + path, **kwargs)

    assert response.status_code == 503, response.text
    assert response.json() == {
        "detail": "Legacy superadmin operations are available only in SQLite mode"
    }


def test_public_announcement_read_remains_available_in_postgres_mode(
    superadmin_api, monkeypatch
):
    from backend.routes import superadmin as superadmin_routes

    client, _, _ = superadmin_api
    client.cookies.clear()
    monkeypatch.setattr(superadmin_routes, "is_postgres", lambda _conn: True, raising=False)

    response = client.get(PREFIX + "/announcement")

    assert response.status_code == 200, response.text
    assert response.json()["announcement"] is None


def test_authenticated_postgres_user_can_read_public_announcement(superadmin_api, monkeypatch):
    import json
    from types import SimpleNamespace
    from backend.routes import superadmin as superadmin_routes
    from backend.services import principals

    client, _, _ = superadmin_api
    notice = {
        "message": "Tenant-wide notice",
        "level": "info",
        "revision": "notice-revision",
        "audience": "roles",
        "roles": ["engineer"],
        "starts_at": None,
        "expires_at": None,
        "dismissible": True,
    }
    statements = []

    class Result:
        def __init__(self, row=None):
            self.row = row

        def fetchone(self):
            return self.row

    class Connection:
        def execute(self, statement, _params=()):
            statements.append(statement)
            if "FROM system_settings" in statement:
                return Result({"setting_value": json.dumps(notice)})
            return Result()

        def close(self):
            pass

    connection = Connection()
    monkeypatch.setattr(main, "get_db_connection", lambda: connection)
    monkeypatch.setattr(superadmin_routes, "is_postgres", lambda _conn: True, raising=False)
    monkeypatch.setattr(
        principals,
        "resolve_principal",
        lambda _conn, token: SimpleNamespace(
            user_id=8, company_role="engineer", is_platform_admin=False
        ),
        raising=False,
    )
    client.cookies.set("session_token", "opaque-token")

    response = client.get(PREFIX + "/announcement")

    assert response.status_code == 200, response.text
    assert response.json()["announcement"]["message"] == notice["message"]
    assert response.json()["dismissal_mode"] == "browser"
    assert not any("announcement_dismissals" in sql for sql in statements)
