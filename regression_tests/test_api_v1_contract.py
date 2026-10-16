"""Contract tests for the versioned native API surface."""

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from regression_tests.test_session_write_routes import session_api


@pytest.fixture
def error_contract_client(tmp_path):
    from backend.app_bootstrap import create_inventory_app

    static_dir = tmp_path / "static"
    static_dir.mkdir()
    app, _ = create_inventory_app(
        lifespan=None,
        cors_allowed_origins=[],
        static_directory=str(static_dir),
    )

    @app.get("/api/v1/test-error")
    def test_error():
        raise HTTPException(status_code=401, detail="Sign in to continue.")

    @app.get("/api/v1/test-validation")
    def test_validation(value: int):
        return {"value": value}

    @app.get("/api/v1/test-status/{status_code}")
    def test_status_error(status_code: int):
        raise HTTPException(status_code=status_code, detail="internal tenant detail")

    @app.get("/api/v1/test-rate-limit")
    def test_rate_limit():
        from limits import parse
        from slowapi.errors import RateLimitExceeded
        from slowapi.wrappers import Limit

        error = RateLimitExceeded(
            Limit(
                limit=parse("5/minute"), key_func=lambda: "test", scope=None,
                per_method=False, methods=None, error_message=None,
                exempt_when=None, cost=1, override_defaults=True,
            )
        )
        error.headers = {"Retry-After": "60"}
        raise error

    @app.get("/api/v1/test-integrity-conflict")
    def test_integrity_conflict():
        import sqlite3

        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE records (id INTEGER UNIQUE)")
        conn.execute("INSERT INTO records VALUES (1)")
        try:
            conn.execute("INSERT INTO records VALUES (1)")
        except sqlite3.IntegrityError as error:
            raise error

    @app.post("/api/v1/auth/native/login")
    def test_locked_login():
        raise HTTPException(status_code=423, detail="Account temporarily locked.")

    @app.get("/api/v1/test-exception")
    def test_unhandled_exception():
        raise RuntimeError("database password=do-not-expose")

    @app.get("/api/legacy/test-error")
    def legacy_error():
        raise HTTPException(status_code=401, detail="Not authenticated")

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def test_v1_http_errors_use_envelope_and_request_id(error_contract_client):
    response = error_contract_client.get("/api/v1/test-error")

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "status": 401,
            "code": "unauthenticated",
            "detail": "Sign in to continue.",
            "request_id": response.headers["x-request-id"],
        }
    }
    assert response.headers["x-request-id"].startswith("req_")


def test_v1_request_id_propagates_only_safe_values(error_contract_client):
    valid = error_contract_client.get(
        "/api/v1/test-error", headers={"X-Request-ID": "req_support_123"}
    )
    invalid = error_contract_client.get(
        "/api/v1/test-error", headers={"X-Request-ID": "bad value with spaces"}
    )

    assert valid.headers["x-request-id"] == "req_support_123"
    assert valid.json()["error"]["request_id"] == "req_support_123"
    assert invalid.headers["x-request-id"].startswith("req_")
    assert invalid.json()["error"]["request_id"] == invalid.headers["x-request-id"]


def test_v1_validation_error_uses_stable_code(error_contract_client):
    response = error_contract_client.get("/api/v1/test-validation", params={"value": "bad"})

    assert response.status_code == 422
    assert response.json()["error"]["status"] == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


@pytest.mark.parametrize(
    ("status_code", "code"),
    [
        (400, "invalid_request"),
        (403, "forbidden"),
        (404, "not_found"),
        (409, "conflict"),
        (429, "rate_limited"),
        (503, "service_unavailable"),
    ],
)
def test_v1_status_errors_use_stable_codes(error_contract_client, status_code, code):
    response = error_contract_client.get(f"/api/v1/test-status/{status_code}")

    assert response.status_code == status_code
    assert response.json()["error"]["code"] == code
    assert "internal tenant detail" not in response.text


def test_v1_rate_limiter_errors_use_standard_envelope(error_contract_client):
    response = error_contract_client.get("/api/v1/test-rate-limit")

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert response.headers["retry-after"] == "60"


def test_v1_integrity_conflict_uses_standard_envelope(error_contract_client):
    response = error_contract_client.get("/api/v1/test-integrity-conflict")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


def test_v1_locked_login_uses_account_locked_code(error_contract_client):
    response = error_contract_client.post("/api/v1/auth/native/login")

    assert response.status_code == 423
    assert response.json()["error"]["code"] == "account_locked"


def test_legacy_http_errors_keep_detail_shape(error_contract_client):
    response = error_contract_client.get("/api/legacy/test-error")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert "x-request-id" not in response.headers


def test_v1_unhandled_exception_uses_sanitized_500(error_contract_client):
    response = error_contract_client.get("/api/v1/test-exception")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "database password" not in response.text
    assert response.headers["x-request-id"] == response.json()["error"]["request_id"]


def test_v1_auth_allowlist_exposes_only_expected_auth_paths():
    import main

    routes = {
        route.path: route
        for route in main.app.routes
        if isinstance(route, APIRoute)
        and route.path.startswith("/api/v1/")
        and route.path not in {"/api/v1/inventory", "/api/v1/openapi.json"}
    }
    assert set(routes) == {
        "/api/v1/csrf-token",
        "/api/v1/auth/native/login",
        "/api/v1/auth/native/refresh",
        "/api/v1/me",
        "/api/v1/auth/logout",
    }
    assert routes["/api/v1/csrf-token"].methods == {"GET"}
    assert routes["/api/v1/auth/native/login"].methods == {"POST"}
    assert routes["/api/v1/auth/native/refresh"].methods == {"POST"}
    assert routes["/api/v1/me"].methods == {"GET"}
    assert routes["/api/v1/auth/logout"].methods == {"POST"}


def test_v1_auth_aliases_reuse_legacy_handler_callables():
    import main

    routes = {
        route.path: route.endpoint
        for route in main.app.routes
        if isinstance(route, APIRoute)
    }
    for versioned, legacy in (
        ("/api/v1/csrf-token", "/api/csrf-token"),
        ("/api/v1/auth/native/login", "/api/auth/native/login"),
        ("/api/v1/auth/native/refresh", "/api/auth/native/refresh"),
        ("/api/v1/me", "/api/me"),
        ("/api/v1/auth/logout", "/api/auth/logout"),
    ):
        assert routes[versioned] is routes[legacy]


def test_v1_protected_auth_routes_require_bearer_not_cookie():
    import main

    main.app.dependency_overrides[main.get_current_user] = lambda: 1
    try:
        with TestClient(main.app) as client:
            assert client.get("/api/v1/me").status_code == 401
            client.cookies.set("session_token", "cookie-session")
            assert client.get("/api/v1/me").status_code == 401
            mixed = client.get(
                "/api/v1/me",
                headers={"Authorization": "Bearer opaque-session"},
            )
            assert mixed.status_code == 401
            client.cookies.clear()
            response = client.get(
                "/api/v1/me",
                headers={"Authorization": "Bearer opaque-session"},
            )
            # The test override resolves the principal, but the bootstrap DB has
            # no matching profile row; 404 proves the Bearer guard was passed.
            assert response.status_code == 404, response.text
            assert response.json()["error"]["code"] == "not_found"
    finally:
        main.app.dependency_overrides.clear()


def test_v1_logout_revokes_bearer_without_cookie_response(session_api):
    import main
    from contextlib import closing
    from backend.database import connect_database

    client, database_path, _control = session_api
    main.app.dependency_overrides.pop(main.get_current_user)
    client.cookies.clear()
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": "Bearer admin-token"},
    )

    assert response.status_code == 200, response.text
    assert "set-cookie" not in response.headers
    with closing(connect_database(database_path)) as conn:
        active = conn.execute(
            "SELECT is_active FROM sessions WHERE session_token='admin-token'"
        ).fetchone()[0]
    assert active == 0


def test_v1_csrf_token_is_no_store():
    import main

    with TestClient(main.app) as client:
        response = client.get("/api/v1/csrf-token")

    assert response.status_code == 200
    assert response.json()["csrf_token"]
    assert response.headers["cache-control"] == "no-store"


def test_v1_openapi_is_filtered_and_versioned():
    import main

    with TestClient(main.app) as client:
        response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-cache"
    document = response.json()
    assert document["info"]["version"] == "1.0.0"
    assert set(document["paths"]) == {
        "/api/v1/csrf-token",
        "/api/v1/auth/native/login",
        "/api/v1/auth/native/refresh",
        "/api/v1/me",
        "/api/v1/inventory",
        "/api/v1/auth/logout",
    }
    assert "/api/inventory" not in document["paths"]
    assert not any(path.startswith("/api/superadmin/") for path in document["paths"])


def test_v1_openapi_documents_bearer_and_login_csrf():
    import main

    with TestClient(main.app) as client:
        document = client.get("/api/v1/openapi.json").json()

    scheme = document["components"]["securitySchemes"]["BearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    assert "opaque" in scheme["description"].lower()
    assert "not a jwt" in scheme["description"].lower()
    assert "SessionCookie" not in document["components"]["securitySchemes"]
    assert document["paths"]["/api/v1/me"]["get"]["security"] == [{"BearerAuth": []}]
    assert document["paths"]["/api/v1/inventory"]["get"]["security"] == [{"BearerAuth": []}]
    assert document["paths"]["/api/v1/auth/logout"]["post"]["security"] == [{"BearerAuth": []}]
    assert document["paths"]["/api/v1/auth/native/login"]["post"].get("security", []) == []
    assert document["paths"]["/api/v1/auth/native/refresh"]["post"].get("security", []) == []
    assert document["paths"]["/api/v1/csrf-token"]["get"].get("security", []) == []
    login_parameters = document["paths"]["/api/v1/auth/native/login"]["post"].get("parameters", [])
    assert any(
        parameter["name"] == "X-CSRF-Token" and parameter["in"] == "header"
        for parameter in login_parameters
    )
    refresh_parameters = document["paths"]["/api/v1/auth/native/refresh"]["post"].get("parameters", [])
    assert any(parameter["name"] == "X-Request-ID" and parameter["required"] for parameter in refresh_parameters)
    csrf_schema = document["paths"]["/api/v1/csrf-token"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    logout_schema = document["paths"]["/api/v1/auth/logout"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert csrf_schema["$ref"].endswith("CsrfTokenResponse")
    assert logout_schema["$ref"].endswith("SuccessResponse")


def test_v1_openapi_documents_login_rate_limit_and_retry_after():
    import main

    with TestClient(main.app) as client:
        document = client.get("/api/v1/openapi.json").json()

    login = document["paths"]["/api/v1/auth/native/login"]["post"]
    assert "5 attempts per minute" in login["description"].lower()
    retry_after = login["responses"]["429"]["headers"]["Retry-After"]
    assert retry_after["schema"]["type"] == "string"
    refresh = document["paths"]["/api/v1/auth/native/refresh"]["post"]
    assert "5 attempts per minute" in refresh["description"].lower()
    assert "within 60 seconds" in refresh["description"].lower()
    assert refresh["responses"]["429"]["headers"]["Retry-After"]["schema"]["type"] == "string"


def test_v1_openapi_includes_pagination_and_standard_errors():
    import main

    with TestClient(main.app) as client:
        document = client.get("/api/v1/openapi.json").json()

    inventory = document["paths"]["/api/v1/inventory"]["get"]
    parameters = {parameter["name"]: parameter for parameter in inventory["parameters"]}
    description = inventory["description"].lower()
    assert "part_number" in description
    assert "store_name" in description
    assert "inventory id" in description
    assert "total count" in description
    assert "authenticated company" in description
    assert parameters["limit"]["schema"]["default"] == 50
    assert parameters["limit"]["schema"]["maximum"] == 100
    assert "cursor" in parameters
    page_schema = inventory["responses"]["200"]["content"]["application/json"]["schema"]
    assert page_schema["$ref"].endswith("InventoryPageResponse")
    for operation in (
        inventory,
        document["paths"]["/api/v1/me"]["get"],
        document["paths"]["/api/v1/auth/logout"]["post"],
    ):
        assert operation["responses"]["401"]["content"]["application/json"]["schema"]["$ref"].endswith("ApiV1ErrorResponse")
