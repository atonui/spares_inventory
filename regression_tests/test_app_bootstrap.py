import sqlite3
import pytest
from fastapi.testclient import TestClient

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded


def test_create_inventory_app_applies_shared_fastapi_bootstrap(tmp_path):
    """App bootstrap extraction must preserve shared middleware and handlers."""
    from backend.app_bootstrap import create_inventory_app, database_integrity_error

    static_dir = tmp_path / "static"
    static_dir.mkdir()

    app, limiter = create_inventory_app(
        lifespan=None,
        cors_allowed_origins=["https://inventory.example"],
        static_directory=str(static_dir),
    )

    assert app.title == "Inventory Management API"
    assert app.version == "1.0.0"
    assert isinstance(limiter, Limiter)
    assert app.state.limiter is limiter
    assert app.exception_handlers[sqlite3.IntegrityError] is database_integrity_error
    assert RateLimitExceeded in app.exception_handlers

    cors = next(
        middleware
        for middleware in app.user_middleware
        if middleware.cls is CORSMiddleware
    )
    assert cors.kwargs["allow_origins"] == ["https://inventory.example"]
    assert cors.kwargs["allow_credentials"] is True
    assert "X-CSRF-Token" in cors.kwargs["allow_headers"]
    static_mount = next(route for route in app.routes if route.path == "/static")
    assert isinstance(static_mount.app, StaticFiles)


def test_root_serves_the_frontend_without_a_static_path(tmp_path):
    from backend.app_bootstrap import create_inventory_app

    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>Inventory UI</title>")
    app, _ = create_inventory_app(
        lifespan=None,
        cors_allowed_origins=[],
        static_directory=str(static_dir),
    )

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Inventory UI" in response.text


def test_legacy_railway_frontend_url_redirects_to_the_custom_domain_root(tmp_path):
    from backend.app_bootstrap import create_inventory_app

    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>Inventory UI</title>")
    app, _ = create_inventory_app(
        lifespan=None,
        cors_allowed_origins=[],
        static_directory=str(static_dir),
    )

    @app.get("/api/example")
    def example():
        return {"ok": True}

    with TestClient(app, base_url="https://sparesinventory-production.up.railway.app") as client:
        frontend = client.get("/static/index.html", follow_redirects=False)
        api = client.get("/api/example", follow_redirects=False)

    assert frontend.status_code == 301
    assert frontend.headers["location"] == "https://www.sparestracker.com/"
    assert api.status_code == 200
    assert api.json() == {"ok": True}


def test_static_frontend_path_on_custom_domain_still_serves_the_page(tmp_path):
    from backend.app_bootstrap import create_inventory_app

    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>Inventory UI</title>")
    app, _ = create_inventory_app(
        lifespan=None,
        cors_allowed_origins=[],
        static_directory=str(static_dir),
    )

    with TestClient(app, base_url="https://www.sparestracker.com") as client:
        response = client.get("/static/index.html", follow_redirects=False)

    assert response.status_code == 200
    assert "Inventory UI" in response.text


@pytest.mark.parametrize("page", ["index.html", "profile.html", "superadmin.html", "forgot_password.html", "reset_password.html"])
def test_html_revalidates_on_get_head_and_conditional_requests(tmp_path, page):
    from backend.app_bootstrap import create_inventory_app

    (tmp_path / page).write_text("<!doctype html><title>Inventory</title>")
    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))
    with TestClient(app) as client:
        response = client.get(f"/static/{page}")
        assert response.status_code == 200
        assert response.headers.get("cache-control") == "no-cache"
        assert client.head(f"/static/{page}").headers.get("cache-control") == "no-cache"
        cached = client.get(f"/static/{page}", headers={"If-None-Match": response.headers["etag"]})
        assert cached.status_code == 304
        assert cached.headers.get("cache-control") == "no-cache"


def test_html_cache_policy_leaves_assets_api_and_missing_files_unchanged(tmp_path):
    from backend.app_bootstrap import create_inventory_app

    (tmp_path / "asset.js").write_text("const inventory = true;")
    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))

    @app.get("/api/example")
    def example():
        return {"ok": True}

    with TestClient(app) as client:
        for path in ["/static/asset.js", "/api/example", "/static/missing.html"]:
            response = client.get(path)
            assert "cache-control" not in response.headers
        assert client.get("/static/missing.html").status_code == 404


def test_email_change_confirmation_page_is_not_cached_and_suppresses_referrers(tmp_path):
    from backend.app_bootstrap import create_inventory_app

    (tmp_path / "email_change_confirmation.html").write_text("<!doctype html><title>Confirm</title>")
    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/static/email_change_confirmation.html")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_email_change_api_errors_are_marked_no_store(tmp_path):
    from fastapi import HTTPException
    from backend.app_bootstrap import create_inventory_app

    app, _ = create_inventory_app(lifespan=None, cors_allowed_origins=[], static_directory=str(tmp_path))

    @app.get("/api/profile/email-change-request")
    def email_change_status():
        raise HTTPException(status_code=401, detail="Sign in")

    with TestClient(app) as client:
        response = client.get("/api/profile/email-change-request")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
