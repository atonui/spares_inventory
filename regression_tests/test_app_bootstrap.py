import sqlite3

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
    assert cors.options["allow_origins"] == ["https://inventory.example"]
    assert cors.options["allow_credentials"] is True
    assert "X-CSRF-Token" in cors.options["allow_headers"]

    static_mount = next(route for route in app.routes if route.path == "/static")
    assert isinstance(static_mount.app, StaticFiles)
