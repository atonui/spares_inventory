"""FastAPI application bootstrap wiring."""

import sqlite3
from typing import Sequence

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import PlainTextResponse

from backend.services.api_v1_errors import api_v1_error_response


class RevalidatingHtmlStaticFiles(StaticFiles):
    """Require cached HTML to validate its script manifest before reuse."""

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        if path.lower().endswith(".html") and response.status_code in (200, 206, 304):
            if path.lower() == "email_change_confirmation.html":
                response.headers["Cache-Control"] = "no-store"
                response.headers["Referrer-Policy"] = "no-referrer"
            else:
                response.headers["Cache-Control"] = "no-cache"
        return response


async def database_integrity_error(request: Request, exc):
    if getattr(exc, "sqlite_errorcode", None) not in (
        sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY,
        sqlite3.SQLITE_CONSTRAINT_UNIQUE,
        sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
    ):
        raise exc
    if request.url.path.startswith("/api/v1/"):
        return api_v1_error_response(request, 409)
    return JSONResponse(
        status_code=409,
        content={"detail": "Invalid database reference or duplicate record; no changes saved"},
    )


def create_inventory_app(
    *,
    lifespan,
    cors_allowed_origins: Sequence[str],
    static_directory: str = "static",
) -> tuple[FastAPI, Limiter]:
    app = FastAPI(
        title="Inventory Management API",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_exception_handler(sqlite3.IntegrityError, database_integrity_error)

    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/v1/"):
            return api_v1_error_response(
                request,
                exc.status_code,
                headers=exc.headers,
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/api/v1/"):
            return api_v1_error_response(request, 422)
        return await request_validation_exception_handler(request, exc)

    async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
        if request.url.path.startswith("/api/v1/"):
            return api_v1_error_response(request, 429, headers=exc.headers)
        return _rate_limit_exceeded_handler(request, exc)

    async def unhandled_exception_handler(request: Request, _exc: Exception):
        if request.url.path.startswith("/api/v1/"):
            return api_v1_error_response(request, 500)
        return PlainTextResponse("Internal Server Error", status_code=500)

    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
    )
    @app.middleware("http")
    async def prevent_announcement_caching(request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            if not request.url.path.startswith('/api/superadmin/announcement'):raise
            import logging
            logging.getLogger(__name__).exception('Announcement request failed')
            response = JSONResponse(status_code=503,content={'detail':'Announcements are temporarily unavailable'})
        if request.url.path.startswith('/api/superadmin/announcement'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.middleware("http")
    async def prevent_email_change_caching(request, call_next):
        response = await call_next(request)
        if request.url.path in {
            "/api/profile/email-change-requests",
            "/api/profile/email-change-request",
            "/api/auth/email-change/confirm",
            "/api/v1/me/email-change-requests",
            "/api/v1/me/email-change-request",
            "/api/v1/auth/email-change/confirm",
        }:
            response.headers["Cache-Control"] = "no-store"
        return response

    app.mount("/static", RevalidatingHtmlStaticFiles(directory=static_directory), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_frontend():
        return FileResponse(f"{static_directory}/index.html")

    return app, limiter
