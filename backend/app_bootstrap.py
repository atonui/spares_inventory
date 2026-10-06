"""FastAPI application bootstrap wiring."""

import sqlite3
from typing import Sequence

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


async def database_integrity_error(request: Request, exc):
    if getattr(exc, "sqlite_errorcode", None) not in (
        sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY,
        sqlite3.SQLITE_CONSTRAINT_UNIQUE,
        sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
    ):
        raise exc
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

    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
    )
    app.mount("/static", StaticFiles(directory=static_directory), name="static")

    return app, limiter
