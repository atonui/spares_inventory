"""Safe error responses for the versioned native API."""

from __future__ import annotations

import re
from uuid import uuid4

from fastapi.responses import JSONResponse
from starlette.requests import Request


_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_CODES = {
    400: "invalid_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    423: "account_locked",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}

_DETAILS = {
    400: "The request could not be processed.",
    401: "Sign in to continue.",
    403: "You do not have access to this resource.",
    404: "The requested resource was not found.",
    409: "The request conflicts with current state.",
    422: "One or more request fields are invalid.",
    423: "Your account is temporarily locked. Try again later.",
    429: "Too many requests. Try again later.",
    500: "The server could not complete the request.",
    503: "The service is temporarily unavailable.",
}


def api_v1_code_for_status(status_code: int) -> str:
    """Return the stable v1 error code for an HTTP status."""
    return _CODES.get(status_code, "internal_error" if status_code >= 500 else "invalid_request")


def _request_id(request: Request) -> str:
    supplied = request.headers.get("X-Request-ID", "")
    if _REQUEST_ID.fullmatch(supplied):
        return supplied
    return f"req_{uuid4().hex}"


def api_v1_error_response(
    request: Request,
    status_code: int,
    code: str | None = None,
    detail: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build a sanitized v1 error with a request ID in body and header."""
    request_id = _request_id(request)
    response_headers = dict(headers or {})
    response_headers["X-Request-ID"] = request_id
    return JSONResponse(
        status_code=status_code,
        headers=response_headers,
        content={
            "error": {
                "status": status_code,
                "code": code or api_v1_code_for_status(status_code),
                "detail": _DETAILS.get(
                    status_code,
                    "The service is temporarily unavailable."
                    if status_code >= 500
                    else "The request could not be processed.",
                ),
                "request_id": request_id,
            }
        },
    )
