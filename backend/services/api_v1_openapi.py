"""Build a public OpenAPI document limited to the native v1 contract."""

from __future__ import annotations

from copy import deepcopy


_V1_PATHS = {
    "/api/v1/csrf-token",
    "/api/v1/auth/native/login",
    "/api/v1/auth/native/refresh",
    "/api/v1/auth/mobile-pairing/claim",
    "/api/v1/auth/mobile-pairing/complete",
    "/api/v1/me",
    "/api/v1/inventory",
    "/api/v1/inventory/adjustments",
    "/api/v1/inventory/add",
    "/api/v1/inventory/consume",
    "/api/v1/inventory/transfer",
    "/api/v1/inventory/transfers/{transfer_id}/receive",
    "/api/v1/inventory/transfers/{transfer_id}/return",
    "/api/v1/auth/logout",
    "/api/v1/me/email-change-requests",
    "/api/v1/me/email-change-request",
    "/api/v1/auth/email-change/confirm",
}

_ERRORS = {
    "400": ("invalid_request", "The request could not be processed."),
    "401": ("unauthenticated", "Sign in to continue."),
    "403": ("forbidden", "You do not have access to this resource."),
    "404": ("not_found", "The requested resource was not found."),
    "410": ("gone", "The pairing request is invalid or has expired."),
    "409": ("conflict", "The request conflicts with current state."),
    "422": ("validation_error", "One or more request fields are invalid."),
    "423": ("account_locked", "Your account is temporarily locked. Try again later."),
    "429": ("rate_limited", "Too many requests. Try again later."),
    "500": ("internal_error", "The server could not complete the request."),
    "503": ("service_unavailable", "The service is temporarily unavailable."),
}

_ERRORS_BY_PATH = {
    "/api/v1/csrf-token": ("429", "500", "503"),
    "/api/v1/auth/native/login": ("400", "401", "403", "409", "422", "423", "429", "500", "503"),
    "/api/v1/auth/native/refresh": ("401", "422", "429", "500", "503"),
    "/api/v1/auth/mobile-pairing/claim": ("400", "410", "422", "429", "500", "503"),
    "/api/v1/auth/mobile-pairing/complete": ("403", "410", "422", "429", "500", "503"),
    "/api/v1/me": ("401", "403", "404", "429", "500", "503"),
    "/api/v1/inventory": ("400", "401", "403", "404", "422", "429", "500", "503"),
    "/api/v1/inventory/adjustments": ("401", "403", "404", "409", "422", "429", "500", "503"),
    "/api/v1/auth/logout": ("401", "403", "404", "429", "500", "503"),
    "/api/v1/me/email-change-requests": ("401", "403", "409", "422", "429", "500", "503"),
    "/api/v1/me/email-change-request": ("401", "403", "404", "429", "500", "503"),
    "/api/v1/auth/email-change/confirm": ("400", "409", "422", "429", "500", "503"),
}

for _operation in ('add', 'consume', 'transfer', 'transfers/{transfer_id}/receive', 'transfers/{transfer_id}/return'):
    _ERRORS_BY_PATH[f'/api/v1/inventory/{_operation}'] = ('400', '401', '403', '404', '409', '422', '429', '500', '503')

_ERROR_SCHEMA = {
    "title": "ApiV1ErrorResponse",
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "title": "ApiV1Error",
            "type": "object",
            "required": ["status", "code", "detail", "request_id"],
            "properties": {
                "status": {"title": "Status", "type": "integer"},
                "code": {"title": "Code", "type": "string"},
                "detail": {"title": "Detail", "type": "string"},
                "request_id": {"title": "Request ID", "type": "string"},
            },
        }
    },
}


def _component_refs(value) -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/"):
            parts = ref.removeprefix("#/components/").split("/", 1)
            if len(parts) == 2:
                refs.add((parts[0], parts[1]))
        for nested in value.values():
            refs.update(_component_refs(nested))
    elif isinstance(value, list):
        for nested in value:
            refs.update(_component_refs(nested))
    return refs


def _error_response(status: str) -> dict:
    code, detail = _ERRORS[status]
    response = {
        "description": f"{status} {code}",
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/ApiV1ErrorResponse"},
                "example": {
                    "error": {
                        "status": int(status),
                        "code": code,
                        "detail": detail,
                        "request_id": "req_0123456789abcdef",
                    }
                },
            }
        },
    }
    if status == "429":
        response["headers"] = {
            "Retry-After": {
                "description": "Seconds to wait before retrying, when supplied.",
                "schema": {"type": "string"},
            }
        }
    return response


def _retain_referenced_components(document: dict) -> None:
    components = document.get("components", {})
    schemas = components.get("schemas", {})
    schemas["ApiV1ErrorResponse"] = _ERROR_SCHEMA
    needed = _component_refs(document.get("paths", {}))
    needed.add(("schemas", "ApiV1ErrorResponse"))
    needed.add(("securitySchemes", "BearerAuth"))
    retained: dict[str, dict] = {}
    while needed:
        section, name = needed.pop()
        if section == "securitySchemes":
            if name == "BearerAuth" and name in components.get(section, {}):
                retained.setdefault(section, {})[name] = components[section][name]
            continue
        source = components.get(section, {})
        if name not in source or name in retained.get(section, {}):
            continue
        value = source[name]
        retained.setdefault(section, {})[name] = value
        needed.update(_component_refs(value))
    bearer = retained.get("securitySchemes", {}).get("BearerAuth")
    if bearer is not None:
        bearer["description"] = (
            "Opaque server-managed session credential; not a JWT. Tenant, role, "
            "expiry, and revocation state are resolved by the server."
        )
        bearer.pop("bearerFormat", None)
    document["components"] = retained


def build_v1_openapi_document(full_document: dict) -> dict:
    """Filter the app schema to the v1 allowlist and add stable error docs."""
    document = deepcopy(full_document)
    document["info"] = {
        "title": "Inventory Management Native API",
        "version": "1.0.0",
        "description": (
            "Versioned native client contract. Company scope is derived from the "
            "authenticated server-side session."
        ),
    }
    document["paths"] = {
        path: document.get("paths", {})[path]
        for path in sorted(_V1_PATHS)
        if path in document.get("paths", {})
    }
    for path, path_item in document["paths"].items():
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            if path in {
                "/api/v1/me", "/api/v1/inventory", "/api/v1/inventory/adjustments", "/api/v1/auth/logout",
                "/api/v1/me/email-change-requests", "/api/v1/me/email-change-request",
            }:
                operation["security"] = [{"BearerAuth": []}]
            else:
                operation["security"] = []
            if path == "/api/v1/auth/native/login" and method.lower() == "post":
                operation["description"] = (
                    operation.get("description", "")
                    + "\n\nRate limit: 5 attempts per minute. A 429 response may include "
                    "the Retry-After header."
                ).strip()
                parameters = operation.setdefault("parameters", [])
                if not any(
                    parameter.get("name") == "X-CSRF-Token"
                    and parameter.get("in") == "header"
                    for parameter in parameters
                ):
                    parameters.append(
                        {
                            "name": "X-CSRF-Token",
                            "in": "header",
                            "required": True,
                            "description": "CSRF token returned by GET /api/v1/csrf-token.",
                            "schema": {"type": "string"},
                        }
                    )
            if path == "/api/v1/auth/native/refresh" and method.lower() == "post":
                operation["description"] = (
                    "Exchange the current refresh token for a new access and refresh token. "
                    "Use a new X-Request-ID for each refresh operation and reuse that same "
                    "ID if retrying the exact request within 60 seconds. Reusing an already "
                    "rotated token with another ID revokes that device session. Responses "
                    "are not stored by caches. Rate limit: 5 attempts per minute. A 429 "
                    "response may include the Retry-After header."
                )
                parameters = operation.setdefault("parameters", [])
                if not any(
                    parameter.get("name") == "X-Request-ID"
                    and parameter.get("in") == "header"
                    for parameter in parameters
                ):
                    parameters.append({
                        "name": "X-Request-ID",
                        "in": "header",
                        "required": True,
                        "description": "Stable client-generated ID reused only for retries of this request.",
                        "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"},
                    })
            if path == "/api/v1/auth/mobile-pairing/claim" and method.lower() == "post":
                operation["description"] = (
                    "Exchange the short-lived QR capability for a separate claim token. The QR capability "
                    "does not authenticate the device; a signed-in desktop account must approve the "
                    "pending request before credentials can be exchanged. QR capabilities expire after "
                    "two minutes and can be claimed once. Do not log request bodies or cache responses."
                )
            if path == "/api/v1/auth/mobile-pairing/complete" and method.lower() == "post":
                operation["description"] = (
                    "Poll using the short-lived claim token. Returns pending until an authenticated "
                    "desktop session approves the request. After approval, exchanges the claim for one "
                    "native session exactly once. Store returned credentials only in secure device storage."
                )
            if path == "/api/v1/inventory" and method.lower() == "get":
                operation["description"] = (
                    operation.get("description", "")
                    + "\n\nRows are ordered by `part_number`, `store_name`, and inventory id "
                    "as a tie-breaker. Pages are scoped to the authenticated company and "
                    "include no total count. Continue with `next_cursor` until it is null."
                ).strip()
            if path == "/api/v1/inventory/adjustments" and method.lower() == "post":
                operation["description"] = (
                    "Set the counted quantity of an unallocated inventory row. The server derives "
                    "company scope from the bearer session and returns 409 when the current quantity "
                    "does not match expected_quantity. Keep operation_id stable when retrying the same "
                    "change after an ambiguous network failure; an accepted operation is applied once."
                )
            if path == "/api/v1/me/email-change-requests" and method.lower() == "post":
                operation["description"] = (
                    "Request a verified email change. The current email remains active until "
                    "the one-time link is confirmed. Response is generic to avoid revealing "
                    "whether an address is registered. Responses use Cache-Control: no-store. "
                    "Rate limit: 3 requests per hour per account."
                )
            if path == "/api/v1/me/email-change-request":
                if method.lower() == "get":
                    operation["description"] = (
                        "Read the caller's pending email change. The proposed address is masked; "
                        "expires_at is an ISO 8601 UTC instant. Status is intentionally generic "
                        "and responses use Cache-Control: no-store."
                    )
                elif method.lower() == "delete":
                    operation["description"] = (
                        "Cancel the caller's pending email change. The response is stable whether "
                        "or not a request is pending. Responses use Cache-Control: no-store. "
                        "Rate limit: 10 requests per hour per account."
                    )
            if path == "/api/v1/auth/email-change/confirm" and method.lower() == "post":
                operation["description"] = (
                    "Confirm a one-time email-change token. This public capability endpoint "
                    "does not require a session or CSRF token. The request body carries the token; "
                    "responses use Cache-Control: no-store. Rate limit: 5 attempts per minute per IP."
                )
            responses = operation.setdefault("responses", {})
            for status in _ERRORS_BY_PATH[path]:
                responses[status] = _error_response(status)
    _retain_referenced_components(document)
    return document
