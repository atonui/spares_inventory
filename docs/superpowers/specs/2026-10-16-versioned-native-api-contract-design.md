# Versioned Native API Contract

**Status:** Approved; implementation complete
**Date:** 2026-10-16
**Scope:** API contract foundation for future iOS and Android clients. This spec does not implement the native app or store release work.

## Context

The SaaS uses PostgreSQL tenant isolation and server-side sessions. Browser clients use the existing cookie and CSRF flow. Native bearer authentication has been added on the same server-managed session model, but the HTTP paths are still under unversioned `/api/...` routes. OpenAPI's current `1.0.0` metadata is not a versioned route contract. The mobile starter currently calls the CSRF-token, native-login, current-user, inventory-list, and logout routes; inventory is returned as an unpaginated array.

The SaaS mobile/store readiness plan makes a documented, versioned API the first remaining gate. This slice establishes that contract without changing the browser contract or beginning broader native feature work.

## Goals

1. Publish an explicit `/api/v1` surface for the five operations already needed by the native starter.
2. Keep authentication, authorization, tenant derivation, and business behavior shared with existing services.
3. Standardize v1 errors and collection pagination for reliable native handling.
4. Make tenant scoping explicit in the contract and prove it with tests.
5. Keep existing `/api/...` web paths and response shapes compatible.

## Non-goals

- Rewriting or removing existing browser routes.
- Adding refresh-token/session-renewal behavior; that remains the next API foundation gate.
- Adding native movement history, stock mutations, user administration, or platform-admin APIs.
- Changing tenant membership rules, roles, PostgreSQL RLS policies, or server-side session behavior.
- Starting broader native UI work or store submission.

## Versioned Surface

The first v1 allowlist contains these operations:

| Method and path | Authentication | Contract purpose |
| --- | --- | --- |
| `GET /api/v1/csrf-token` | Public, no-store | Obtain the signed CSRF token required for native login. |
| `POST /api/v1/auth/native/login` | Public plus CSRF token | Authenticate invitation-provisioned credentials and create the existing server-managed session. |
| `GET /api/v1/me` | Bearer session | Return the authenticated user's current profile and company role. |
| `GET /api/v1/inventory` | Bearer session | Return a tenant-scoped inventory page. |
| `POST /api/v1/auth/logout` | Bearer session | Revoke the current server-side session. |

The v1 router must be an explicit allowlist. It must not expose a route merely because the underlying router is included. Add operations only with a reviewed contract and corresponding authorization, tenant-isolation, and schema tests. Platform-admin operations are outside this native company API.

### Authentication behavior

- Login keeps the existing request fields, invitation-only eligibility, password checks, lockout behavior, and rate limit. The client first gets `/api/v1/csrf-token`, then sends the token in `X-CSRF-Token` on login.
- A successful login returns the existing opaque bearer credential, its expiry, and the user summary. The credential remains backed by the same server-side session and revocation state described in the native bearer-session design.
- Protected v1 endpoints require `Authorization: Bearer <credential>`; cookie-only authentication is not accepted on `/api/v1`. Tenant, membership, and role context are resolved from that session on the server. Clients never select a tenant through URL, query, header, or body fields.
- Logout revokes the presented session. The v1 Bearer response does not set or clear a browser session cookie. It is safe for the client to clear its locally stored credential after success; retry semantics for an already-expired credential follow the standard `401` error contract.
- Cookie and CSRF behavior for existing browser paths is unchanged. The v1 CSRF endpoint remains available for login protection; authenticated bearer calls do not need browser CSRF tokens.

## Error Contract

Every non-success JSON response from a v1 route uses this envelope:

```json
{
  "error": {
    "status": 401,
    "code": "unauthenticated",
    "detail": "Sign in to continue.",
    "request_id": "req_01J..."
  }
}
```

`status` matches the HTTP status. `code` is a stable machine-readable snake_case value; `detail` is safe to show or log in a client and must not reveal secrets, SQL, internal stack traces, or another tenant's data. `request_id` is an opaque correlation value. The response also carries that value in `X-Request-ID`; clients may include it in support reports.

The contract defines stable codes for at least:

| HTTP status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Request cannot be processed as sent. |
| 401 | `unauthenticated` | Credential is missing, malformed, expired, inactive, or revoked. |
| 403 | `forbidden` | Authenticated identity lacks required company membership or permission. |
| 404 | `not_found` | Resource is absent or not visible in the caller's tenant. |
| 409 | `conflict` | Request conflicts with current state. |
| 422 | `validation_error` | Request fields fail schema validation. |
| 423 | `account_locked` | Account is temporarily locked; preserve the current login lockout policy. |
| 429 | `rate_limited` | Rate limit was reached; include `Retry-After` when available. |
| 500 | `internal_error` | Unexpected failure; no internal detail is exposed. |
| 503 | `service_unavailable` | Required SaaS service is unavailable. |

The v1 OpenAPI document will list endpoint-specific possible errors and examples. Existing `/api/...` routes retain their current error response formats. Request IDs must be generated or safely propagated by trusted server infrastructure; arbitrary client-provided values must not be reflected without validation.

## Inventory Pagination

`GET /api/v1/inventory` accepts `limit` and `cursor` query parameters:

- `limit` defaults to `50` and is capped at `100`; invalid or out-of-range values return the standard `422` envelope.
- `cursor` is optional, opaque, and only meaningful for this endpoint. The client must treat it as an uninterpreted string.
- The endpoint returns a stable keyset-paginated page ordered by `part_number`, `store_name`, then inventory row `id`. The unique row ID is the final tie-breaker so continuation does not skip or duplicate rows when names match.
- A cursor is integrity-protected and bound to the endpoint's ordering/version. It carries only the last inventory row ID; the server resolves that row's current sort values inside the authenticated tenant transaction. The cursor never grants access or selects a tenant. This keeps cursor size bounded even when part or store names are long.
- Pagination executes inside the same authenticated tenant-scoped database transaction as the existing inventory read. It must not query another tenant to calculate totals or construct continuation state.
- No total count is returned in v1. The mobile client fetches subsequent pages until `next_cursor` is `null`.

Success response:

```json
{
  "items": [
    {
      "id": 123,
      "part_id": 45,
      "store_id": 8,
      "part_number": "ABC-123",
      "description": "Example part",
      "store_name": "Main Store",
      "store_type": "warehouse",
      "store_owner": null,
      "quantity": 12,
      "min_threshold": 3,
      "is_allocated": false,
      "work_order": null
    }
  ],
  "page": {
    "limit": 50,
    "next_cursor": "opaque-cursor-or-null"
  }
}
```

The v1 inventory item fields follow the existing `InventoryResponse` meaning and types. The legacy `GET /api/inventory` continues returning its current bare array.

## Tenant and Authorization Rules

- The authenticated server-side session is the only source of tenant identity for v1 company routes.
- The authenticated principal and existing tenant transaction/RLS mechanisms remain authoritative for both reads and writes.
- A user with no active company membership cannot use company-scoped v1 endpoints. Platform-admin status alone does not grant company inventory access.
- Tenant identifiers supplied by clients are not accepted as a way to choose data scope. If a future endpoint needs a tenant-related field for a business operation, it must validate it against the authenticated principal and must not override the principal's scope.
- Missing, revoked, expired, archived-user, or removed-membership sessions fail with the documented authentication/authorization errors using existing server policy.

## OpenAPI and Compatibility

- Publish a dedicated OpenAPI document for `/api/v1` routes with `info.version: 1.0.0`, an HTTP Bearer scheme describing opaque server-side sessions, schemas, examples, pagination, error codes, rate limits, and tenant-scoping behavior.
- Keep contract version separate from app package versions. Within `/api/v1`, make only backward-compatible additions; incompatible changes require `/api/v2` or an explicit migration period and deprecation policy.
- Keep the combined application documentation discoverable, but clearly label v1 routes and legacy browser `/api` routes. The new v1 document must not imply that all existing `/api` routes are stable mobile endpoints.
- Existing web paths, cookies, CSRF behavior, response bodies, and inventory array shape remain unchanged. v1 routes may delegate into shared service functions; they must not duplicate business logic or relax authorization.

## Testing and Acceptance

1. Contract tests verify all five paths, methods, authentication requirements, request/response schemas, error envelopes, and OpenAPI security declarations.
2. Tests prove the existing browser routes retain their paths and response shapes, including array response from `GET /api/inventory`, cookie login, and CSRF enforcement.
3. Native login tests prove the v1 CSRF flow, rate limiting, invitation-only access, opaque bearer response, and no unintended session cookie behavior.
4. Tenant-isolation tests create at least two companies and prove the same principal can only read its own `/api/v1/me` and inventory data. Client-supplied tenant hints and forged cursors cannot change that scope.
5. Pagination tests cover defaults, maximum, invalid limits, empty results, stable ties, page continuation without gaps/duplicates, malformed/tampered cursors, and changes between requests according to keyset semantics.
6. Error tests verify representative 400/401/403/404/409/422/429/500/503 responses use the v1 envelope, status matches, request ID is present in body/header, and sensitive details are redacted.
7. Run existing Python and web regression suites plus PostgreSQL integration tests. No local PostgreSQL installation is required when repository CI provides the PostgreSQL service.

## Delivery Sequence

1. Review and approve this spec.
2. Write an implementation plan that breaks down routing/allowlisting, error translation, inventory pagination, OpenAPI, client contract types, and tests.
3. Implement and verify on a fresh branch from merged `main`, leaving the native app source unchanged in this contract slice.
4. After the versioned API contract is implemented and merged, continue to the separate session renewal/revocation gate. Broader native client work remains deferred until the SaaS API foundation is ready.

## Open Implementation Detail

The implementation must select a cursor encoding and signing key source consistent with existing secret management, and preserve behavior across supported SQLite/PostgreSQL test adapters where practical. That choice must not change the externally documented properties: opaque, integrity-protected, endpoint-bound, tenant-neutral, and stable keyset continuation.
