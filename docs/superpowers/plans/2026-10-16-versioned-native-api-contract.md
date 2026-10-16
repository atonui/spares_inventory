# Versioned Native API Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a documented `/api/v1` contract for native login, profile, inventory listing, and logout while preserving the existing browser API.

**Architecture:** Add explicit v1 routes alongside existing handlers and reuse their authentication and tenant-scoped database services. Translate errors only for `/api/v1`, paginate inventory with an opaque signed keyset cursor, and publish a filtered v1 OpenAPI document. Keep legacy `/api/...` paths and payloads unchanged.

**Tech Stack:** Python 3, FastAPI, Pydantic, PostgreSQL/SQLite test adapters, pytest, existing `itsdangerous` and database SQL helpers.

**Spec:** `docs/superpowers/specs/2026-10-16-versioned-native-api-contract-design.md`

## Global Constraints

- The v1 allowlist contains only `GET /api/v1/csrf-token`, `POST /api/v1/auth/native/login`, `GET /api/v1/me`, `GET /api/v1/inventory`, and `POST /api/v1/auth/logout`.
- Tenant, membership, and role context come only from the authenticated server-side session and existing tenant transaction/RLS mechanisms.
- Existing browser `/api/...` routes, cookie behavior, CSRF behavior, error bodies, and `GET /api/inventory` bare-array response remain unchanged.
- The v1 error envelope is `{ "error": { "status", "code", "detail", "request_id" } }`; its `status` matches HTTP status and `request_id` is also returned in `X-Request-ID`.
- Inventory pagination defaults to 50 rows, caps at 100, orders by `part_number`, `store_name`, then inventory row `id`, and returns no total count.
- A cursor is opaque, integrity-protected, endpoint/order-version-bound, and never selects a tenant or grants authorization.
- Do not add refresh-token behavior, native app changes, platform-admin APIs, or unrelated routes in this slice.
- Do not add a dependency if existing FastAPI/Pydantic/`itsdangerous` facilities can meet the requirement.

## Review Focus

- **Bearer versus cookie ambiguity:** mixed credentials must continue to fail closed; v1 errors must normalize the resulting 401. Test an Authorization header plus `session_token` cookie.
- **Cross-tenant continuation:** a cursor created under one company must not expose another company's rows when replayed under a different company session. Test cursor replay across two PostgreSQL tenants.
- **Keyset ties and row changes:** duplicate part/store sort keys must neither skip nor duplicate rows; inserts between page requests follow keyset continuation semantics. Test stable tie ordering and an insertion between requests.
- **Error paths outside endpoint code:** validation, auth dependencies, rate limits, integrity errors, and unexpected errors must all use the envelope only for `/api/v1`. Test representative errors from dependency, validation, rate limiter, and server exception paths, plus a legacy-route control.
- **Secret and identifier leakage:** error details and cursors must not reveal internal exceptions, tenant IDs, or signing material. Assert sanitized error content and tampered-cursor behavior.

---

## File Map

- Modify `backend/routes/auth.py` to expose the v1 auth/profile/logout/CSRF aliases through the existing route factory and shared handler logic.
- Modify `backend/routes/inventory_reads.py` to add the v1 inventory handler while retaining the existing unpaginated web handler.
- Create `backend/services/api_v1_errors.py` for v1-only error response creation, status-to-code mapping, and safe request ID validation/generation.
- Create `backend/services/api_v1_pagination.py` for signed cursor encode/decode and inventory continuation state.
- Create `backend/schemas/api_v1.py` for v1 inventory page, pagination metadata, and error response schemas.
- Modify `backend/app_bootstrap.py` for v1 error translation middleware/handler integration without changing legacy error behavior.
- Modify `main.py` to publish the v1 OpenAPI JSON endpoint after v1 routes are registered and pass any required cursor signing configuration.
- Create `backend/services/api_v1_openapi.py` to generate a filtered OpenAPI document containing only the `/api/v1` routes and their referenced schemas/security schemes.
- Create `regression_tests/test_api_v1_contract.py` for route, auth, error, compatibility, and OpenAPI checks.
- Create `regression_tests/test_api_v1_inventory.py` for pagination and tenant-isolation integration checks.

## Task 1: V1 Error Envelope and Request IDs

**Files:**
- Create: `backend/services/api_v1_errors.py`
- Modify: `backend/app_bootstrap.py`
- Test: `regression_tests/test_api_v1_contract.py`
- Regression: `regression_tests/test_app_bootstrap.py`, `regression_tests/test_sitewide_csrf.py`

**Interfaces:**
- Produces `api_v1_error_response(request, status_code, code, detail, request_id=None) -> JSONResponse` and `api_v1_code_for_status(status_code) -> str`.
- Maps status codes to the spec's stable codes: 400 `invalid_request`, 401 `unauthenticated`, 403 `forbidden`, 404 `not_found`, 409 `conflict`, 422 `validation_error`, 423 `account_locked`, 429 `rate_limited`, 500 `internal_error`, and 503 `service_unavailable`.
- Reads an existing request ID only if it passes the selected safe format/length validation; otherwise generates an opaque ID. Return it in both `error.request_id` and `X-Request-ID`.
- `backend/app_bootstrap.py` registers exception handlers for v1 HTTP, validation, rate-limit, integrity, and unexpected errors. Each handler branches on `request.url.path.startswith("/api/v1/")`; non-v1 responses retain their existing FastAPI/SlowAPI/database shape.

- [x] **Step 1: Write failing v1 error contract tests** named `test_v1_http_errors_use_envelope_and_request_id`, `test_v1_validation_error_uses_stable_code`, `test_v1_locked_login_uses_account_locked_code`, and `test_legacy_http_errors_keep_detail_shape`. Assert matching HTTP/body status, exact envelope keys, header/body request ID equality, safe detail, 423 mapping, and unchanged legacy error shape.
- [x] **Step 2: Run the focused tests and verify failure** with `pytest regression_tests/test_api_v1_contract.py -k 'error or validation' -q`.
- [x] **Step 3: Implement v1-only error handlers** in `backend/services/api_v1_errors.py` and register them in `backend/app_bootstrap.py`. Preserve the existing exception response behavior for all non-v1 paths; normalize dependency, validation, rate-limit, handled database, and unexpected errors for v1. Preserve `Retry-After` when present.
- [x] **Step 4: Run focused and legacy bootstrap tests** with `pytest regression_tests/test_api_v1_contract.py -k 'error or validation' regression_tests/test_app_bootstrap.py regression_tests/test_sitewide_csrf.py -q`.
- [x] **Step 5: Commit** as `feat: standardize versioned api errors`.

## Task 2: Authenticated V1 Route Allowlist

**Files:**
- Modify: `backend/routes/auth.py`
- Modify: root `main.py` only if required to bind a new operation dependency; prefer existing router dependencies.
- Test: `regression_tests/test_api_v1_contract.py`
- Regression: `regression_tests/test_native_bearer_auth.py`, `regression_tests/test_auth_router.py`, `regression_tests/test_session_authentication.py`

**Interfaces:**
- Adds exactly these v1 aliases in the existing auth router factory: `GET /api/v1/csrf-token`, `POST /api/v1/auth/native/login`, `GET /api/v1/me`, and `POST /api/v1/auth/logout`.
- Each alias delegates to the existing handler/business logic and dependencies; do not copy password/session or profile query logic into a second implementation. V1 logout revokes the bearer session without emitting `Set-Cookie`; legacy browser logout continues to clear its cookie.
- Login continues to require `verify_public_csrf`; protected v1 routes require a Bearer credential and resolve it through the shared session logic. Cookie-only requests to v1 protected routes return 401; mixed cookie/Bearer credentials continue to fail closed. Existing web routes keep accepting their current cookie flow.

- [x] **Step 1: Write failing route alias tests** named `test_v1_auth_allowlist_exposes_only_expected_auth_paths`, `test_v1_csrf_login_me_logout_use_shared_auth_logic`, and `test_v1_auth_keeps_web_routes_unchanged`. Assert methods, response schema compatibility, CSRF-protected login, no cookie set by bearer login/logout, session revocation on logout, and legacy route behavior.
- [x] **Step 2: Run the focused tests and verify failure** with `pytest regression_tests/test_api_v1_contract.py -k 'auth or allowlist' -q`.
- [x] **Step 3: Register v1 aliases in `backend/routes/auth.py`** by attaching additional paths to shared endpoint callables or thin wrappers that call the same internal handler. Keep response models and native session implementation shared.
- [x] **Step 4: Run focused auth plus existing bearer/auth tests** with `pytest regression_tests/test_api_v1_contract.py -k 'auth or allowlist' regression_tests/test_native_bearer_auth.py regression_tests/test_auth_router.py regression_tests/test_session_authentication.py -q`.
- [x] **Step 5: Commit** as `feat: expose native auth under api v1`.

## Task 3: Signed Cursor Pagination for V1 Inventory

**Files:**
- Create: `backend/services/api_v1_pagination.py`
- Create: `backend/schemas/api_v1.py`
- Modify: `backend/routes/inventory_reads.py`
- Modify: `main.py` to pass a signing secret sourced from existing server configuration.
- Test: `regression_tests/test_api_v1_inventory.py`
- Regression: `regression_tests/test_inventory_read_router.py`, `regression_tests/test_tenant_isolation_matrix.py`, `regression_tests/test_tenant_rls.py`

**Interfaces:**
- `encode_inventory_cursor(secret: str, inventory_id: int) -> str` and `decode_inventory_cursor(secret: str, cursor: str) -> InventoryCursor` in `backend/services/api_v1_pagination.py`.
- `InventoryCursor` contains only the last inventory row ID and a cursor format/version marker. Resolve its sort values from the row inside the authenticated tenant transaction. Use `itsdangerous` with a dedicated salt and existing server secret; reject malformed, invalid-signature, wrong-purpose, and unsupported-version cursors with HTTP 400 and `invalid_request`.
- `InventoryPageResponse` contains `items: list[InventoryResponse]` and `page: InventoryPageMetadata`; metadata contains `limit: int` and `next_cursor: str | None`.
- Adds only `GET /api/v1/inventory`; SQL is keyset-based and runs inside `authenticated_database_transaction(..., readonly=True)`.

- [x] **Step 1: Write failing cursor unit and endpoint tests** named `test_inventory_cursor_round_trips_and_rejects_tampering`, `test_v1_inventory_default_limit_and_response_envelope`, `test_v1_inventory_limit_bounds`, `test_v1_inventory_pages_are_stable_with_duplicate_sort_keys`, and `test_legacy_inventory_remains_unpaginated_array`.
- [x] **Step 2: Run the focused tests and verify failure** with `pytest regression_tests/test_api_v1_inventory.py -q`.
- [x] **Step 3: Implement cursor signing and validation** in `backend/services/api_v1_pagination.py`, using `URLSafeTimedSerializer` or the equivalent existing `itsdangerous` API and a purpose-specific salt. Encode only the last row ID and version, not tenant/user identity; resolve sort keys inside the authenticated tenant transaction.
- [x] **Step 4: Add v1 schemas and the keyset query** in `backend/schemas/api_v1.py` and `backend/routes/inventory_reads.py`. Enforce default 50/max 100; request one extra row to determine continuation; order/filter with `(part_number, store_name, id)` and return at most `limit` rows. Keep the legacy query and its `List[InventoryResponse]` response model unchanged.
- [x] **Step 5: Run SQLite-focused pagination and legacy read tests** with `pytest regression_tests/test_api_v1_inventory.py regression_tests/test_inventory_read_router.py -q`.
- [x] **Step 6: Commit** as `feat: add cursor pagination to v1 inventory`.

## Task 4: Tenant Isolation and Error Edge Cases

**Files:**
- Modify: `regression_tests/test_api_v1_inventory.py`
- Modify: `regression_tests/test_api_v1_contract.py`
- Reuse: `regression_tests/postgres_fixtures.py`
- Reuse: existing tenant transaction/RLS services without production code changes unless a test exposes a real contract bug.

**Interfaces:**
- Use two separately seeded PostgreSQL organizations, memberships, and inventory datasets through the existing `postgres_schema` fixture.
- Exercise v1 endpoints through `TestClient` with valid bearer sessions; do not assert tenant isolation by directly calling endpoint functions.

- [x] **Step 1: Add PostgreSQL integration tests** named `test_v1_inventory_is_scoped_to_authenticated_company`, `test_v1_cursor_replay_cannot_cross_company_scope`, `test_v1_client_tenant_hints_do_not_expand_scope`, `test_v1_platform_admin_without_membership_cannot_read_inventory`, and `test_v1_errors_redact_internal_details`.
- [ ] **Step 2: Run the PostgreSQL integration tests** in `.github/workflows/postgres-tests.yml`, which provisions PostgreSQL 17 and runs `pytest regression_tests -q`. For local targeted runs, provide `TEST_DATABASE_URL` pointing to a disposable database whose name ends in `_test`; the fixture rejects other database names.
- [ ] **Step 3: Fix only demonstrated contract defects** in route transaction setup or error/cursor handling; preserve the authenticated principal and transaction-local RLS as the only tenant authority.
- [ ] **Step 4: Rerun tenant integration tests** and existing `regression_tests/test_tenant_isolation_matrix.py`, `regression_tests/test_tenant_rls.py`, and `regression_tests/test_authenticated_transactions.py`.
- [x] **Step 5: Commit** as `test: verify v1 tenant isolation and cursor safety`.

## Task 5: V1 OpenAPI Document and Full Verification

**Files:**
- Create: `backend/services/api_v1_openapi.py`
- Modify: `main.py`
- Modify: `backend/schemas/api_v1.py` and route response metadata as needed.
- Modify: `regression_tests/test_api_v1_contract.py`
- Regression: complete Python regression suite and existing web/mobile API tests.

**Interfaces:**
- Expose `GET /api/v1/openapi.json` as a no-cache JSON document with `info.version == "1.0.0"`, only the five allowlisted paths, the `BearerAuth` HTTP Bearer scheme, route schemas, standard error responses, and pagination parameter/response documentation.
- `build_v1_openapi_document(full_document: dict) -> dict` filters paths to `/api/v1/...` and retains only referenced schemas and security schemes. The combined `/openapi.json` remains available and backward compatible.

- [x] **Step 1: Write failing OpenAPI tests** named `test_v1_openapi_is_filtered_and_versioned`, `test_v1_openapi_documents_bearer_and_login_csrf`, and `test_v1_openapi_includes_pagination_and_standard_errors`. Assert excluded platform/admin and legacy paths are absent and all v1 paths are present.
- [x] **Step 2: Run the focused OpenAPI tests and verify failure** with `pytest regression_tests/test_api_v1_contract.py -k openapi -q`.
- [x] **Step 3: Implement the filtered OpenAPI builder and route** in `backend/services/api_v1_openapi.py` and `main.py`. Preserve the current app OpenAPI output and make only the v1 document's cache behavior explicit (`Cache-Control: no-cache`).
- [ ] **Step 4: Run the complete verification suite**: `pytest -q`, plus the repository's PostgreSQL CI test command. Confirm legacy route schemas, login, CSRF, and inventory array tests pass unchanged.
- [ ] **Step 5: Run `git diff --check`, inspect the final diff, and commit** as `docs: publish versioned native api contract`.

## Completion Check

- [x] All five v1 operations exist and no additional native/platform route is exposed.
- [x] V1 errors use the documented envelope and request IDs; legacy route error contracts are unchanged.
- [x] Inventory pagination meets the exact bounds, ordering, cursor, and tenant rules in the spec.
- [x] The v1 OpenAPI document contains only the allowlisted paths and accurately documents auth, errors, and pagination.
- [ ] PostgreSQL tests prove tenant isolation, cross-company cursor replay safety, and no platform-admin inventory access.
- [ ] Existing browser and regression tests pass; no mobile app source changes are included.
