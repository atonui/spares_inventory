# SaaS Email Change Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not begin implementation before the user approves this plan and chooses the execution method.

**Goal:** Require email ownership verification before changing a user's active sign-in email in the PostgreSQL SaaS service, notify the old address after success, and preserve legacy SQLite behavior until cutover.

**Architecture:** Add a PostgreSQL request-token table and two transactional outbox message types. A shared service owns creation, replacement, cancellation, confirmation, uniqueness checks, and notifications. Expose cookie/CSRF browser routes for the existing web profile and bearer-authenticated versioned routes for native clients; both call the same service. Confirmation is a public POST authorized only by the one-time token. Profile UI displays the current address until confirmation. Keep existing sessions active after change.

**Tech Stack:** FastAPI, Python 3.12, PostgreSQL 17, Psycopg, Pydantic v2, existing encrypted mail outbox/worker, AlpineJS, pytest, Node UI regression tests, current `/api/v1` OpenAPI builder.

**Spec:** `docs/superpowers/specs/2026-10-17-email-change-verification-design.md`

## Global Constraints

- Existing address remains active until the new address is confirmed.
- Store a separate pending request and only a hash of a single-use, one-hour token.
- Email confirmation must recheck uniqueness while holding the relevant database locks.
- Send a notice to the previous address after successful change.
- Use the encrypted mail outbox and retain its separate worker database identity.
- Retain all existing sessions after email change.
- Trim and lowercase newly proposed addresses and enforce case-insensitive uniqueness. Do not rewrite current address values automatically.
- Use the v1 routes in this plan; cookie-based web routes are additional thin aliases because the profile page currently authenticates with cookies and v1 protected endpoints require Bearer credentials.
- Rate limit change requests to 3 per authenticated account per hour. The plan recommends 5 confirmation attempts per IP per minute, matching invitation acceptance; that exact confirmation threshold is included for review because the approved design left it open.
- PostgreSQL SaaS behavior changes; SQLite keeps current direct profile-email behavior until cutover.
- Do not deploy, change production variables, provision database roles, begin account deletion, or edit existing migrations.

## Review Focus

- A stolen, leaked, expired, replayed, or superseded token must never change the account email; assert hash-only persistence and one-time consumption in Tasks 2, 3, and 6.
- Concurrent requests or confirmations must not assign one normalized email to two accounts or leave multiple pending requests; assert unique-index and lock behavior in Tasks 1, 3, and 6.
- One authenticated user must not read or cancel another user's request, including through request-supplied identity or company IDs; assert real API calls in Tasks 4 and 6.
- Mail scanners and prefetchers must not consume a token on GET; assert state remains unchanged in Task 4.
- Existing timezone/password workflows and legacy SQLite direct email editing must remain functional while PostgreSQL blocks unverified direct updates; assert compatibility in Tasks 4, 5, and 6.

---

## Pre-implementation data gate

Before applying the new expression index to any shared or production SaaS database, query for case-insensitive collisions:

```sql
SELECT lower(btrim(email)) AS normalized_email, count(*)
FROM users
GROUP BY lower(btrim(email))
HAVING count(*) > 1;
```

The migration must not silently rewrite existing emails or delete identities. If collisions exist, stop before applying that migration and obtain a separate reviewed remediation decision. Local disposable PostgreSQL test databases must also verify the unique expression index and its collision behavior.

## Important implementation detail: browser and native transports

The approved v1 contract uses Bearer authentication, while the current profile page uses a browser session cookie. Therefore the implementation must expose both of these interfaces over shared service functions:

| Transport | Routes |
|---|---|
| Browser cookie + CSRF | `POST /api/profile/email-change-requests`, `GET /api/profile/email-change-request`, `DELETE /api/profile/email-change-request` |
| Native v1 Bearer | `POST /api/v1/me/email-change-requests`, `GET /api/v1/me/email-change-request`, `DELETE /api/v1/me/email-change-request` |
| Token capability | `POST /api/auth/email-change/confirm` and `POST /api/v1/auth/email-change/confirm` |

Both confirmation paths invoke the same token-authorized operation. The confirmation page uses the browser path. The v1 OpenAPI document lists only versioned routes. The web aliases retain legacy error/CSRF conventions; native aliases retain v1 error envelopes and require explicit Bearer transport for authenticated operations.

## Task 1: Add the request schema and normalized-email uniqueness constraint

**Files:**
- Create: `backend/postgres_migrations/v0009_email_change_verification.py`
- Modify: `backend/postgres_migrations/registry.py`
- Test: `regression_tests/test_postgres_migrations.py`
- Test: `regression_tests/test_email_change_service.py`

**Interfaces:**
- Migration v0009 creates `email_change_requests` with `id`, `user_id`, `proposed_email`, `token_hash`, `delivery_suppressed`, `created_at`, `expires_at`, `consumed_at`, and `canceled_at`; account/token RLS scopes rows through transaction-local settings.
- Add a unique index on `lower(btrim(users.email))` to make case-insensitive uniqueness race-safe without rewriting existing rows. Migration application requires the collision preflight above to be clean.
- Add a unique token-hash index, user/lifecycle lookup index, and partial unique index ensuring one unconsumed, uncanceled request per user. Expired requests are canceled/replaced transactionally before a new pending request is inserted.
- The request table is global identity data, not tenant-owned inventory. It has no company ID and its application access is restricted by account/token RLS plus server-derived `user_id` in service queries. No request accepts a client-supplied user or company identifier. Occupied target addresses receive a non-deliverable placeholder for the same pending window so status cannot reveal address ownership.
- Store timestamps as canonical UTC instants, following existing temporal conventions.

- [ ] **Step 1: Write failing migration tests.** Cover migration v0009 registration/checksum immutability, request table columns/constraints, one active request per user, token-hash uniqueness, and lower/trimmed email uniqueness across differently cased addresses.
- [ ] **Step 2: Run focused tests and verify RED.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_postgres_migrations.py regression_tests/test_email_change_service.py -q`.
- [ ] **Step 3: Add append-only v0009 and register it.** Do not edit migrations v0001-v0008. The migration adds no user/email rewrites and no tenant columns.
- [ ] **Step 4: Run focused PostgreSQL tests and verify GREEN.** Confirm expression-index conflicts fail safely and the test fixture reaches migration v0009.
- [ ] **Step 5: Commit** as `feat: add SaaS email change request schema`.

## Task 2: Extend encrypted transactional mail for verification and old-address notices

**Files:**
- Modify: `backend/services/mail_outbox.py`
- Modify: `backend/services/mail_delivery.py`
- Modify: `backend/mail_worker.py`
- Create: `backend/services/email_change_mail.py`
- Modify: `backend/postgres_migrations/v0009_email_change_verification.py`
- Test: `regression_tests/test_mail_outbox.py`
- Test: `regression_tests/test_mail_delivery.py`
- Test: `regression_tests/test_email_change_mail.py`
- Test: `regression_tests/test_mail_delivery.py`

**Interfaces:**
- `enqueue_email_change_verification(conn, *, email, token, frontend_url, encryption_key, expires_at)` creates a one-time verification URL using the configured frontend base URL and enqueues `email_change_verification` with an encrypted payload.
- `enqueue_email_changed_notice(conn, *, old_email, new_email, encryption_key)` enqueues `email_changed_notice`; it contains no token.
- Mail templates validate recipient and payload shape, reject unsupported or unsafe URLs, and use generic message content that does not leak user or tenant identifiers.
- Extend the v0009 check constraint to allow `organization_invitation`, `password_reset`, `email_change_verification`, and `email_changed_notice`.
- The worker retains its existing restricted outbox-only database permissions. No grant to `users` or `email_change_requests` is added.

- [ ] **Step 1: Write failing helper, delivery, and worker tests.** Assert encryption/decryption boundary, token URL only in encrypted payload, no raw token in outbox columns, no token in old-address notice, URL validation, safe provider-independent rendering, and that expired verification links are not sent.
- [ ] **Step 2: Run the focused tests and verify RED.** Run `pytest regression_tests/test_email_change_mail.py regression_tests/test_mail_delivery.py regression_tests/test_mail_outbox.py -q`.
- [ ] **Step 3: Implement both enqueue helpers and message templates.** Reuse the configured frontend base URL and current encryption helper. Add only sanitized message types and payloads. Have the worker terminally reject an expired verification link using the encrypted payload expiry, matching password-reset handling.
- [ ] **Step 4: Run focused delivery/outbox tests.** Verify enqueue is transaction-bound and existing invitation/password-reset templates remain unchanged.
- [ ] **Step 5: Commit** as `feat: queue email change notifications`.

## Task 3: Implement single-use email change lifecycle service

**Files:**
- Create: `backend/services/email_change.py`
- Modify: `backend/services/authenticated_transactions.py` only if account-level writes need a distinct transaction helper
- Test: `regression_tests/test_email_change_service.py`
- Regression: `regression_tests/test_authenticated_transactions.py`, `regression_tests/test_session_authentication.py`

**Interfaces:**
- `request_email_change(conn, *, user_id, proposed_email, frontend_url, encryption_key, now) -> dict`: normalize by trim/lowercase, reject a case-insensitive match to the current address, safely handle an already-registered address without enumeration, cancel/supersede any prior request, create a hashed random token expiring in one hour, and enqueue verification mail in the same transaction.
- `get_pending_email_change(conn, *, user_id, now) -> dict | None`: return status, masked proposed address, and UTC expiry only; never return raw token or URL.
- `cancel_email_change(conn, *, user_id, now) -> None`: cancel the caller's pending request idempotently.
- `confirm_email_change(conn, *, token, encryption_key, now=None) -> dict`: hash the supplied token, lock the matching request and user, verify active/unexpired state, recheck normalized uniqueness, update only that user's email, mark the request consumed, and enqueue an old-address notice in the same transaction. All writes roll back together on failure.
- Confirmation returns the same generic failure for malformed, expired, canceled, superseded, replayed, or unavailable addresses. It never reveals another account's identity.
- Use only server-derived `user_id` in request/status/cancel operations. Keep sessions active after confirmation.

- [ ] **Step 1: Write failing service tests.** Cover pending state without active email change; token hashing; expiry; cancellation/replacement; replay and concurrent confirmation; case normalization and conflict; uniqueness recheck; rollback on queue failure; old-address notice; and per-user scoping.
- [ ] **Step 2: Run service tests and verify RED.** Run `pytest regression_tests/test_email_change_service.py -q` against SQLite fakes only for pure service behavior and PostgreSQL integration fixtures for locks/constraints.
- [ ] **Step 3: Implement the service with explicit transaction ownership.** Routes call it inside the authenticated account write transaction; token confirmation runs in its own PostgreSQL transaction. Do not commit within service functions.
- [ ] **Step 4: Run service and auth-transaction regressions.** Verify database rollback preserves both email and request state if either outbox insert fails.
- [ ] **Step 5: Commit** as `feat: verify SaaS email changes`.

## Task 4: Add browser and versioned API routes, errors, and OpenAPI contract

**Files:**
- Modify: `backend/routes/auth.py`
- Modify: `backend/schemas/auth.py` or create `backend/schemas/email_change.py`
- Modify: `backend/services/api_v1_openapi.py`
- Modify: `backend/services/api_v1_errors.py` only if a stable conflict code is missing
- Test: `regression_tests/test_email_change_routes.py`
- Test: `regression_tests/test_api_v1_contract.py`
- Regression: `regression_tests/test_auth_router.py`, `regression_tests/test_native_bearer_auth.py`, `regression_tests/test_sitewide_csrf.py`

**Interfaces:**
- Browser cookie/CSRF routes from the transport table call shared service functions. Browser routes preserve existing legacy error response shape.
- Native v1 routes require explicit Bearer credentials for request/status/cancel, reject cookie-only and mixed-auth use, and use the standard v1 error envelope.
- Public confirmation routes accept only a POST JSON body containing the token; GET never consumes a token. No session or CSRF cookie is required because the token is the one-time authorization capability.
- Add schemas for proposed email, token, pending status, and safe success responses. Never return raw tokens, full links, or unmasked pending addresses in errors.
- Include the four v1 routes in `_V1_PATHS` and error mapping in `backend/services/api_v1_openapi.py`; document auth, CSRF/Bearer, generic errors, rate limits, no-store behavior, and UTC expiration.
- The old `PUT /api/profile` continues timezone edits. In PostgreSQL SaaS mode, direct `email` updates through this route must fail with a clear validation response; SQLite retains existing behavior until cutover.

- [ ] **Step 1: Write failing route/OpenAPI tests.** Assert exact route allowlist methods, cookie CSRF enforcement, bearer enforcement, no-cookie v1 access, token-only confirmation, no state mutation on GET, stable v1 errors, no token leakage, and unchanged timezone update.
- [ ] **Step 2: Run route tests and verify RED.** Run `pytest regression_tests/test_email_change_routes.py regression_tests/test_api_v1_contract.py -q`.
- [ ] **Step 3: Add route aliases around the shared service.** Keep business logic out of route handlers. Apply 3/hour per-user request and 5/minute per-IP confirmation limits; responses use `Cache-Control: no-store` where token or account status is involved.
- [ ] **Step 4: Add the versioned OpenAPI definitions and PostgreSQL-only direct-email guard.** Preserve the existing SQLite profile contract and all unrelated `/api/profile` behavior.
- [ ] **Step 5: Run focused API/auth/CSRF regressions.** Verify current login, refresh, bearer, profile, and error contracts remain intact.
- [ ] **Step 6: Commit** as `feat: expose verified email change API`.

## Task 5: Add profile request/status/cancel and verification confirmation UI

**Files:**
- Modify: `static/js/pages/profile.js`
- Modify: `static/profile.html`
- Create: `static/email_change_confirmation.html`
- Create: `static/js/pages/email-change-confirmation.js`
- Test: `regression_tests/test_profile_email_change_ui.cjs`
- Test: `regression_tests/test_email_change_confirmation_ui.cjs`

**Interfaces:**
- Profile page keeps the current active email visible, has a separate proposed-email form, shows pending/masked status and expiry, and supports cancel/retry.
- The existing display-timezone form remains independent and must not create, clear, or submit an email-change request.
- The confirmation page reads the token from the URL fragment, shows an explicit confirmation action, submits it once to `/api/auth/email-change/confirm`, clears token state and removes it from the visible URL, then shows success or safe retry guidance.
- The confirmation page uses no third-party analytics/scripts and sends `Referrer-Policy: no-referrer`; token is never written to localStorage/sessionStorage or telemetry.
- UI states remain accessible: labels, keyboard operation, status announcements, loading/error messages, and double-submit protection.

- [ ] **Step 1: Write failing UI tests.** Cover pending/request/cancel states, profile timezone independence, confirmation submit-once behavior, token URL cleanup, no persistent token storage, and accessible messages.
- [ ] **Step 2: Run frontend regressions and verify RED.** Run `node regression_tests/test_profile_email_change_ui.cjs && node regression_tests/test_email_change_confirmation_ui.cjs`.
- [ ] **Step 3: Implement the profile and confirmation surfaces.** Match current design tokens; do not redesign the profile workflow.
- [ ] **Step 4: Run focused UI tests and existing frontend entrypoint/profile tests.** Ensure no regression in password and timezone flows.
- [ ] **Step 5: Commit** as `feat: add verified email change profile flow`.

## Task 6: PostgreSQL security, concurrency, and full verification

**Files:**
- Modify: `regression_tests/test_email_change_service.py`
- Modify: `regression_tests/test_email_change_routes.py`
- Modify: `regression_tests/test_tenant_isolation_matrix.py` only if required for account-scope coverage
- Modify: `docs/environment.md` only if the feature introduces a new variable (expected none)

**Required coverage:**
- Two users cannot read or cancel each other's pending requests; client-supplied user or organization IDs cannot expand scope.
- Confirmation can be performed without a logged-in session only with a valid token. Token hash is single-use and cannot be replayed under another account.
- Concurrent request/confirmation attempts preserve case-insensitive email uniqueness and cannot create duplicate active requests.
- Cookie browser writes reject missing/invalid CSRF; v1 protected routes reject cookies without Bearer; public token confirmation does not mutate on GET.
- Verification and changed-address notices are transactionally enqueued; queue/outbox/database failures leave neither a changed email nor partially consumed token.
- Sessions remain active after change, per approved decision.
- SQLite direct profile email change remains supported until SaaS cutover; PostgreSQL rejects the legacy direct email field.
- Existing invitation and password-reset flows/templates continue to pass.
- The v1 OpenAPI document accurately includes request, status, cancellation, and confirmation routes with all error responses and security requirements.

- [ ] **Step 1: Add PostgreSQL integration and security tests.** Use `postgres_schema` disposable fixtures and actual API calls; do not rely only on direct service invocation for authorization assertions.
- [ ] **Step 2: Run focused PostgreSQL CI tests.** Use `.github/workflows/postgres-tests.yml` or locally `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_email_change_service.py regression_tests/test_email_change_routes.py -q`.
- [ ] **Step 3: Fix only defects demonstrated by tests.** Keep app tenant context derived from the authenticated session and account identifiers derived from the principal.
- [ ] **Step 4: Run the complete verification suite.** Run `pytest regression_tests -q`, `node regression_tests/test_profile_email_change_ui.cjs`, `node regression_tests/test_email_change_confirmation_ui.cjs`, and the relevant frontend entrypoint tests. The GitHub PostgreSQL workflow remains the actual PostgreSQL CI gate.
- [ ] **Step 5: Run `git diff --check`, inspect the full diff and migration registry, and commit** as `test: verify SaaS email change boundaries`.

## Completion checks

- [ ] No route can directly change PostgreSQL SaaS email without consuming a valid unexpired token.
- [ ] Email change request/confirm/outbox updates are atomic and token values never appear outside encrypted delivery payload and the one-time URL.
- [ ] Case-insensitive uniqueness is enforced by PostgreSQL and existing-address collisions were checked before any shared database migration application.
- [ ] Browser and native route contracts, CSRF/Bearer rules, error behavior, and OpenAPI docs match the spec.
- [ ] Email-change confirmation page and profile pending state work without changing timezone/password flows.
- [ ] SQLite behavior remains compatible until cutover.
- [ ] No production deployment, credential change, provider call, account deletion, mobile app implementation, or unrelated SaaS work occurred.
- [ ] Request whole-branch review after implementation and tests pass. Do not merge or deploy without the user's review.
