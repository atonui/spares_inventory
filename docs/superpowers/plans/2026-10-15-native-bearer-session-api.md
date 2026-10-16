# Native Bearer Session API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opaque native bearer authentication backed by PostgreSQL server-side sessions, preserving the existing browser cookie + CSRF contract and deriving all tenant and role context server-side.

**Follow-on:** The API-auth slice is merged in PR #138. Native route versioning and secure token renewal were intentionally deferred here; the current client signs in again after expiry. Track those prerequisites, account/data deletion, privacy, review access, and store gates in [`2026-10-16-saas-mobile-store-readiness.md`](2026-10-16-saas-mobile-store-readiness.md).

**Architecture:** Hash PostgreSQL session credentials at rest and resolve either a cookie or bearer credential through the existing principal/session lifecycle. Add a PostgreSQL-only native login endpoint; use a shared request credential helper for authentication and transaction-time revalidation. Keep cookie-authenticated writes behind CSRF and permit bearer-authenticated writes to omit CSRF only after the bearer credential has been validated. Document the contract in OpenAPI and add regression/integration coverage. SQLite behavior and client applications remain unchanged.

**Tech Stack:** Python, FastAPI, psycopg, PostgreSQL 17 migrations, pytest, existing JavaScript regression suite.

**Spec:** `docs/superpowers/specs/2026-10-15-native-bearer-session-api-design.md`

## Global Constraints

- Do not edit an already applied PostgreSQL migration; add the next checksummed migration after v0004.
- Preserve existing web login/logout/session response and cookie behavior.
- Do not accept tenant, role, or platform-admin claims from bearer credentials or request bodies.
- Never persist, log, audit, or return raw credentials beyond the successful native-login response.
- Do not alter SQLite authentication behavior or introduce local PostgreSQL setup requirements.
- Keep `/api` paths as-is; do not add `/api/v1` aliases, JWTs, refresh tokens, or mobile UI.
- Test migration preservation against the PostgreSQL 17 service in GitHub Actions.

## Review Focus

1. Existing active sessions remain usable across the raw-token-to-hash migration; the migration is transactional and indexed uniquely.
2. Bearer requests cannot bypass CSRF based on header presence alone; invalid or mixed cookie/bearer credentials fail closed.
3. Native logout, expiry, password changes, account archival, and membership revocation all use the same server-side session lifecycle.
4. Tenant and platform-admin boundaries are unchanged; no client-supplied tenant or role data influences authorization.
5. Browser and SQLite contracts remain compatible, while OpenAPI accurately documents the native contract.

## File Responsibility Map

- `backend/postgres_migrations/v0005_hashed_sessions.py` — checksummed migration definition and SQL that hashes existing session credentials, uniquely indexes hashes, and removes raw session-token storage after successful backfill.
- `backend/postgres_migrations/registry.py` — register v0005 without changing existing migration entries.
- `backend/services/session_credentials.py` — credential hashing and extraction of exactly one cookie or syntactically valid bearer credential; reject mixed credentials.
- `backend/services/principals.py` — resolve PostgreSQL session principals by credential hash while keeping authorization server-derived.
- `backend/services/session_authentication.py` — authenticate and update activity by hash; retain SQLite branch behavior.
- `backend/services/authenticated_transactions.py`, `backend/services/tenant_context.py`, `backend/services/platform_transactions.py` — transaction-time revalidation against the same credential/principal.
- `main.py` — request authentication, shared credential access, authenticated CSRF dependency, and router dependency wiring.
- `backend/routes/auth.py` — native login, bearer-compatible session operations/logout, and web compatibility.
- `backend/routes/*.py` (all authenticated routes currently reading `request.cookies`) — replace direct cookie reads used for authenticated work with the shared helper; retain public/unauthenticated CSRF behavior.
- `backend/postgres_migrations/v0005_hashed_sessions.py` and `regression_tests/test_postgres_migrations.py` — migration preservation and no-raw-token assertions.
- `regression_tests/test_session_credentials.py`, `test_session_authentication.py`, `test_authenticated_transactions.py`, `test_auth_router.py`, `test_sitewide_csrf.py`, `test_tenant_isolation_matrix.py` — focused credential, auth, transaction, CSRF, and tenant tests.
- `regression_tests/test_native_bearer_auth.py` — native endpoint, revocation, and OpenAPI contract coverage.

## Implementation Tasks

### Task 1: Add the credential hash migration and primitive

**Files:** `backend/services/session_credentials.py`, `backend/postgres_migrations/v0005_hashed_sessions.py`, `backend/postgres_migrations/registry.py`, `regression_tests/test_session_credentials.py`, `regression_tests/test_postgres_migrations.py`.

- [ ] **Step 1: Add failing tests for deterministic hashing and credential parsing.** Assert SHA-256 hashes are stable and distinct from raw values; cookie-only and bearer-only extraction work; malformed bearer and simultaneous cookie + bearer inputs fail with 401. Run `pytest regression_tests/test_session_credentials.py -q` and confirm failure.
- [ ] **Step 2: Implement credential helpers.** Add a single hashing function and request credential parser with explicit transport metadata. Do not log input values. Use constant-time-independent hash lookup; tokens are high entropy, so SHA-256 is appropriate.
- [ ] **Step 3: Add the next migration.** In one transaction, add nullable `session_token_hash`, backfill every existing `sessions.session_token` as lowercase hex SHA-256, set NOT NULL, add a unique index, clear obsolete `users.session_token` values, then drop the raw `sessions.session_token` column. The migration must abort on null/collision/backfill errors rather than discard sessions.
- [ ] **Step 4: Register and test migration behavior.** Extend Postgres migration tests to seed an active session, apply v0005, verify the old raw credential still resolves through its computed hash, and verify no raw session column/value remains. Preserve checksums and order of v0001-v0004. Run `pytest regression_tests/test_postgres_migrations.py -q` through the existing PostgreSQL 17 CI service.
- [ ] **Step 5: Run focused tests and commit.** Run `pytest regression_tests/test_session_credentials.py regression_tests/test_postgres_migrations.py -q`; commit as `feat: hash postgres session credentials`.

### Task 2: Resolve cookie and bearer credentials through the shared session lifecycle

**Files:** `backend/services/principals.py`, `backend/services/session_authentication.py`, `backend/services/authenticated_transactions.py`, `backend/services/tenant_context.py`, `backend/services/platform_transactions.py`, `main.py`, `regression_tests/test_session_authentication.py`, `regression_tests/test_authenticated_transactions.py`.

- [ ] **Step 1: Add failing session tests.** Cover cookie and bearer credentials resolving the same principal, lookup by hash, expiry/revocation/archive/membership revalidation, and mixed-credential rejection. Include a transaction test proving a request authenticated as one session cannot revalidate with another. Run the focused test files and confirm failures.
- [ ] **Step 2: Move PostgreSQL lookups to hash.** Make `resolve_principal` hash the presented credential and query `session_token_hash`. Update activity timestamps and session validation to use the hash too. Keep SQLite functions and SQL unchanged.
- [ ] **Step 3: Wire the shared extractor into request auth.** Make `get_current_user` read the shared cookie-or-bearer credential; missing/malformed/conflicting credentials return 401. Maintain the current return value and dependency contract consumed by route factories.
- [ ] **Step 4: Make transaction revalidation use the same credential.** Update authenticated read/write and platform transaction helpers to pass the exact extracted credential into Postgres revalidation. Continue deriving RLS and roles exclusively from the principal loaded in that transaction.
- [ ] **Step 5: Verify session lifecycle regressions and commit.** Run `pytest regression_tests/test_session_authentication.py regression_tests/test_authenticated_transactions.py regression_tests/test_session_access.py -q`; commit as `feat: resolve bearer credentials as server sessions`.

### Task 3: Add authenticated bearer-aware CSRF without weakening public mutations

**Files:** `main.py`, `backend/routes/auth.py`, `backend/routes/invitations.py`, route factory modules with unsafe methods, `regression_tests/test_sitewide_csrf.py`, `regression_tests/test_session_write_routes.py`.

- [ ] **Step 1: Add failing CSRF cases.** Assert valid cookie writes require CSRF; validated bearer writes can omit it; invalid bearer cannot omit it; cookie + bearer is rejected; login, password reset, and invitation acceptance remain CSRF-protected. Run focused tests and confirm failures.
- [ ] **Step 2: Implement a separate authenticated CSRF dependency.** Preserve the existing `verify_csrf` for unauthenticated writes. Add a dependency that shares/caches the authenticated principal resolution and skips CSRF only when that validated request used bearer transport; otherwise enforce the existing token check. Header presence alone must never affect the result.
- [ ] **Step 3: Wire only authenticated unsafe routes.** Give protected route factories the authenticated CSRF dependency for create/update/delete actions. Leave login, reset, invitation acceptance, and other public mutation handlers on the original CSRF dependency. Read-only routes receive no CSRF bypass logic.
- [ ] **Step 4: Verify route coverage and commit.** Run `pytest regression_tests/test_sitewide_csrf.py regression_tests/test_session_write_routes.py -q`; add a route-level assertion that the expected public mutations still require CSRF. Commit as `feat: allow validated bearer writes without csrf`.

### Task 4: Add native login and replace authenticated direct cookie reads

**Files:** `backend/routes/auth.py`, applicable auth schema module, `main.py`, all route modules with authenticated `request.cookies.get("session_token")` reads, `regression_tests/test_auth_router.py`, `regression_tests/test_native_bearer_auth.py`, `regression_tests/test_tenant_isolation_matrix.py`.

- [ ] **Step 1: Add failing native-login tests.** Cover PostgreSQL-only availability; existing password, lockout, rate limit, active-account and remember-me expiry behavior; response includes one opaque credential and expiry; response sets no session cookie; web login continues to set only its current cookie and returns no credential. Run focused tests and confirm failure.
- [ ] **Step 2: Implement `POST /api/auth/native/login`.** Reuse the current credential verification and lockout/rate-limit policy. Create the same server-side session with a fresh high-entropy raw credential, persist only its hash in PostgreSQL, and return the raw credential once in the native response. Do not set a session cookie. Require existing login CSRF.
- [ ] **Step 3: Make session operations bearer-compatible.** Use the shared credential for current-session identification, logout/revocation, session listing, and session revocation. Native logout revokes the server record; browser logout still clears the cookie. Ensure raw credentials never appear in list/profile responses.
- [ ] **Step 4: Replace route cookie reads.** Audit the authenticated route modules and replace cookie reads used for transaction-time auth, activity/audit attribution, or current-session selection with the shared resolver. Preserve cookie access only where the endpoint must explicitly set/delete the browser cookie. Add a source audit test or command-level assertion so new business routes do not reintroduce direct reads.
- [ ] **Step 5: Verify tenant and auth behavior, then commit.** Run `pytest regression_tests/test_auth_router.py regression_tests/test_native_bearer_auth.py regression_tests/test_tenant_isolation_matrix.py regression_tests/test_session_write_routes.py -q`; commit as `feat: add native bearer session login`.

### Task 5: Document OpenAPI and verify the full contract

**Files:** `main.py`, `backend/routes/auth.py`, `regression_tests/test_native_bearer_auth.py`, `docs/` API/auth documentation if an existing API contract document is present.

- [ ] **Step 1: Add failing OpenAPI assertions.** Assert the OpenAPI document includes an HTTP Bearer scheme, opaque server-managed credential description, native login success response fields, and relevant 401/403 responses without changing existing paths or web schemas.
- [ ] **Step 2: Add OpenAPI security metadata.** Declare the bearer security scheme and apply it only to authenticated routes while documenting cookie support and native login's CSRF requirement. Do not globally mark public login/reset endpoints as bearer-protected.
- [ ] **Step 3: Complete cross-platform client contract docs.** Describe Authorization header use, HTTPS, secure credential storage (Keychain/Keystore), no JWT/refresh endpoint, re-login after expiry, and server-side tenant derivation. Keep docs scoped to API foundation; no mobile app implementation.
- [ ] **Step 4: Run complete verification.** Run `pytest regression_tests -q` and `node --test regression_tests/*.cjs`; run `python -m compileall -q backend main.py` and `git diff --check`. Confirm CI uses its PostgreSQL 17 service and no local database installation is needed. Inspect migration output and captured logs for raw-token leakage.
- [ ] **Step 5: Commit final docs and OpenAPI changes.** Commit as `docs: document native bearer session api` (or include docs in the preceding implementation commit if that matches repository convention).

## Completion Checklist

- [ ] Migration is additive, checksummed, transactional, preserves valid sessions, and removes raw PostgreSQL session-token storage.
- [ ] Cookie and bearer credentials resolve to the same server-side principal and revalidate consistently during reads/writes.
- [ ] Only a validated bearer request can omit CSRF; web and unauthenticated mutation protections are intact.
- [ ] Native login/logout/session management works on PostgreSQL; web behavior and SQLite regressions remain intact.
- [ ] Tenant isolation, platform-admin separation, token redaction, and OpenAPI contract are verified.
- [ ] Full Python/JavaScript tests and CI PostgreSQL integration pass; branch is ready for user review and PR merge.
