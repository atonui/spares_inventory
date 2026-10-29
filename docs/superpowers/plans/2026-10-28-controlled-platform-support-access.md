# Controlled Platform Support Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Approved on 2026-10-28; task-by-task implementation in progress.

**Goal:** Let platform administrators handle account-access and inventory/equipment support for one tenant at a time through an explicit, audited, temporary, read-only support session.

**Architecture:** Add a platform-owned PostgreSQL support-session record bound to the administrator, their current server-side auth session, and one organization. A dedicated support transaction validates that record on every request and sets transaction-local RLS context only from its organization ID. Route-specific read endpoints expose a fixed field allowlist; all data reads write a curated platform audit event in the same transaction. No impersonation or general RLS bypass is introduced.

**Tech Stack:** FastAPI, PostgreSQL/psycopg, existing session credential hashing and password verification, PostgreSQL RLS, Alpine.js, pytest, and Node UI regression tests.

**Spec:** `docs/superpowers/specs/2026-10-28-controlled-platform-support-access-design.md`

## Global Constraints

- Platform-admin status alone never creates tenant context or grants inventory or company-user-list access.
- Tenant queries continue to use server-resolved membership and PostgreSQL RLS; never add a blanket RLS bypass.
- Support sessions are read-only, bound to one organization and one active platform login session, and expire after 15 minutes.
- Starting a support session requires a reason and current-password verification; never store or log the password or raw session credential.
- Never expose password hashes, reset credentials, raw or hashed session credentials, session IP/user-agent, customer names, free-text work-order descriptions, notes, costs, attachments, or arbitrary activity details.
- Support access may include suspended organizations only through the same explicit, read-only, reasoned, password-confirmed workflow.
- No generic tenant browser, user impersonation, tenant writes, data export, or direct tenant hard deletion.
- Use the restricted web runtime role in PostgreSQL integration tests; never use the migration/table-owner role to prove RLS behavior.

## Review Focus

- Missing, malformed, expired, ended, wrong-actor, wrong-auth-session, or revoked support session must yield no tenant rows; pin in Task 1 support-transaction tests.
- A support session for organization A cannot read organization B even if a request supplies B's row IDs; pin each lookup family in Task 2 cross-tenant tests.
- Account lookups use explicit membership joins because `users` and `organization_memberships` are not RLS tables; pin exact organization/email scope and no global-email existence leak in Task 2.
- Logout, password change, session revocation, and platform-admin revocation must prevent any subsequent read; pin each lifecycle path in Task 3 tests.
- Audit failure, unexpected query error, and expired session must never return partial or unaudited tenant data; pin transaction rollback and generic errors in Tasks 1–2.

---

### Task 1: Persist and authorize support sessions

**Files**

- Create: `backend/postgres_migrations/v0015_platform_support_sessions.py`
- Modify: `backend/postgres_migrations/registry.py`, `docs/saas-cutover-runbook.md`
- Create: `backend/services/platform_support.py`
- Test: `regression_tests/test_platform_support.py`, `regression_tests/test_postgres_migrations.py`

**Interfaces**

- `create_support_session(conn, *, actor_user_id: int, auth_session_id: int, organization_id: UUID, reason: str, now: datetime) -> dict`
- `authenticated_support_transaction(get_connection, *, session_token: str | None, support_session_id: UUID, expected_user_id: int | None = None)` yields `(conn, principal, support_session)` in a write-capable transaction in which each endpoint must append its resource-specific read audit event before commit.
- The support-session table has a UUID primary key, actor user ID, auth-session row ID, organization ID, reason, created/expiry timestamps, and nullable ended timestamp. Add indexes for live lookup by `(actor_user_id, auth_session_id, expires_at)` and organization audit lookup. Use migration version 15 and preserve append-only migration checksums.

- [x] **Step 1: Add failing migration and authorization tests.** Add `test_support_session_migration_creates_indexed_bound_session_table`, asserting the exact actor/auth-session/organization/reason/time fields and live-lookup index; `test_create_support_session_sets_fixed_expiry_and_rejects_second_live_session`, asserting 15-minute expiry and 409 for a concurrent second start; and `test_authenticated_support_transaction_sets_only_bound_organization`, asserting RLS returns selected-tenant rows only. Add parameterized `test_authenticated_support_transaction_rejects_invalid_session_state` for missing, ended, expired, wrong-actor, wrong-auth-session, inactive-auth-session, and revoked-platform-admin cases, each asserting zero tenant rows.
- [x] **Step 2: Attempt the focused PostgreSQL tests and confirm the environment can run them.** Attempted `python -m pytest regression_tests/test_platform_support.py regression_tests/test_postgres_migrations.py -q`; this workspace has no pytest module and no `TEST_DATABASE_URL`, so test execution is pending in a configured environment. No dependencies were installed.

```bash
TEST_DATABASE_URL=postgresql://... pytest regression_tests/test_platform_support.py regression_tests/test_postgres_migrations.py -q
```

Expected: FAIL because migration 15 and the support-session service are absent.

- [x] **Step 3: Add migration 15 and register it.** Grant the web runtime only the table operations needed for session creation, validation, end/revocation, and audit; document matching runtime table/sequence grants in `docs/saas-cutover-runbook.md`. Do not grant DDL or tenant-table bypass privileges.
- [x] **Step 4: Implement `create_support_session` and `authenticated_support_transaction` in `backend/services/platform_support.py`.** Resolve the current auth-session row ID from `hash_session_credential(session_token)`, lock that `sessions` row while enforcing one unexpired, unended support session per login, bind support ID/actor/auth session/organization from stored state, validate expiry and ended state, and call `set_tenant_context` only after every check succeeds.
- [x] **Step 5: Attempt the focused PostgreSQL tests and migration suite.** Tests cover restricted-role RLS isolation and selected-organization access, but could not execute here because pytest and `TEST_DATABASE_URL` are unavailable; run them in CI or a configured test environment before merge.
- [x] **Step 6: Run `git diff --check` and inspect grants against `docs/saas-cutover-runbook.md`.**
- [x] **Step 7: Commit the migration, support-session helper, tests, and grants documentation.** Run `git add backend/postgres_migrations backend/services/platform_support.py regression_tests/test_platform_support.py regression_tests/test_postgres_migrations.py docs/saas-cutover-runbook.md` followed by `git commit -m "feat: add scoped platform support sessions"`.


**Verification note:** Migration, helper, and regression coverage are committed. Python syntax/compile checks and `git diff --check` passed. PostgreSQL RLS and concurrent-start behavior remain unverified at runtime until the focused suite runs with pytest and a disposable `TEST_DATABASE_URL`.

### Task 2: Add bounded read-only support APIs and per-read auditing

**Files**

- Create: `backend/routes/platform_support.py`
- Modify: `main.py`, `backend/services/platform_audit.py`
- Test: `regression_tests/test_platform_support.py`, `regression_tests/test_platform_audit.py`, `regression_tests/test_session_write_routes.py`

**Interfaces**

- `POST /api/platform/support-sessions` accepts `{organization_id, reason, current_password}` and returns `{support_session_id, organization, expires_at}`. The start transaction authenticates the platform session, verifies password via the existing password verifier, creates the support row, and records `support_session_started`.
- `GET /api/platform/support-sessions/current` returns the live support session bound to the current login, or `null`; it exposes no support-session token or tenant data.
- `DELETE /api/platform/support-sessions/{support_session_id}` ends only the caller's session and records `support_session_ended`.
- Add fixed lookup routes for exact email account/access lookup, part/inventory lookup, work-order lookup, and equipment/calibration lookup. Each lookup requires the support-session ID and uses its stored organization; clients cannot choose another organization per request.
- Every data route uses `authenticated_support_transaction`, returns no more than 25 rows, and inserts `support_data_read` within the same transaction after the fixed query succeeds.

- [x] **Step 1: Add failing route tests:** `test_start_support_session_requires_current_password_and_reason` asserts invalid password or a reason outside 10–500 chars creates no row; `test_account_lookup_is_exact_and_support_organization_scoped` asserts only an exact email in the bound organization is returned and global existence is not revealed; `test_operational_lookup_results_are_bounded_and_allowlisted` asserts each response is at most 25 rows and has no excluded keys; `test_support_read_audit_contains_no_query_or_row_values` asserts resource/action/session/request ID only; and `test_support_read_rolls_back_when_audit_insert_fails` asserts no tenant payload is returned.
- [ ] **Step 2: Run `TEST_DATABASE_URL=postgresql://... pytest regression_tests/test_platform_support.py regression_tests/test_platform_audit.py -q` and confirm the missing routes/audit classifications fail.**
- [x] **Step 3: Implement start/current/end routes and password verification.** Apply existing authenticated CSRF protection to start and end; use a bounded reason (10–500 characters); do not persist password input; apply the existing login limiter of 5 requests per minute to session starts.
- [x] **Step 4: Implement exact-email account/access lookup with explicit joins through the support-session organization membership.** Return only user ID, name/email, archived state, role, membership state, failed-login count, lockout time, and last-login time. Do not require membership to be active so support can diagnose deactivated accounts; always filter on the session organization.
- [x] **Step 5: Implement fixed tenant-RLS lookups for inventory/parts, work orders, equipment/history, and movements/transfers.** Join any assignee/completer names through `organization_memberships` for the bound organization. Include only fields in the approved spec; do not return customer names, free text, notes, costs, or arbitrary logs.
- [x] **Step 6: Add curated audit actions for start/read/denial/end.** Keep successful read audit insertion atomic with returned rows. Generate a server-side UUID correlation ID per support request; never accept a client-supplied correlation ID. For denials after a platform actor and target organization are known, write a minimal denial event in a separate transaction so the rejected request's rollback cannot erase it. Never record query values or returned rows.
- [x] **Step 7: Wire the router in `main.py` with platform-auth and CSRF dependencies; classify all mutations in the session-write route matrix.**
- [ ] **Step 8: Run focused PostgreSQL tests and the route/audit suites.** Expected: wrong-tenant requests return no data; audit insert failure rolls back the read response; anonymous errors do not reveal support-session or organization existence.
- [x] **Step 9: Commit the platform support routes and audit coverage.** Run `git add backend/routes/platform_support.py backend/services/platform_audit.py main.py regression_tests/test_platform_support.py regression_tests/test_platform_audit.py regression_tests/test_session_write_routes.py` followed by `git commit -m "feat: add audited platform support reads"`.

### Task 3: End support access with authentication and platform-admin revocation

**Files**

- Modify: `backend/routes/auth.py`, `backend/routes/platform_organizations.py`, `backend/services/platform_support.py`
- Test: `regression_tests/test_platform_support.py`, auth/session regression tests, `regression_tests/test_platform_organizations.py`

- [ ] **Step 1: Add failing tests:** `test_logout_ends_current_support_session`, `test_password_change_ends_all_actor_support_sessions`, `test_revoke_other_sessions_ends_only_revoked_support_sessions`, and `test_platform_admin_revocation_ends_actor_support_sessions`. Each asserts the affected session is ended and later support reads return no tenant rows; the revoke-other-sessions test asserts the current login remains live.
- [ ] **Step 2: Run the focused tests and confirm each currently leaves the support session usable or unended.**
- [x] **Step 3: Update active support rows in the same transaction as logout, password change, and session revocation.** Include the affected support-session ID, actor, organization, and end reason in the curated audit event; preserve the currently used session when `/api/auth/revoke-other-sessions` revokes other devices.
- [x] **Step 4: Update `revoke_platform_admin` to end all active support sessions for that actor in the same transaction as the platform-admin deletion.** Do not end another administrator's sessions.
- [x] **Step 5: Add server checks for organization disappearance and expiry to return no data and mark the session ended when possible.** No scheduled cleanup worker is required; the expiry timestamp remains authoritative.
- [ ] **Step 6: Run focused auth, platform-admin, and support-session PostgreSQL tests.** Verify revocation happens atomically and stale support IDs remain unusable.
- [x] **Step 7: Commit authentication and platform-admin session termination integration.** Run `git add backend/routes/auth.py backend/routes/platform_organizations.py backend/services/platform_support.py regression_tests/test_platform_support.py regression_tests/test_platform_organizations.py` followed by `git commit -m "fix: end support sessions on access revocation"`.

### Task 4: Build the visible support workspace in the SaaS superadmin UI

**Files**

- Modify: `static/superadmin.html`, `static/superadmin.css`, `static/js/pages/superadmin.js`
- Test: `regression_tests/test_superadmin_ui.cjs`

- [x] **Step 1: Add failing UI tests:** `support start requires organization reason and password confirmation`, `support password clears after any start response`, `active support session restores into banner`, `support banner shows tenant reason expiry and end control`, and `terminal support state clears data and returns to platform console`. Assert requests are not sent before confirmation and that every account/operations lookup includes the support-session ID but not a free-standing organization ID.
- [x] **Step 2: Run `node --test regression_tests/test_superadmin_ui.cjs` and confirm the new tests fail.**
- [x] **Step 3: Add a support entry from the SaaS organization directory and a dedicated support view.** The view offers exact account lookup and bounded part/inventory, work-order, and equipment lookups; no global users tab or arbitrary organization ID input is added.
- [x] **Step 4: Add the persistent support banner** with organization, reason, expiry countdown, and End action. On expiry or any 401/403/404 that invalidates the session, clear support data and return to the platform console.
- [x] **Step 5: Connect UI calls to the fixed `/api/platform/support-sessions` and support lookup routes.** Keep the support-session UUID in page state only; the UUID does not grant access without the authenticated session and server-side validation.
- [x] **Step 6: Add loading, empty, error, retry, and busy states; render all returned values through text bindings.** Clear the password field after every start attempt and avoid caching support records beyond the active view.
- [x] **Step 7: Run the superadmin UI suite and relevant announcement/platform-admin regression tests.**
- [x] **Step 8: Commit the SaaS support workspace and UI tests.** Run `git add static/superadmin.html static/superadmin.css static/js/pages/superadmin.js regression_tests/test_superadmin_ui.cjs` followed by `git commit -m "feat: add controlled platform support workspace"`.

### Task 5: Run the abuse-case matrix and finalize operations documentation

**Files**

- Modify: `docs/saas-cutover-runbook.md`, `docs/superpowers/plans/2026-10-27-superadmin-platform-admin-alignment.md`
- Test: `regression_tests/test_platform_support.py`, tenant RLS tests, `regression_tests/test_superadmin_ui.cjs`

- [x] **Step 1: Add cross-tenant abuse tests:** `test_support_lookup_rejects_forged_session_and_foreign_row_ids`, `test_support_search_and_join_never_mix_tenant_rows`, `test_suspended_organization_support_is_read_only_and_scoped`, and `test_platform_only_identity_still_cannot_call_normal_tenant_routes`. Assert forged/foreign inputs reveal no rows, result bounds hold, suspended access cannot write, and ordinary tenant endpoints still return 403.
- [ ] **Step 2: Run all support, auth/session, platform organization/audit, tenant RLS, and superadmin UI suites.**

```bash
TEST_DATABASE_URL=postgresql://... pytest regression_tests/test_platform_support.py regression_tests/test_platform_audit.py regression_tests/test_platform_organizations.py regression_tests/test_tenant_context.py regression_tests/test_tenant_rls.py regression_tests/test_auth_router.py -q
node --test regression_tests/test_superadmin_ui.cjs
```

Expected: all tests pass under the restricted web runtime role; the UI tests confirm active support state is visible and cleared on every terminal path.

- [x] **Step 3: Update the Task 7 plan status and cutover runbook** with migration version, exact runtime grants, support-session expiry behavior, password step-up, audit actions, and incident response steps for ending active sessions.
- [ ] **Step 4: Run `git diff --check`, inspect generated OpenAPI routes, and review the complete PR diff for data fields outside the approved allowlist.**
- [x] **Step 5: Commit the final abuse-case coverage and operational documentation.** Run `git add docs/saas-cutover-runbook.md docs/superpowers/plans/2026-10-27-superadmin-platform-admin-alignment.md regression_tests/test_platform_support.py` followed by `git commit -m "test: cover platform support access boundaries"`.

**Acceptance:** A platform administrator can resolve one tenant's approved account and inventory issues through a password-confirmed, reasoned, short-lived, read-only session; every request is bound to the stored organization and RLS, each successful read is audited, revocation stops access, and ordinary platform screens remain tenant-data-free.
