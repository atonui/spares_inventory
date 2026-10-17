# Mail Worker Database Role Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent the SaaS web runtime from reading mail recipient addresses and encrypted payloads while preserving transactional enqueueing, aggregate platform mail counts, and worker delivery.

**Architecture:** The web process keeps `DATABASE_URL` and receives column-level enqueue privileges plus read access to a counts-only view. The mail worker uses a distinct `MAIL_WORKER_DATABASE_URL` role with access only to the global outbox; the migration identity remains separate. PostgreSQL migrations create the aggregate view, while deployment runbooks provision credentials and grants.

**Tech Stack:** Python, FastAPI, psycopg 3, PostgreSQL 17, pytest, immutable PostgreSQL migrations.

**Spec:** `docs/superpowers/specs/2026-10-17-mail-worker-database-role-design.md`

## Global Constraints

- “Require `MAIL_WORKER_DATABASE_URL` when starting the mail worker. Missing or blank configuration must stop startup before opening a database connection or claiming mail. The worker must not fall back to `DATABASE_URL`.”
- “The web role must not have table-level `SELECT`, `UPDATE`, or `DELETE` rights on `mail_outbox`.”
- “Add the non-parameterized view `platform_mail_outbox_counts`, exposing exactly one row with integer columns `pending` and `failed`”.
- “Role creation, passwords, and login credentials remain environment provisioning responsibilities, not application migrations.”
- “Do not edit Railway variables, create live database roles, provision services, or launch the worker as part of this code change.”
- “The repository currently documents Railway as SQLite-backed.”

## Review Focus

1. `MAIL_WORKER_DATABASE_URL` is missing or blank while `DATABASE_URL` is set: worker startup fails before opening any connection. Test in Task 3.
2. The web role tries to read recipient or payload columns or query individual outbox rows: PostgreSQL denies access. Test in Task 2.
3. The web role performs a first and repeated idempotent enqueue with `RETURNING id` under only the documented column grants. Test in Task 2.
4. The outbox is empty or contains mixed statuses: the counts view returns exactly one row with only the two documented counts. Test in Task 1.
5. The worker processes queued mail but tries to read unrelated identity, session, invitation, platform, or inventory tables: PostgreSQL denies access. Test in Task 3.

---

## File Map

- Create `backend/postgres_migrations/v0007_mail_outbox_counts.py` for the immutable aggregate view migration.
- Modify `backend/postgres_migrations/registry.py` to register migration 7.
- Modify `backend/routes/platform_organizations.py` to read the aggregate view.
- Modify `backend/mail_worker.py` to require and use the worker-only database URL.
- Modify `regression_tests/test_postgres_migrations.py`, `regression_tests/test_platform_organizations.py`, and `regression_tests/test_invitation_routes.py` for the view and web-role grants.
- Modify `regression_tests/test_mail_delivery.py` and create `regression_tests/test_mail_database_roles.py` for worker configuration and role isolation.
- Modify `docs/environment.md` and `docs/saas-cutover-runbook.md` to document the three connection identities and exact role grants.
- `.github/workflows/postgres-tests.yml` already runs the full PostgreSQL regression suite; confirm the new tests are included without changing the workflow unless the current command excludes them.

## Task 1: Add a Counts-Only Database View

**Files:**
- Create: `backend/postgres_migrations/v0007_mail_outbox_counts.py`
- Modify: `backend/postgres_migrations/registry.py`
- Modify: `backend/routes/platform_organizations.py`
- Test: `regression_tests/test_postgres_migrations.py`
- Test: `regression_tests/test_platform_organizations.py`

**Interfaces:**
- Produces migration `(7, "mail_outbox_counts")`.
- Produces view `platform_mail_outbox_counts` with exactly one row and integer columns `pending` and `failed`.
- The platform dashboard consumes that view and keeps its existing JSON response fields.

- [ ] **Step 1: Write failing view and migration tests.** Assert the migration registry ends at version 7, the view returns exactly one row for an empty queue, mixed pending/failed/sent rows return correct counts, and `information_schema.columns` lists only `pending` and `failed`. Add a platform dashboard test asserting the existing response fields are preserved and counts come from the view; grant the test web role `SELECT` on the view.
- [ ] **Step 2: Run the new PostgreSQL tests and confirm RED.** Run `TEST_DATABASE_URL=<disposable-postgres-dsn-ending-in-_test> uv run --with-requirements requirements.txt --with pytest==9.1.1 --with httpx==0.27.2 pytest -q regression_tests/test_postgres_migrations.py regression_tests/test_platform_organizations.py`. Expect the new migration and view contract assertions to fail, not a connection or fixture setup error.
- [ ] **Step 3: Implement immutable migration `v0007_mail_outbox_counts`.** Define `platform_mail_outbox_counts` as a single aggregate row counting `status = 'pending'` and `status = 'failed'`, cast both values to integer, and explicitly revoke view privileges from `PUBLIC`. Register the migration without editing earlier migrations. Update the dashboard query to select only `pending, failed` from the view.
- [ ] **Step 4: Run the focused PostgreSQL tests.** Re-run the Step 2 command and confirm the migration registry, empty and mixed queue counts, one-row shape, and unchanged dashboard response all pass.
- [ ] **Step 5: Commit the task.** Commit the migration, registry, dashboard, and tests with message `Add aggregate mail outbox status view`.

## Task 2: Restrict Web Runtime Outbox Access

**Files:**
- Modify: `regression_tests/test_invitation_routes.py`
- Modify: `regression_tests/test_platform_organizations.py`
- Create or modify: `regression_tests/test_mail_database_roles.py`

**Interfaces:**
- Consumes `platform_mail_outbox_counts` from Task 1.
- The web runtime role has no table-level `SELECT`, `UPDATE`, or `DELETE` on `mail_outbox`.
- The enqueue path remains `enqueue_mail(...) -> int` and returns the existing row ID for an idempotency conflict.

- [ ] **Step 1: Write failing restricted-role PostgreSQL assertions against the existing web-role fixtures.** Assert first and repeated enqueue return the same ID, and direct selection of `recipient_email`, `encrypted_payload`, or whole outbox rows raises `InsufficientPrivilege`. Assert the platform dashboard reads counts through the aggregate view. Leave the current broad fixture grants in place for this step so the direct-read denial fails for the expected reason.
- [ ] **Step 2: Run the web-role tests and confirm RED.** Run `TEST_DATABASE_URL=<disposable-postgres-dsn-ending-in-_test> uv run --with-requirements requirements.txt --with pytest==9.1.1 --with httpx==0.27.2 pytest -q regression_tests/test_invitation_routes.py regression_tests/test_platform_organizations.py regression_tests/test_mail_database_roles.py`. Expect the new direct-read denial assertion to fail because the test role can still read the outbox, not a connection or fixture setup error.
- [ ] **Step 3: Restrict the web test-role grants and prove the existing enqueue SQL works.** Replace table-level outbox grants in the web fixtures with only `INSERT(organization_id, message_type, recipient_email, encrypted_payload, idempotency_key)`, `SELECT(id, idempotency_key)`, `UPDATE(idempotency_key)`, required sequence `USAGE`, and `SELECT` on `platform_mail_outbox_counts`. Keep `enqueue_mail` transactional and unchanged if these grants support insert and conflict paths. If PostgreSQL requires a narrower SQL change, make it only with a failing test demonstrating the exact grant requirement; do not add table-wide web `SELECT`.
- [ ] **Step 4: Run the focused PostgreSQL tests.** Re-run the Step 2 command and confirm invite creation and organization provisioning still enqueue mail, repeated enqueue is idempotent, aggregate counts work, and direct message reads fail.
- [ ] **Step 5: Commit the task.** Commit the role-grant tests and any necessary enqueue changes with message `Restrict web access to mail outbox`.

## Task 3: Isolate Worker Connection and Database Role

**Files:**
- Modify: `backend/mail_worker.py`
- Modify: `regression_tests/test_mail_delivery.py`
- Modify: `regression_tests/test_mail_database_roles.py`

**Interfaces:**
- `run(*, once: bool = False) -> None` reads `MAIL_WORKER_DATABASE_URL` for its psycopg connection.
- The worker requires `MAIL_PAYLOAD_ENCRYPTION_KEY`, `RESEND_API_KEY`, and `RESEND_FROM_EMAIL` as before.
- The worker database identity receives only the outbox `SELECT` and `UPDATE` columns needed by `claim_pending_mail`, `mark_mail_sent`, and `mark_mail_failed`; it receives no rights on unrelated application tables.

- [ ] **Step 1: Write failing worker configuration and privilege tests against current behavior.** With valid mail secrets and `DATABASE_URL` set but `MAIL_WORKER_DATABASE_URL` absent or blank, assert `run()` raises before `psycopg.connect`. With both URLs present, assert it connects using `MAIL_WORKER_DATABASE_URL`. Also assert a connection using the current broad web-role fixture cannot serve as the worker role because it can read unrelated application tables. Leave current connection and broad grants in place for this step so the new expectations fail for those reasons.
- [ ] **Step 2: Run the worker tests and confirm RED.** Run `TEST_DATABASE_URL=<disposable-postgres-dsn-ending-in-_test> uv run --with-requirements requirements.txt --with pytest==9.1.1 --with httpx==0.27.2 pytest -q regression_tests/test_mail_delivery.py regression_tests/test_mail_database_roles.py`. Expect the missing/blank worker URL and wrong-connection/overbroad-role assertions to fail, not database setup.
- [ ] **Step 3: Implement worker-only connection selection and fail-closed startup.** Require a nonblank `MAIL_WORKER_DATABASE_URL` before connecting, use it for the psycopg connection, and do not read `DATABASE_URL` in the worker. Keep current validation of encryption and provider configuration before opening the connection. Replace the broad test role with a dedicated worker role granted schema `USAGE`, `SELECT(id, organization_id, message_type, recipient_email, encrypted_payload, status, attempt_count, available_at, lease_expires_at, claim_token)`, and `UPDATE(status, claim_token, lease_expires_at, attempt_count, updated_at, sent_at, last_error_code, available_at)`. Assert the role can claim, deliver through the injected provider transport, and mark messages sent or failed, but cannot read `users`, `sessions`, `organization_invitations`, `platform_admins`, or `inventory` and has no outbox `INSERT` or `DELETE` privilege.
- [ ] **Step 4: Run the focused PostgreSQL and worker tests.** Re-run the Step 2 command and confirm startup fails without the worker URL, connects with it when configured, delivery/retry behavior remains intact, and unrelated table access is denied.
- [ ] **Step 5: Commit the task.** Commit the worker change and tests with message `Use isolated mail worker database credentials`.

## Task 4: Document PostgreSQL Role Provisioning and Verify the Release

**Files:**
- Modify: `docs/environment.md`
- Modify: `docs/saas-cutover-runbook.md`
- Verify: `.github/workflows/postgres-tests.yml`

**Interfaces:**
- Documents `DATABASE_URL` for web runtime, `MAIL_WORKER_DATABASE_URL` for the worker, and `MIGRATION_DATABASE_URL` for schema migrations.
- Documents runtime revocation of broad outbox grants, the narrow web column grants and counts-view grant, and worker-only outbox grants. Role names and secret values are supplied by environment provisioning.

- [ ] **Step 1: Update environment and cutover documentation.** Remove the statement that the worker uses `DATABASE_URL`. Document distinct login roles, the exact least-privilege grant intent, the aggregate view, worker startup command, required setting names only, and that live role and secret provisioning is separate from this code change. Keep the current Railway SQLite service unchanged.
- [ ] **Step 2: Verify the CI workflow includes the new tests.** Confirm `.github/workflows/postgres-tests.yml` runs `pytest regression_tests -q` against PostgreSQL 17. Do not change the workflow if this already includes all new tests.
- [ ] **Step 3: Run focused and full verification.** Run `TEST_DATABASE_URL=<disposable-postgres-dsn-ending-in-_test> uv run --with-requirements requirements.txt --with pytest==9.1.1 --with httpx==0.27.2 pytest -q regression_tests/test_postgres_migrations.py regression_tests/test_invitation_routes.py regression_tests/test_platform_organizations.py regression_tests/test_mail_delivery.py regression_tests/test_mail_database_roles.py`, then run the full local `pytest -q` suite and `git diff --check`. Record any unavailable PostgreSQL setup or unrelated baseline failures by exact test name; GitHub's PostgreSQL workflow is the required complete database gate.
- [ ] **Step 4: Commit the task.** Commit the documentation with message `Document separate mail worker database role`.

## Final Review Checklist

- [ ] `MAIL_WORKER_DATABASE_URL` is required and the worker never falls back to `DATABASE_URL`.
- [ ] The web role cannot read outbox recipients, ciphertext, or individual status rows.
- [ ] The web role can enqueue invitations idempotently and read only aggregate pending/failed counts.
- [ ] The worker can deliver and update mail state, with no access to unrelated application tables.
- [ ] Earlier migrations are unchanged; migration 7 is immutable and its checksum is registered.
- [ ] Environment and cutover docs do not imply that live roles or Railway values have been changed.
- [ ] PostgreSQL CI and the frontend suite pass on the implementation commit before merge.
- [ ] No production role creation, secret change, deployment, or live-recipient test was performed.
