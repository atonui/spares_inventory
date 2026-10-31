# SaaS Tenant Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move the inventory application onto a tenant-aware PostgreSQL foundation, preserve the current installation as the first company, and prove tenant isolation before production cutover.

**Architecture:** Add a PostgreSQL 17 runtime using Psycopg 3.3.6 and a new immutable PostgreSQL migration chain; keep the existing SQLite migrations intact for legacy import and rollback. Resolve one company membership from the authenticated server-side session, set transaction-local tenant context, and enforce company scope in both application queries and PostgreSQL RLS. Import a read-only SQLite snapshot into an empty PostgreSQL database through a guarded CLI; no dual-write path.

**Tech Stack:** FastAPI, Python, Psycopg 3, PostgreSQL, existing SQLite migration code, pytest, GitHub Actions PostgreSQL service container.

**Spec:** `docs/superpowers/specs/2026-10-15-saas-foundation-design.md`

## Global Constraints

- New companies are provisioned by a platform administrator and begin with an emailed invitation to their first company owner. There is no public company signup in the pilot.
- Each user account belongs to exactly one company in v1.
- Company roles are `owner`, `admin`, `manager`, and `engineer`; a separate `platform_admin` role does not itself grant routine access to company inventory.
- The current installation becomes the first company; existing users, company data, and company audit history move into it.
- PostgreSQL row-level security provides a second enforcement layer; the web application's database role is restricted and is not a table owner, superuser, or `BYPASSRLS` role.
- Keep a narrow database-routing boundary so a later move to one database per company remains possible; do not provision separate databases in this plan.
- All existing operational data goes into the first organization; no data is consolidated or deleted during tenant assignment.
- Existing sessions are revoked at cutover; existing migrated users are not falsely marked email-verified.
- No billing, public self-service signup, native mobile implementation, offline stock writes, or app-store submission in this plan.
- Production cutover is a separate explicit approval point after copy-only rehearsal and backup verification.

## Review Focus

- Missing or invalid tenant context must fail closed; test unauthenticated and platform-only requests against tenant routes.
- A pooled or reused connection must never retain a prior company's context; test tenant A, rollback, then tenant B on the same connection.
- Conflicting natural keys and cross-company foreign keys must be rejected; test duplicate part numbers and equipment serial numbers across organizations as well as cross-org references.
- PostgreSQL transaction failures must roll back stock and audit writes together; test duplicate-key failures, constraint failures, and concurrent stock consumption.
- Legacy null-actor logs, canonical UTC timestamps, archived records, and historical transfers must be preserved; test both successful import and malformed legacy data rejection without source mutation.

---

### Task 1: PostgreSQL integration-test environment

**Files:**
- Modify: `requirements.txt`
- Create: `.github/workflows/postgres-tests.yml`
- Create: `regression_tests/postgres_fixtures.py`
- Create: `regression_tests/test_postgres_test_setup.py`

**Interfaces:**
- Produces `postgres_test_dsn() -> str` and a fixture `postgres_admin_connection`; only test DSNs whose database name ends in `_test` are accepted.
- CI provides PostgreSQL 17 as a service container and runs the backend regression suite with `TEST_DATABASE_URL` set to the isolated test database.

- [ ] **Step 1: Write failing tests** for rejection of an unset DSN, rejection of a database name without `_test`, successful connection to a disposable test database, and cleanup of each test schema.
- [ ] **Step 2: Run `pytest regression_tests/test_postgres_test_setup.py -q`** and confirm the new fixture/imports are missing.
- [ ] **Step 3: Add `psycopg[binary]==3.3.6`, the test connection helper, and a GitHub Actions workflow using a PostgreSQL 17 service container.** The fixture must refuse production-looking database names before creating or dropping schemas.
- [ ] **Step 4: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_postgres_test_setup.py -q`** and confirm all safety/setup tests pass; then confirm the workflow YAML parses and invokes the same command.
- [ ] **Step 5: Commit** as `test: add isolated PostgreSQL integration environment`.

### Task 2: PostgreSQL connection and transaction boundary

**Files:**
- Create: `backend/postgres_database.py`
- Modify: `backend/config.py`
- Modify: `backend/app_database.py`
- Modify: `main.py`
- Test: `regression_tests/test_postgres_database.py`
- Test: `regression_tests/test_app_database.py`

**Interfaces:**
- Produces `connect_postgres(dsn: str, *, readonly: bool = False) -> psycopg.Connection` using `dict_row`.
- Produces `postgres_transaction(conn, *, readonly: bool = False)`; it owns commit/rollback but does not set a tenant until Task 4.
- Keeps `open_application_database()` and the SQLite `connect_database()` compatibility path for migration fixtures and local legacy inspection; application startup in `main.py` selects PostgreSQL from `DATABASE_URL` and applies only PostgreSQL migrations.

- [ ] **Step 1: Write failing tests** for PostgreSQL DSN selection, dictionary-key row access, read-only connection behavior, transaction commit/rollback, and redaction of the DSN from public errors.
- [ ] **Step 2: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_postgres_database.py -q`** and confirm failures identify the missing connector and transaction helper.
- [ ] **Step 3: Implement the Psycopg connector, database URL dispatch, and `main.py` startup selection** without changing route SQL yet; add a bounded connection timeout and keep credentials out of logs.
- [ ] **Step 4: Run the PostgreSQL tests plus `pytest regression_tests/test_app_database.py -q`** and confirm SQLite compatibility tests still pass.
- [ ] **Step 5: Commit** as `feat: add PostgreSQL database boundary`.

### Task 3: Versioned PostgreSQL schema and tenant constraints

**Files:**
- Create: `backend/postgres_migrations/__init__.py`
- Create: `backend/postgres_migrations/registry.py`
- Create: `backend/postgres_migrations/runner.py`
- Create: `backend/postgres_migrations/v0001_core_schema.py`
- Create: `backend/postgres_migrations/v0002_tenancy.py`
- Modify: `backend/postgres_database.py`
- Test: `regression_tests/test_postgres_migrations.py`

**Interfaces:**
- Produces `apply_postgres_migrations(conn) -> MigrationStatus` and `postgres_migration_status(conn) -> MigrationStatus`.
- PostgreSQL migrations are immutable, ordered, checksummed, and independent from SQLite migration versions 1–6.
- `v0002_tenancy` creates `organizations`, `organization_memberships`, and `platform_admins`; tenant tables receive `organization_id UUID NOT NULL` after the organization row exists. User identities, sessions, system logs, and platform audit/configuration records remain global; company activity records are tenant-scoped.

- [ ] **Step 1: Write failing tests** for fresh migration, repeat startup, altered checksum rejection, incomplete history rejection, and rollback after an injected migration failure.
- [ ] **Step 2: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_postgres_migrations.py -q`** and confirm the PostgreSQL migration package is missing.
- [ ] **Step 3: Implement the versioned migration chain** for the current inventory schema and tenant model. Use organization-scoped uniqueness for part numbers, work-order numbers, equipment serial numbers, and store names where currently unique; use same-organization composite foreign keys for tenant relationships. Keep the current UTC ISO-8601 text contract for application timestamps in this migration.
- [ ] **Step 4: Enable RLS in a default-deny state** on tenant tables; add policies in Task 4. Keep role creation/credentials in deployment setup, not in application startup, and do not grant table ownership or `BYPASSRLS` to the web role.
- [ ] **Step 5: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_postgres_migrations.py -q`** and assert migration status is current, constraints exist, and failures leave no partial schema/ledger rows.
- [ ] **Step 6: Commit** as `feat: add versioned PostgreSQL tenant schema`.

### Task 4: Authenticated company context and RLS enforcement

**Files:**
- Create: `backend/services/principals.py`
- Create: `backend/services/tenant_context.py`
- Modify: `backend/services/session_authentication.py`
- Modify: `backend/services/session_access.py`
- Modify: `backend/services/authenticated_transactions.py`
- Modify: `main.py`
- Test: `regression_tests/test_tenant_context.py`
- Test: `regression_tests/test_tenant_rls.py`

**Interfaces:**
- Produces immutable `AuthenticatedPrincipal(user_id: int, organization_id: UUID | None, company_role: str | None, is_platform_admin: bool)`.
- Produces `resolve_principal(conn, session_token: str) -> AuthenticatedPrincipal`, which requires an active session and an active organization membership.
- Produces `set_tenant_context(conn, organization_id: UUID) -> None`, implemented with transaction-local `set_config('app.organization_id', ..., true)`.
- Changes `authenticate_session(...)` to return `AuthenticatedPrincipal`; route factories consume the principal rather than trusting a request-supplied organization ID.

- [ ] **Step 1: Write failing tests** for missing/expired session, missing membership, company role resolution, platform-admin-without-membership denial on tenant routes, and a connection reused from organization A to organization B.
- [ ] **Step 2: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_tenant_context.py regression_tests/test_tenant_rls.py -q`** and confirm missing principal/context code fails.
- [ ] **Step 3: Implement principal resolution and set transaction-local organization context before any tenant query.** Never accept a caller-provided organization ID as authorization.
- [ ] **Step 4: Add RLS policies for every tenant table** and test them using the restricted runtime role, not the migration/table-owner role. Verify no context, wrong context, and rolled-back context all deny access.
- [ ] **Step 5: Run both test files** and confirm organization A cannot select, insert, update, or delete organization B records.
- [ ] **Step 6: Commit** as `feat: enforce authenticated tenant database context`.

### Task 5: Tenant-scoped catalog and company administration data

**Files:**
- Modify: `backend/routes/stores.py`
- Modify: `backend/routes/parts.py`
- Modify: `backend/routes/work_orders.py`
- Modify: `backend/services/work_orders.py`
- Modify: `backend/services/archiving.py`
- Modify: `backend/services/authorization.py`
- Modify: CSV import/export handlers in `backend/routes/parts.py` and `backend/routes/stores.py`
- Modify: corresponding `backend/schemas/` modules
- Test: `regression_tests/test_tenant_catalog_routes.py`
- Test: `regression_tests/test_stores_router.py`
- Test: `regression_tests/test_parts_router.py`
- Test: `regression_tests/test_work_order_router.py`

**Interfaces:**
- Each tenant route, including CSV imports and exports, receives `AuthenticatedPrincipal` and opens its connection inside a tenant transaction.
- Administrative authorization helpers accept `principal` and the owning transaction connection; they do not open a second unscoped connection.
- Existing role capability is preserved: `admin` and `owner` receive company-admin rights; manager and engineer permissions remain unchanged.

- [ ] **Step 1: Add parameterized failing route tests** that create two organizations with overlapping local record IDs and verify store, store-type, part, work-order, CSV import/export, archive, and restore requests only return or mutate the caller's organization.
- [ ] **Step 2: Run the four named route test files and the new tenant test** to establish the current cross-company leaks or missing principal signatures.
- [ ] **Step 3: Update the route/service queries and request schemas** to include server-derived organization scope; convert SQLite-only SQL in these files to Psycopg-compatible SQL, use `RETURNING id`, and preserve existing response shapes.
- [ ] **Step 4: Run the route tests** and verify duplicate natural keys are allowed across organizations but rejected within one organization.
- [ ] **Step 5: Commit** as `feat: scope catalog and work-order data by organization`.

### Task 6: Tenant-scoped stock, movement, equipment, history, and reports

**Files:**
- Modify: `backend/routes/inventory_reads.py`
- Modify: `backend/routes/inventory_writes.py`
- Modify: `backend/routes/reports.py`
- Modify: `backend/routes/equipment.py`
- Modify: `backend/routes/history.py`
- Modify: `backend/routes/users.py`
- Modify: `backend/routes/timezone_settings.py`
- Modify: `backend/services/inventory.py`
- Modify: `backend/services/stock_access.py`
- Modify: `backend/services/stock_transactions.py`
- Modify: `backend/services/transfer_helpers.py`
- Modify: `backend/services/activity.py`
- Modify: `backend/services/timezone_policy.py`
- Modify: `backend/services/security_settings.py`
- Modify: relevant `backend/schemas/` modules
- Test: `regression_tests/test_tenant_stock_routes.py`
- Test: `regression_tests/test_tenant_equipment_history.py`
- Test: `regression_tests/test_tenant_reports.py`
- Test: `regression_tests/test_stock_transactions.py`
- Test: `regression_tests/test_transfer_receipts.py`

**Interfaces:**
- Stock writes use PostgreSQL transactions and row locks on the inventory identities they change; they do not depend on SQLite `BEGIN IMMEDIATE`.
- New IDs come from `INSERT ... RETURNING id`; time values use `backend.temporal.serialize_instant(backend.temporal.utc_now())`.
- Organization timezone/default settings are stored and read under the authenticated organization; per-user display preferences remain global user data.
- `record_activity` receives an explicit organization scope for tenant events; platform events remain global.

- [ ] **Step 1: Add failing two-organization tests** for inventory reads/writes, consumption, receiving, dispatch/receipt, counts, equipment assignments/history, user/store joins, organization timezone/default settings, movement history, and report totals.
- [ ] **Step 2: Run the new tests plus `regression_tests/test_stock_transactions.py` and `regression_tests/test_transfer_receipts.py`** against PostgreSQL and confirm either cross-company access or SQLite-only transaction assumptions fail.
- [ ] **Step 3: Convert the named services/routes to PostgreSQL-compatible statements and organization-scoped predicates.** Replace `lastrowid`/`last_insert_rowid()`, `strftime`, `INSERT OR IGNORE`, positional row access, and `BEGIN IMMEDIATE` with `RETURNING`, application UTC serialization, `ON CONFLICT DO NOTHING`, dictionary-row access, and targeted row locks.
- [ ] **Step 4: Keep each stock change, movement, and audit event in one PostgreSQL transaction.** Add concurrency tests proving competing consumption cannot produce negative stock and rejected transactions leave no movement or audit rows.
- [ ] **Step 5: Run all named tests and the full Python regression suite**; confirm tenant A cannot read or change tenant B through any tested route and existing stock invariants remain intact.
- [ ] **Step 6: Commit** as `feat: scope stock and operational records by organization`.

### Task 7: Platform administration, global data, and announcement split

**Files:**
- Modify: `backend/routes/superadmin.py`
- Modify: `backend/routes/auth.py`
- Modify: `backend/routes/history.py`
- Modify: `backend/app_activity.py`
- Modify: `backend/app_bootstrap.py`
- Modify: `backend/services/security_settings.py`
- Modify: `database_restore.py`
- Modify: `backend/services/announcements.py`
- Modify: `static/superadmin.html`
- Modify: `static/index.html`
- Modify: relevant frontend factories and role tests in `regression_tests/`
- Test: `regression_tests/test_tenant_platform_admin.py`
- Test: `regression_tests/test_tenant_announcements.py`

**Interfaces:**
- Platform routes require `principal.is_platform_admin`; company routes require an active company role.
- Organization settings and company announcements use `organization_id`; platform settings, system logs, and platform announcements use dedicated global records.
- Platform audit records store actor, action, result, timestamp, and optional organization scope. Platform-wide database maintenance remains restricted to platform administrators and every operation is auditable.

- [ ] **Step 1: Add failing authorization and audience tests** proving company admins cannot call platform settings, account controls, SQL/database tools, or platform broadcasts; platform announcements and the existing first-company announcement reach only their intended audience.
- [ ] **Step 2: Run the named tests** and confirm existing global-role checks and singleton announcement storage conflict with tenant behavior.
- [ ] **Step 3: Split platform and company authorization/storage** while retaining the existing public API response behavior for the first company. Move the current site-wide notice into the first organization's announcement record and add a separate platform announcement record.
- [ ] **Step 4: Replace SQLite-specific platform maintenance queries and database exception handling.** Keep database backup/restore as a privileged, auditable platform operation using PostgreSQL-native maintenance tooling; never treat an uploaded SQLite file as a PostgreSQL restore. Document the exact operator workflow and audit record in the cutover runbook.
- [ ] **Step 5: Update superadmin/profile/inventory role rendering and frontend regressions** for company roles and platform administrator status; verify existing Alpine bindings remain intact.
- [ ] **Step 6: Run backend and JavaScript regression suites** and commit as `feat: separate platform administration from company roles`.

### Task 8: Read-only SQLite-to-PostgreSQL import command

**Files:**
- Create: `backend/migration_import/__init__.py`
- Create: `backend/migration_import/sqlite_to_postgres.py`
- Create: `backend/migration_import/verify.py`
- Create: `regression_tests/test_sqlite_postgres_import.py`
- Modify: `docs/database-migrations.md`
- Modify: `docs/environment.md`

**Interfaces:**
- Produces `import_sqlite_snapshot(source_path: Path, target_dsn: str, *, organization_name: str, platform_admin_email: str, tenant_owner_email: str, dry_run: bool = True) -> ImportReport`.
- CLI: `python -m backend.migration_import import-sqlite --source PATH --target-dsn-env DATABASE_URL --organization-name NAME --platform-admin-email EMAIL --tenant-owner-email EMAIL [--apply]`.
- The SQLite source opens read-only; omitted `--apply` means rollback-only rehearsal. The target database must be empty except for the PostgreSQL migration ledger and bootstrap records.

- [ ] **Step 1: Write failing import tests** for a current SQLite fixture, an empty PostgreSQL target, owner-role mapping, organization-scoped natural keys, preserved timestamps/audit rows, legacy null user IDs, source immutability, bad foreign references, and target-not-empty refusal.
- [ ] **Step 2: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_sqlite_postgres_import.py -q`** and confirm the importer/report contracts are missing.
- [ ] **Step 3: Implement a deterministic table-by-table import** that assigns all operational rows to the first organization, validates `platform_admin_email` identifies a legacy superadmin and `tenant_owner_email` identifies a different legacy admin/superadmin, maps the platform admin to no tenant membership and the separate tenant owner to company owner, maps remaining user roles, invalidates password-reset tokens, and revokes sessions. Do not log row contents, password hashes, session tokens, or DSNs.
- [ ] **Step 4: Implement `ImportReport` verification** for source/target row counts, per-store/part balances, transfer states, organization memberships, temporal fields, and foreign keys; dry-run must leave target unchanged.
- [ ] **Step 5: Run the importer tests against both current and legacy SQLite fixtures**; compare source snapshots before/after and prove a failed import rolls back every target change.
- [ ] **Step 6: Commit** as `feat: add verified SQLite to PostgreSQL import`.

### Task 9: Cutover runbook and end-to-end acceptance

**Files:**
- Create: `docs/saas-cutover-runbook.md`
- Modify: `docs/environment.md`
- Modify: `.github/workflows/postgres-tests.yml`
- Test: `regression_tests/test_tenant_isolation_matrix.py`
- Test: `regression_tests/test_tenant_runtime_startup.py`

**Interfaces:**
- Runtime startup selects PostgreSQL from `DATABASE_URL`, applies only pending PostgreSQL migrations, and refuses an invalid or newer ledger.
- The cutover runbook requires a verified restorable backup, read-only maintenance, import verification, test-account sign-in, and an explicit go/no-go checklist.

- [ ] **Step 1: Add an isolation matrix test** covering every tenant route family, CSV import/export, report, admin action, and tenant relationship listed in the spec; add startup tests for empty, current, invalid, and newer PostgreSQL schemas.
- [ ] **Step 2: Run `TEST_DATABASE_URL=postgresql://.../inventory_test pytest regression_tests/test_tenant_isolation_matrix.py regression_tests/test_tenant_runtime_startup.py -q`** and close each missing route/context case.
- [ ] **Step 3: Write the cutover runbook** with copy-only rehearsal commands, backup/restore verification, exact count/balance comparisons, maintenance-window steps, rollback conditions, session revocation, and a prohibition on cutover if any reconciliation check fails.
- [ ] **Step 4: Run `pytest regression_tests -q` and `node --test regression_tests/*.cjs`** in the configured PostgreSQL test environment; require all backend and frontend tests to pass. Run `git diff --check`.
- [ ] **Step 5: Commit** as `docs: add SaaS database cutover runbook`.

## Deferred to the separate email plan

This plan creates the tenant membership and platform-role foundation only. It does not implement company invitations, email verification, password-reset delivery changes, provider integration, the transactional outbox, or a mail worker. New companies must not be onboarded until that separate email plan is complete.

## Production boundary

The plan ends with a tested migration command and cutover runbook. It does not execute production backup, maintenance mode, database provisioning, data migration, or DNS/deployment changes. Those require a separate review of the concrete cutover checklist immediately before execution.
