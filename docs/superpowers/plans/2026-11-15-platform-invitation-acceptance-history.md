# Platform Invitation Acceptance History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give platform administrators a secure, paginated history showing each organization invitation’s status and acceptance time.

**Architecture:** Add a curated PostgreSQL view over invitation records and a platform-admin-only API endpoint with bounded pagination and status/search filters. Add a dedicated platform-console view that reads invitation lifecycle data separately from the existing email-delivery history.

**Tech Stack:** Python, FastAPI, PostgreSQL migrations, pytest, HTML, Alpine.js, Node.js regression tests.

**Spec:** `docs/superpowers/specs/2026-11-15-platform-invitation-acceptance-history-design.md`

## Global Constraints

- Only authenticated platform administrators can read the global history.
- Never return invitation tokens, token hashes, encrypted mail payloads, or unrelated user records.
- Keep email provider delivery status separate from invitation lifecycle status.
- Display stored timestamps in UTC; use bounded pagination with a maximum page size of 100.
- Do not add acceptance notification emails or retention/purge behavior.

## Review Focus

- Re-inviting the same address must produce distinct rows; never correlate mail-outbox rows by organization and email.
- An invitation with `accepted_at` must remain accepted even if the account is later archived or renamed.
- Pending invitations become expired according to `expires_at`; status must not be frozen at view creation time.
- Non-platform identities must not read the curated global view or endpoint.
- Search and status filters must be parameterized and reject unsupported values before querying.

---

### Task 1: Curated invitation history view and migration test baseline

**Files:**
- Create: `backend/postgres_migrations/v0025_platform_invitation_history.py`
- Modify: `backend/postgres_migrations/registry.py`
- Modify: `regression_tests/test_postgres_migrations.py`
- Modify: `regression_tests/test_security_session_events.py`

**Interfaces:**
- Produces migration version 25, named `platform_invitation_history`.
- The view exposes invitation ID, organization ID/name/slug, recipient email, role, invited-at, expires-at, accepted-at, accepted-by ID, accepted-account name, and cancelled-at. It must not expose `token_hash`.

- [ ] **Step 1: Write the failing migration assertions**
  - Add a migration-registry test that checks version/name, curated columns, no `token_hash`, and `REVOKE ALL ... FROM PUBLIC`.
  - Add an integration fixture grant for the curated view and assert that accepted and pending invitation records appear with their expected timestamps and no token data.
- [ ] **Step 2: Run the focused migration tests and confirm the new assertions fail**
  - Run: `pytest regression_tests/test_postgres_migrations.py -q` and the focused invitation-history integration test.
  - Expected: the new migration is missing.
- [ ] **Step 3: Make the v22 migration test independent of later migrations**
  - In `test_v22_upgrade_preserves_v21_events_and_enables_new_taxonomy`, apply only `MIGRATIONS[:22]` for the v22 upgrade assertion. This keeps the test focused on migration 22 instead of expecting the current schema to stop at version 22.
- [ ] **Step 4: Add migration v25**
  - Create a curated view joining `organization_invitations` with organizations and the accepted user, revoke public access, and add a descending created-time/ID index for global pagination.
  - Register v25 after migration 24.
- [ ] **Step 5: Run focused migration tests**
  - Run the commands from Step 2.
  - Expected: the migration privacy and record-shape assertions pass, including on a schema already migrated through v24.
- [ ] **Step 6: Commit the migration task**
  - Commit the migration, registry, and focused tests together.

### Task 2: Platform-authorized invitation history API

**Files:**
- Modify: `backend/routes/platform_organizations.py`
- Modify: `backend/services/platform_audit.py`
- Modify: `regression_tests/test_platform_organizations.py`
- Modify: `regression_tests/test_platform_audit.py`

**Interfaces:**
- Add `GET /api/platform/invitations?limit=25&offset=0&status=all&search=`.
- Return `{rows, total, limit, offset}`. Each row includes organization, invitee email, role, invited/expiry times, lifecycle status, accepted time, accepted user ID/name, and cancelled time.
- Valid statuses: `all`, `pending`, `accepted`, `cancelled`, `expired`. Search is optional, trimmed, and limited to 100 characters; match invitation email or organization name/slug.

- [ ] **Step 1: Write failing route tests**
  - Verify all lifecycle states, filters, pagination, stable newest-first ordering, private no-store response headers, and that token fields never appear.
  - Verify invalid status/search/pagination errors and denial for non-platform identities.
  - Verify one curated `platform_invitation_history_read` audit event with bounded details that omit search text and recipient email.
- [ ] **Step 2: Run the focused route and audit tests and confirm they fail**
  - Run: `pytest regression_tests/test_platform_organizations.py -k invitation_history -q` and the matching audit-detail test.
  - Expected: route and audit action are not implemented.
- [ ] **Step 3: Implement the endpoint**
  - Use `authenticated_platform_transaction` and the curated view only.
  - Validate `limit` (1–100), `offset` (0–100000), status, and search length before querying.
  - Derive status from timestamps at request time, with accepted taking precedence over cancelled, cancelled over expired, and pending last.
  - Audit reads with `limit`, `offset`, and `result_count` only.
- [ ] **Step 4: Run focused route and audit tests**
  - Run the commands from Step 2.
  - Expected: authorized reads return only curated data; invalid and unauthorized reads are rejected.
- [ ] **Step 5: Commit the API task**
  - Commit the route, audit allowlist, and tests together.

### Task 3: Dedicated platform-console invitation history

**Files:**
- Modify: `static/superadmin.html`
- Modify: `static/js/pages/superadmin.js`
- Modify: `regression_tests/test_superadmin_ui.cjs`

**Interfaces:**
- Add an `Invitations` platform navigation item and page title.
- Add `loadPlatformInvitations(offset)`, bounded status/search filters, lifecycle status labels, loading/error/empty states, and pagination.

- [ ] **Step 1: Write failing UI tests**
  - Assert the platform-only navigation exposes the Invitations page and the legacy console cannot select it.
  - Assert filters are encoded, pagination uses the endpoint contract, retry recovers from API errors, and lifecycle labels map known states while unknown values display safely.
  - Assert the new history remains separate from the existing email-delivery table.
- [ ] **Step 2: Run the focused UI tests and confirm they fail**
  - Run: `node --test --test-name-pattern='platform invitation history' regression_tests/test_superadmin_ui.cjs`.
  - Expected: no platform invitation-history view or loader exists.
- [ ] **Step 3: Implement the page and loader**
  - Add a dedicated platform-only section with columns for organization, invitee, role, status, invited UTC, accepted UTC, and accepted account.
  - Load data only when the section is selected or refreshed; do not add it to initial platform boot requests.
  - Keep the delivery-history panel and its statuses unchanged.
- [ ] **Step 4: Run focused UI tests and the full frontend regression suite**
  - Run the focused command from Step 2, then `node --test regression_tests/*.cjs`.
  - Expected: all frontend regression tests pass.
- [ ] **Step 5: Commit the UI task**
  - Commit the page, client behavior, and tests together.

### Task 4: Full verification and review

**Files:**
- No additional files unless verification identifies a defect.

- [ ] Run `pytest regression_tests -q` with the PostgreSQL test database configured.
- [ ] Run `node --test regression_tests/*.cjs`.
- [ ] Run `git diff --check` and inspect the complete diff for changes outside the approved design.
- [ ] Confirm the platform invitation history does not expose invitation token material and does not merge delivery state with acceptance state.
