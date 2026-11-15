# Platform Invitation Delivery History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let platform administrators identify organization invitation recipients and inspect send and known delivery outcomes from the platform overview.

**Architecture:** Add a platform-authorized, read-only endpoint that returns a bounded page of curated invitation outbox metadata, with organization display fields. Keep outbox access narrow through an explicit PostgreSQL view and runtime SELECT grant; record each successful history read through the existing curated platform audit writer. Add a paginated table to the current platform overview UI.

**Tech Stack:** Python, FastAPI, PostgreSQL migrations, pytest, vanilla JavaScript/Alpine, Node regression tests.

**Spec:** `docs/superpowers/specs/2026-11-15-platform-invitation-delivery-history-design.md`

## Global Constraints

- Only include `organization_invitation` messages.
- Do not expose encrypted payloads, invitation URLs or tokens, idempotency keys, raw provider responses, or unsanitized error text.
- A queue state of `sent` means provider acceptance, not inbox delivery.
- Show `unknown` when no delivery event is recorded.
- Audit history reads without recipient addresses or payload details in audit data.
- Use bounded pagination, newest-first ordering, and platform authorization.
- Do not add resend, cancellation, retention, or purge behavior.

## Review Focus

- Malformed pagination bounds must return 422; test limit and offset validation in the route test.
- Platform session expiry/revocation must block history reads; test unauthorized access through the existing platform transaction/session test patterns.
- Password reset, owner welcome, and other non-invitation messages must never appear; test mixed outbox rows.
- Sensitive payload and credentials must not appear in JSON responses; assert forbidden keys and known secret strings are absent.
- A sent message with delivery status unknown must remain distinguishable from delivered; test the response and UI label mapping.

---

### Task 1: Narrow database read surface

**Files:**
- Create: `backend/postgres_migrations/v0024_platform_invitation_delivery_history.py`
- Modify: `backend/postgres_migrations/registry.py`
- Modify: `docs/environment.md`
- Modify: `docs/saas-cutover-runbook.md`
- Test: `regression_tests/test_postgres_migrations.py`
- Test: `regression_tests/test_mail_database_roles.py`

**Interfaces:**
- Produces migration `(24, "platform_invitation_delivery_history")`.
- Produces view `platform_invitation_delivery_history` exposing only: `id, organization_id, organization_name, organization_slug, recipient_email, status, delivery_status, attempt_count, created_at, updated_at, sent_at, last_error_code`. The view joins organizations and filters `message_type = 'organization_invitation'` and non-null organization.

- [ ] **Step 1: Write failing migration and privilege tests.** Assert migration creates the exact allowlisted view columns/filter and revokes PUBLIC privileges. Assert the app runtime has SELECT on the view but no new direct outbox SELECT rights.
- [ ] **Step 2: Run focused tests and confirm RED.** Run: `pytest regression_tests/test_postgres_migrations.py regression_tests/test_mail_database_roles.py -q`. Expected: missing migration and view/grant behavior fail.
- [ ] **Step 3: Add migration v24 and registry entry.** Create the filtered view with only the interface columns above, revoke PUBLIC, grant SELECT to the configured application runtime role following existing migration/grant conventions. Do not alter prior migrations.
- [ ] **Step 4: Document the new view grant.** Update environment setup and cutover grant documentation to include only `SELECT` on this view for the application runtime role.
- [ ] **Step 5: Run focused tests and confirm GREEN.** Run the same command; migration and role-isolation tests pass.
- [ ] **Step 6: Commit.** `git add backend/postgres_migrations/v0024_platform_invitation_delivery_history.py backend/postgres_migrations/registry.py docs/environment.md docs/saas-cutover-runbook.md regression_tests/test_postgres_migrations.py regression_tests/test_mail_database_roles.py && git commit -m "feat: add scoped invitation delivery read view"`

### Task 2: Platform-authorized history endpoint and audit

**Files:**
- Modify: `backend/routes/platform_organizations.py`
- Modify: `backend/services/platform_audit.py`
- Test: `regression_tests/test_platform_organizations.py`
- Test: `regression_tests/test_platform_audit.py`
- Test: `regression_tests/test_platform_transactions.py`

**Interfaces:**
- Add `GET /api/platform/invitation-mail` with query parameters `limit: int = 25`, `offset: int = 0`; enforce `1 <= limit <= 100` and `0 <= offset <= 100000`.
- Return `{"rows": [...], "total": int, "limit": int, "offset": int}`; each row contains only the view columns in Task 1.
- Add audit action `platform_invitation_mail_read`, result `success`, details `{"limit": int, "offset": int, "result_count": int}`.

- [ ] **Step 1: Write failing route, audit allowlist, and secrecy tests.** Cover platform authorization, bounds, mixed message types, stable ordering/pagination, exact returned keys, no secrets in output, and safe audit details without recipient addresses.
- [ ] **Step 2: Run focused tests and confirm RED.** Run: `pytest regression_tests/test_platform_organizations.py regression_tests/test_platform_audit.py regression_tests/test_platform_transactions.py -q`. Expected: route/action missing and assertions fail.
- [ ] **Step 3: Implement endpoint.** Use `authenticated_platform_transaction(..., readonly=False)` so successful reads and their audit entry share a transaction; validate a PostgreSQL connection; query count and page only from the new view, order by `created_at DESC, id DESC`, and record one curated audit event with limit, offset, and result count. Return exact view fields only.
- [ ] **Step 4: Add strict audit detail sanitization.** Allow only integer `limit`, `offset`, and `result_count` values with the endpoint bounds; do not allow recipient or organization PII in details.
- [ ] **Step 5: Run focused tests and confirm GREEN.** Run the same command; route, role, audit, and secrecy assertions pass.
- [ ] **Step 6: Commit.** `git add backend/routes/platform_organizations.py backend/services/platform_audit.py regression_tests/test_platform_organizations.py regression_tests/test_platform_audit.py regression_tests/test_platform_transactions.py && git commit -m "feat: expose audited platform invitation mail history"`

### Task 3: Dashboard history table and pagination

**Files:**
- Modify: `static/superadmin.html`
- Modify: `static/js/pages/superadmin.js`
- Modify: `static/css/platform-console.css`
- Test: `regression_tests/test_superadmin_ui.cjs`

**Interfaces:**
- Add UI state: `invitationMailRows`, `invitationMailTotal`, `invitationMailOffset`, `invitationMailLimit = 25`, `invitationMailLoading`, `invitationMailError`.
- Add methods `loadInvitationMail()` and `changeInvitationMailPage(direction)`.
- Render the invitation history in the platform overview near “Needs attention”; display organization, recipient, queue status, delivery status, attempt count, created/sent timestamps, and sanitized error code. Provide previous/next controls and explicit loading, empty, and error states.

- [ ] **Step 1: Write failing UI tests.** Assert API query/pagination behavior, visible required columns, status semantics (“Sent to provider” vs “Delivered”), omission of resend controls, and loading/error/empty states.
- [ ] **Step 2: Run UI test and confirm RED.** Run: `node --test regression_tests/test_superadmin_ui.cjs`. Expected: new state/methods/markup are missing.
- [ ] **Step 3: Implement UI behavior.** Load the first page on platform overview refresh, request subsequent pages from `/platform/invitation-mail?limit=25&offset=N`, and keep errors recoverable without hiding existing dashboard metrics.
- [ ] **Step 4: Add table styling.** Follow existing platform-console table and responsive patterns; keep columns readable on mobile with the established stacked-row behavior.
- [ ] **Step 5: Run UI test and confirm GREEN.** Run: `node --test regression_tests/test_superadmin_ui.cjs`; all tests pass.
- [ ] **Step 6: Commit.** `git add static/superadmin.html static/js/pages/superadmin.js static/css/platform-console.css regression_tests/test_superadmin_ui.cjs && git commit -m "feat: show invitation delivery history in platform dashboard"`

### Task 4: Cross-surface verification and review

**Files:**
- No additional product files unless a regression is found.

- [ ] **Step 1: Run focused regression suite.** Run: `pytest regression_tests/test_platform_organizations.py regression_tests/test_platform_audit.py regression_tests/test_platform_transactions.py regression_tests/test_mail_database_roles.py regression_tests/test_postgres_migrations.py -q`.
- [ ] **Step 2: Run dashboard UI suite.** Run: `node --test regression_tests/test_superadmin_ui.cjs`.
- [ ] **Step 3: Run static checks.** Run: `python -m compileall -q backend` and `git diff --check`.
- [ ] **Step 4: Inspect final diff for privacy and grants.** Confirm no sensitive outbox fields are selected or returned, no broad table grants were added, the audit payload contains no recipient or message details, and the UI clearly separates provider acceptance from delivery confirmation.
- [ ] **Step 5: Prepare PR.** Create a PR with title `feat: show invitation delivery history in platform dashboard` and summarize migration/view scope, audited endpoint, UI, and verification; do not merge or deploy.

