# Platform Audit and Security Logging Implementation Plan

**Date:** 2026-10-31  
**Status:** Tasks 1 and 2 remain in progress; Task 3 is complete in merged PR #322; Task 4 is in progress in the current branch. PRs #315–#322 are merged.
**Design:** [Platform Audit and Security Logging Design](../specs/2026-10-31-platform-audit-security-logging-design.md)

## Scope and sequencing

This plan covers platform administrative audit, global authentication/security events, tenant activity integration, and operational diagnostics relevant to the platform console. It does not change tenant authorization, add impersonation, broaden support access, or set a legal retention schedule.

Implement one task per reviewable PR. Preserve existing tenant RLS and the support-session allowlist throughout. Do not add audit export, purge, or archive behavior until the associated retention/access decisions are approved.

## Task 1 — Reliable, privacy-safe global security event store

**Goal:** Record authentication and account-security outcomes in PostgreSQL without requiring a tenant membership, including attempts for unmatched accounts.

**Design decisions before implementation:**
- Confirm the event schema, allowed event names/outcomes, and minimal fields.
- Decide whether unmatched identifier correlation is necessary. Default is omit it; if needed, use keyed HMAC pseudonymization with a defined secret rotation and expiry.
- Decide event-level retention and the purpose/access period for IP and user-agent before production writes begin.

**Implementation outline:**
- Add a PostgreSQL migration for a dedicated global security-event table and useful indexes. Keep it outside tenant RLS and expose it only through platform-authorized transactions.
- Add a writer service with strict action/detail allowlists, bounded metadata, UTC timestamps, and a server-generated request ID. Do not let callers supply tenant IDs for unknown-account events.
- Ensure writes work with psycopg/PostgreSQL and do not depend on SQLite placeholders. Define failure behavior: security-event persistence failures should be observable without breaking public authentication responses or logging sensitive input.
- Route selected login, lockout, password-reset, password-change, session/mobile credential issue/rotation/revocation events through the writer.
- Remove raw email from reset-failure details and prevent credential/token/body capture in both database and runtime logs.
- Keep existing tenant activity semantics for authenticated business activity; do not duplicate all auth events into `activity_logs`.

**Tests and acceptance:**
- PostgreSQL tests cover successful and failed login, known and unmatched account, reset outcomes, session revocation, and expected transaction behavior.
- Assert event details omit raw email, password, reset/session/refresh/CSRF tokens, request bodies, and authorization data.
- Assert platform admins can read events, tenant admins cannot access the global stream, and no request-controlled organization can influence event placement.
- Confirm selected events actually persist in PostgreSQL; no swallowed placeholder/schema failure may pass as success.

## Task 2 — Complete and normalize platform audit coverage

**Goal:** Ensure each consequential platform action is represented once, consistently, with actor, target, result, and safe context.

**Implementation outline:**
- Create an event coverage matrix mapping each platform mutation and support operation to its expected audit action and transaction boundary.
- Review organization lifecycle, membership/role and platform-admin changes, global settings, announcements, support-session start/read/denial/end/expiry, logout, and any newly added platform operations.
- Add missing events and tests. Keep audit writes in the same transaction as state changes when atomicity is possible; explicitly document cases where it is not.
- Tighten reason and detail validation. Avoid putting email, inventory values, notes, query parameters, or raw exception text into details.
- Verify runtime database permissions and migration role behavior before describing the stream as append-only; defer external tamper-evident storage to a separate approved task.

**Tests and acceptance:**
- Each action in the matrix has success and relevant denied/failure coverage.
- Mutation rollback cannot leave a success audit event for a failed mutation.
- Audit reads remain platform-authorized and safe-detail sanitization covers historical as well as new rows.

## Task 3 — Improve platform audit usability

**Goal:** Make the existing platform audit log useful for investigation without broadening its data access.

**Implementation outline:**
- Add human-readable actor and organization labels via safe joins/lookups, preserving IDs for deterministic reference.
- Present action/result labels and structured safe detail fields instead of raw JSON as the primary view.
- Add server-validated filters and pagination by time, actor, organization, action, and result; preserve bounded query parameters.
- Improve empty/loading/error states and make UTC/time display unambiguous.
- Treat export as a separate decision. Do not add it in this task unless the user approves its audience, fields, and audit behavior.

**Tests and acceptance:**
- UI tests cover filters, pagination, labels, safe detail rendering, and empty/error states.
- API tests verify platform authorization, field safety, bounds, and stable ordering.
- No tenant business activity appears in the global platform audit table.

## Task 4 — Security events platform view

**Goal:** Give platform operators a focused, privacy-safe view of security events created in Task 1.

**Implementation outline:**
- Add a read-only, platform-authorized API with bounded filters and pagination.
- Build a Security events view separate from administrative Audit log, with recent-by-default results and clear event/outcome labels.
- Display account match and actor ID when available; never display raw unmatched email or pseudonymous identifier by default.
- Add aggregate signals only when their source and thresholds are defined; do not infer account compromise from a single failed attempt.

**Tests and acceptance:**
- Cross-tenant and non-platform callers are denied.
- Filters are bounded; sensitive event fields never reach the API/UI.
- Existing platform console navigation and other tenant user flows remain intact.

### Task 4 progress — 2026-11-01

- Added a read-only `/api/platform/security-events` route using the authenticated platform transaction. It returns curated fields only, sanitizes historic details, limits pages to 100, orders newest-first, and validates event-family, outcome, account-match, actor, and UTC bounds.
- Added a separate Security events console view with recent events by default, bounded pagination, filters, fixed event/outcome/detail labels, and text-only rendering. It omits unmatched submitted identifiers, IP address, user-agent, and request ID.
- Extended the deployment grant helper with an opt-in `--platform-reader` mode for column-level SELECT on the API fields. The default remains writer-only; production grants have not been applied or verified.
- Added PostgreSQL tests for role authorization, filter validation, pagination, redaction, and restricted grants. They could not run locally because FastAPI/pytest and `TEST_DATABASE_URL` are unavailable; PostgreSQL CI is required before merge.

## Task 5 — Retention and evidence controls

**Goal:** Implement only the retention behavior approved in the design decision record.

**Prerequisite decisions:** Approved retention by stream and field, stock evidence treatment, archive/legal-hold requirements, backup behavior, responsible operator, and purge authorization.

**Implementation outline:**
- Provide a dry-run/preview showing affected event counts and time bounds.
- Implement a scheduled, bounded purge or archive job with least-privilege credentials and auditable execution.
- Keep stock evidence retention independent from ordinary tenant activity cleanup.
- Ensure purge/archive actions themselves are audited and recoverable where required.
- Verify interactions with database backups and restores.

**Acceptance:**
- Tests cover cutoff boundaries, protected evidence, retries/idempotency, legal hold if approved, and least-privilege access.
- Operational runbook specifies monitoring, failure handling, and restore implications.
- No data is removed before explicit policy approval.

## Task 6 — Operational diagnostics and health signals

**Goal:** Improve service troubleshooting without turning the application into a raw cross-tenant log browser.

**Implementation outline:**
- Verify actual hosting log retention/access settings and decide the supported observability source.
- Add or standardize request/correlation IDs across API and mail-worker logs, preserving redaction rules.
- Define approved health signals and their authoritative sources (for example API availability, database connectivity, mail-worker queue age/failure counts).
- Add aggregate health cards or links to provider dashboards only after the signals and access model are agreed.
- Avoid raw tenant payloads, SQL consoles, secret values, or unrestricted log search in the product UI.

**Acceptance:**
- Logs correlate requests across service components without recording credentials or tenant content.
- Health indicators have documented sources, freshness, and failure behavior.
- Provider retention/access and operational ownership are recorded.

## Cross-cutting rollout requirements

- Use feature flags or an equivalent safe rollout if new views could be exposed before authorization and redaction are verified.
- Keep tenant activity tenant-scoped; do not rely on UI hiding as an access boundary.
- Treat audit/security data as sensitive personal/security data and restrict production access.
- Update the privacy data inventory after schema and retention changes; its deployment/retention statements must reflect verified current configuration.
- Add monitoring for event-write failures without recursively logging the event payload.
- Do not claim immutability, compliance, or complete security coverage without verifying database grants, backup behavior, and provider configuration.

## Proposed execution order

1. Resolve Task 1 event/retention decisions and implement the security writer.
2. Complete platform audit coverage (Task 2).
3. Improve the existing audit UI (Task 3).
4. Add the Security events view (Task 4).
5. Approve then implement retention controls (Task 5).
6. Add operational health/logging improvements (Task 6).

Tasks 3 and 4 can follow independently after their APIs are stable. Retention work is intentionally gated by an explicit policy decision.

## Task 1 progress — 2026-11-01

- Merged #315: v21 table, curated writer, login success/failure and already-locked account attempts.
- Follow-up #316: reset request/failure/completion routing; no reset email/name in activity or success diagnostics; telemetry persistence failures use a fixed diagnostic without exception payload.
- Follow-up #316 includes explicit opt-in runtime-grant tooling and disposable PostgreSQL integration tests. Production grants must be applied and verified by the operator; they have not been changed by development verification.
- Merged #317: account-lockout transition and committed password-change events; removed duplicate login activity records and submitted-identifier runtime logging.
- Still pending after this slice: session/mobile credential issue/rotation/revocation coverage; global event read authorization/API/UI (Task 4); final coverage matrix and rollout verification.
- Retention policy remains undecided. No purge, archive, export, or retention schedule added. IP/user-agent purpose and retention still require a decision before broader rollout.

### Session lifecycle slice

Migration v22 extends the existing stream with `session_issued` and `session_rotated`.
Session events contain actor ID, fixed source/reason labels, an optional mobile
flag, and positive affected-session counts. They never contain credential values,
hashes, device names, submitted identifiers, or request/response bodies.

| Flow | Event behavior |
| --- | --- |
| Browser/native login | Issued event after commit; native replacement also records the prior-session count |
| Approved mobile pairing completion | Issued event and any mobile replacement after commit; pending/invalid requests issue no event |
| Native refresh | One rotated event for a new credential pair; exact-response retry emits none |
| Refresh invalidation | Revoked event for a committed expiry, unavailable account, or refresh-reuse revocation |
| Specific/other-session/logout/mobile-device revocation | Positive committed changes only; failed or no-op operations emit none |

Bulk revocations omit the mobile flag when the affected set may mix browser and
mobile sessions. Password reset/change events already represent their associated
session invalidation; this slice does not duplicate those as bulk revoke events.
Administrator-driven account/membership invalidation coverage remains part of the
remaining coverage-matrix review. All new events use the existing best-effort
postcommit writer and retain its process-crash omission window.

Apply v22 before relying on issuance/rotation telemetry. It changes the event CHECK
constraint only; it preserves existing rows and needs no new runtime columns or
grants. No global reader API/UI, retention, export or purge is added.

### Administrator invalidation coverage — PR #319

- Add safe actor/target identifiers and positive active-session counts for committed member removal/deactivation; do not emit an event for denied, foreign, no-op, or rolled-back mutations. The global event remains post-commit/best-effort.
- Suppress `company_role_changed` for requests that leave the platform company role unchanged.
- Constrain platform-audit result strings to `success`, `denied`, or `failure` before SQL.
- Add coverage for repeated explicit revocations, expired/unavailable native refresh telemetry, and unchanged platform audit results.
- See [platform event coverage](../../platform-event-coverage.md) for the source-backed matrix and documented gaps. PR #320 adds aggregate post-commit security telemetry when global mobile-duration shortening deactivates active sessions.
- Task 1/2 remain incomplete: the authorized security-event read API/UI, production grants/access and operational rollout checks, and full denied/failure coverage remain open. Retention/export/purge and provider/backup controls remain gated by policy decisions.

### Global mobile policy invalidations — PR #320

- Lock and count only active mobile sessions whose calculated deadline is past and whose expiry values the setting update shortens; the setting transaction uses those rows to set `is_active=FALSE`.
- After commit, write one aggregate `session_revoked` event with the acting platform administrator, fixed `mobile_duration_policy` reason, mobile flag, and count. Do not fan out one row per account for this global operation.
- No session event is produced for expiry-only tightening that leaves sessions active, repeated/no-op policy updates, or failed commits. The existing best-effort writer can still omit telemetry after commit if persistence fails.
