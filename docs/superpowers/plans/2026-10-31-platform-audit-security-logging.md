# Platform Audit and Security Logging Implementation Plan

**Date:** 2026-10-31  
**Status:** Proposed; implementation has not started  
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
