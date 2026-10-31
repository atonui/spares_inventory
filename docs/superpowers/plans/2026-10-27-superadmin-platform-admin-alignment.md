# Superadmin Platform Administration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Complete the PostgreSQL platform-admin console in safe, reviewable slices while preserving the app’s existing tenant-isolation model and SQLite deployment.

**Architecture:** Treat platform authority as a separate capability backed by platform_admins and authenticated_platform_transaction. Platform actions run without implicit tenant context; tenant work remains behind active organization membership and RLS. Keep the legacy SQLite superadmin surface available only for SQLite mode, and add PostgreSQL platform features through explicit /api/platform routes.

**Tech Stack:** FastAPI, Python, PostgreSQL/psycopg, existing SQLite compatibility path, Alpine.js, pytest and browser regression tests.

**Spec:** User attachment saas_superadmin_architecture.md; existing SaaS contract docs/superpowers/specs/2026-10-15-saas-tenant-admin-and-invitations-design.md. The latter’s least-privilege and one-company-per-user rules constrain this implementation. Reviewed main snapshot: 14c767d10378cee24fd7bc76c756c5b8ead9c970.

## Global Constraints

- Platform-admin status alone never creates tenant context or grants inventory or company-user-list access.
- Tenant queries continue to use server-resolved membership and PostgreSQL RLS; never add a blanket RLS bypass.
- Do not add global support/billing roles until concrete workflows and permission boundaries are specified.
- Do not expose deployment secrets or environment variables in the application UI.
- Keep tenant support access out of the routine platform console. Add it only through the dedicated, read-only-by-default support workflow in Task 7. Do not implement direct tenant hard deletion, feature entitlements, or billing overrides in this core plan; each needs its own approved design.
- Preserve current SQLite behavior until the separately reviewed database cutover.

## Review Focus

- A platform-only identity calls a tenant endpoint: receive 403 and no tenant data.
- A member’s organization is suspended while the member has an existing session: tenant access is denied; platform access for a platform admin remains usable.
- The last active platform admin is targeted for removal or concurrent removals occur: at least one active admin remains.
- Audit filters contain malformed dates, oversized values, or SQL-like strings: reject or return no matches without changing query behavior.
- A PostgreSQL deployment calls a SQLite-only superadmin endpoint: return a deliberate 404/503; the equivalent SQLite operation remains available in SQLite mode.

---

## Current Alignment

- **Authority separation:** PostgreSQL platform authority is held in `platform_admins`; tenant authority comes from the single organization membership stored in `organization_memberships`. These identities are mutually exclusive and enforced by PostgreSQL. Platform transactions clear tenant context, while tenant transactions require a resolved active company principal. Platform admins have no tenant membership or tenant data access.
- **Platform console:** `/api/platform` and the SaaS UI provide platform dashboard counts, organization search/detail/lifecycle controls, initial-owner invitations, platform-admin grant/revoke, narrowly scoped company-role changes, audit events, announcements, and the supported global session/security settings. The console does not expose tenant inventory or a general tenant-user directory.
- **Tenant lifecycle and boundaries:** Organization suspension is reason-audited and blocks tenant access for existing and new sessions. Store stock authorization checks the principal’s organization against the store’s organization. Membership uniqueness enforces the documented one-company-per-user model.
- **Audit and announcements:** Platform mutations and support access are audited through `platform_audit_events`. PostgreSQL announcements use `platform_announcements`; SQLite retains its legacy persistence path until cutover.
- **Controlled support:** A separate, audited, read-only support workflow grants short-lived access to allowlisted tenant resources for one organization, with persistent UI indication and revocation/expiry. It does not impersonate the customer or grant general tenant browsing.
- **Legacy/API boundary:** SQLite-only `/api/superadmin` operations are guarded against PostgreSQL use; public announcement delivery remains compatible across modes. The legacy superadmin UI remains for SQLite mode.
- **Still separate design work:** True impersonation, feature flags/tenant limits, billing portfolio or overrides, OAuth/integration management, global MFA/step-up policy, and tenant termination/data erasure have no implementation in this plan and require their own designs. Operational service-health and latency dashboards are also not provided by the current platform console.

## Delivery Plan

### Task 1: Make SQLite and PostgreSQL superadmin boundaries explicit

**Files**
- Modify: main.py and backend/routes/superadmin.py
- Modify: backend/services/announcements.py for PostgreSQL mapping-row compatibility on the public read path
- Test: regression_tests/test_superadmin_router.py, regression_tests/test_superadmin_mode_boundaries.py, and regression_tests/test_announcement_service.py

- [x] Reuse the existing SQLite-mode coverage for table inspection, SQL console, backup, restore, and VACUUM; add failing PostgreSQL-mode tests proving those operations fail closed with a documented 503 before reaching SQLite-specific code.
- [x] Inventory every /api/superadmin route and classify it as SQLite-only or public compatibility behavior. Preserve public announcement reads for anonymous and authenticated PostgreSQL users until the platform announcement path is ready.
- [x] Add route-level mode guards for every SQLite-only route. Do not rely on the browser hiding a tab.
- [x] Keep /api/platform as the PostgreSQL platform surface. Do not migrate global users.role assumptions into PostgreSQL.

**Acceptance:** Existing SQLite regression tests still pass; PostgreSQL calls to SQLite-only routes fail deliberately; public notice delivery remains intact.

### Task 2: Expose the platform audit trail

**Files**
- Create: backend/routes/platform_audit.py
- Create: backend/services/platform_audit.py
- Modify: backend/routes/platform_organizations.py, main.py, static/superadmin.html, static/js/pages/superadmin.js, static/superadmin.css
- Test: new regression_tests/test_platform_audit.py; extend regression_tests/test_superadmin_ui.cjs

- [x] Add a shared record_platform_audit_event(conn, actor_user_id, action, result, organization_id=None, details=None) service and move existing platform-route inserts through it without changing event meanings.
- [x] Add GET /api/platform/audit-events using authenticated_platform_transaction(readonly=True), with bounded pagination and filters for actor, organization, action, result, and UTC time range. Add migration indexes for created_at and the most-used filter combinations. Live EXPLAIN validation remains pending a disposable TEST_DATABASE_URL.
- [x] Return only safe event fields. Never return invitation tokens, encrypted mail payloads, credentials, or arbitrary SQL. Render details with text binding, not HTML.
- [x] Add a Platform Audit section to the SaaS superadmin UI with loading, empty, error, retry, filters, and pagination states.
- [x] Add tests for non-platform denial, date/filter validation, stable ordering, pagination totals, cross-organization coverage, and secret redaction. PostgreSQL integration tests require TEST_DATABASE_URL and could not run in this workspace.

**Acceptance:** The SaaS console can inspect platform events already being written, and new platform mutations use the same audited service.

### Task 3: Implement organization suspension and reactivation

**Files**
- Modify: backend/routes/platform_organizations.py, backend/services/principals.py, backend/services/tenant_context.py, and the relevant auth path in backend/routes/auth.py
- Test: extend regression_tests/test_platform_organizations.py, regression_tests/test_platform_transactions.py, and tenant-context/auth tests

- [x] Add a validated status request with action and required reason; use the existing organizations.is_active field and record the reason in platform_audit_events.
- [x] Add a platform endpoint for activate/suspend that is idempotent for the requested state and returns 404 for an unknown organization.
- [x] Carry organization activity into the resolved company principal and reject suspended organizations in the shared tenant authorization boundary. Ensure login does not create a usable tenant session for a suspended organization.
- [x] Keep platform transactions independent of that organization’s state so the platform admin can reactivate it.
- [x] Add regression coverage for existing sessions, new login attempts, reactivation, repeated state changes, unauthorized callers, refresh behavior, invitation acceptance, and platform-only tenant denial. PostgreSQL integration tests require TEST_DATABASE_URL and could not run in this workspace.

**Acceptance:** Suspension blocks all tenant-scoped routes consistently; reactivation restores tenant access without changing membership roles or bypassing RLS.

### Task 4: Improve the organization directory without opening tenant data

**Files**
- Modify: backend/routes/platform_organizations.py, backend/schemas/platform_organizations.py, backend/services/platform_audit.py, static/superadmin.html, static/js/pages/superadmin.js, static/superadmin.css
- Add: backend/postgres_migrations/v0014_organization_invitation_mail_counts.py and update the runtime-role grant instructions
- Test: regression_tests/test_platform_organizations.py and regression_tests/test_superadmin_ui.cjs

- [x] Add server-side search, status filters, and bounded pagination to GET /api/platform/organizations.
- [x] Add aggregate organization detail needed for operations (status, creation time, active-member count, pending/failed invitation-mail counts); do not expose inventory rows or enumerate company users.
- [x] Add clear active/suspended states and a reason-confirmed suspend/reactivate flow in the SaaS UI.
- [x] Keep company-role change as a narrow target-ID operation, require a support reason, preserve owner-transfer protection, and audit it. Do not add a tenant roster browser under this plan.
- [x] Test pagination/filter validation, stale updates, organization-not-found behavior, and no user/inventory payload in organization responses. PostgreSQL integration execution requires a disposable TEST_DATABASE_URL and remains pending in this workspace.

**Acceptance:** Platform admins can locate and manage organization state while company data stays behind company membership and RLS.

### Task 5: Finish platform-admin management in the SaaS UI

**Files**
- Modify: backend/routes/platform_organizations.py, backend/schemas/invitations.py or a focused platform-admin schema module, static/superadmin.html, static/js/pages/superadmin.js, static/superadmin.css
- Test: regression_tests/test_platform_organizations.py and regression_tests/test_superadmin_ui.cjs

- [x] Add an exact-email grant operation so the UI can grant an existing identity without adding a global user-directory endpoint. Keep current admin listing limited to platform admins.
- [x] Wire GET /api/platform/admins and grant/revoke controls into the SaaS-only UI with explicit confirmation and clear pending/error states.
- [x] Preserve the last-active-admin protection and prohibit self-removal; add regression coverage for duplicate grants, unknown/archived identities, last-admin removal, self-removal, and concurrent revoke attempts. PostgreSQL integration execution requires a disposable TEST_DATABASE_URL and remains pending in this workspace.
- [x] Record grant/revoke events through the shared audit service.

**Acceptance:** Platform-admin access is manageable from the SaaS console without exposing a searchable tenant user directory.

### Task 6: Move system announcements and existing global security settings onto platform routes

**Files**
- Create or modify: backend/routes/platform_settings.py and backend/services/announcements.py
- Modify: main.py, static/superadmin.html, static/js/pages/superadmin.js
- Test: regression_tests/test_security_settings.py, announcement tests, and regression_tests/test_superadmin_ui.cjs

- [x] Use the existing PostgreSQL platform_announcements table for PostgreSQL-mode notice management and delivery, preserving scheduling, audience, role targeting, revision conflicts, and dismissal behavior. Keep SQLite’s existing persistence path until cutover.
- [x] Add platform-authorized management endpoints and preserve the public read endpoint/contract used by the rest of the app.
- [x] Port only the existing global session/security settings that have defined product behavior; run them through authenticated_platform_transaction and audit mutations.
- [x] Do not claim MFA or global password-policy enforcement until the authentication flow actually enforces it. Design those controls separately, with step-up authentication before destructive operations.
- [x] Add regression coverage for role targeting, anonymous delivery, schedule boundaries, revision conflicts, settings validation, audit allowlists, and SQLite UI route compatibility. PostgreSQL integration tests could not be executed in this workspace because pytest and TEST_DATABASE_URL are unavailable; existing SQLite and UI suites remain the executable compatibility checks.

**Acceptance:** SaaS platform admins can manage global notices and supported security settings, while tenant announcements and company timezone settings remain separate. The migration importer continues to leave pre-existing company announcements tenant-scoped; it does not automatically promote them to platform-wide notices.

---

### Task 7: Design controlled, audited tenant support access

**Implementation status:** Approved design and implementation are tracked in
[`2026-10-28-controlled-platform-support-access-design.md`](../specs/2026-10-28-controlled-platform-support-access-design.md)
and [`2026-10-28-controlled-platform-support-access.md`](2026-10-28-controlled-platform-support-access.md).
The first implementation slice is fixed at 15 minutes and remains read-only.

**Scope:** This is an approved product direction, but it needs a focused security design and separate implementation slice. It does not grant routine tenant-data browsing to platform admins.

**Design requirements**
- Platform admins may view platform-level tenant metadata in the normal console. Tenant user or inventory data requires an explicit support session for one organization and a documented reason.
- Start with read-only access to a narrowly listed set of support resources. Do not create a generic tenant browser, database console, or customer-identity impersonation session.
- Keep the platform administrator authenticated as themselves. Every support request must retain both the actor and target organization; show a persistent support-access banner and provide an immediate end/revoke action.
- Store support-session state server-side, bind it to the authenticated platform session and one organization, and impose a fixed 15-minute maximum lifetime. Never encode support authority in a client-editable JWT claim.
- Authorize every support request against that live support session and its allowed resource/action set. Expiry, revocation, platform-admin revocation, or logout must end access. Tenant transactions must remain explicitly scoped and must not use a blanket RLS bypass.
- Audit support-session start, each data access (resource/action), denied access, and end/expiry, including actor, organization, reason, timestamp, and request correlation ID. Redact sensitive field values from audit details.
- Any write capability, broader resource set, or true impersonation requires a separate design and explicit approval; do not silently expand the read-only workflow.

**Implementation planning steps**
- [x] Inventory concrete support cases and agree on the minimum resource/field allowlist before coding.
- [x] Trace how the allowlisted reads can be performed while preserving organization scoping and PostgreSQL RLS; if this requires a new trusted database policy/context, document and review that policy before implementation.
- [x] Specify the server-side support-session lifecycle, maximum lifetime, revocation behavior, audit schema, UI banner, and failure behavior.
- [x] Write abuse-case tests for cross-tenant access, missing/expired/revoked sessions, actor revocation, logout, context cleanup after errors, and attempts to write or access unlisted resources.
- [x] Put the resulting approved design in a separate spec and implementation plan; then implement the narrow read-only workflow in its own reviewable PR.

**Acceptance:** A support case can be handled against one tenant with explicit authorization and an audit trail, while ordinary platform-admin access still reveals no tenant roster or inventory.

---

## Later, Separate Design Work

These are not prerequisites for the core platform console and should each get its own design/plan before implementation:

1. **Support-access expansion:** Task 7 covers the initial read-only workflow. Broader data access, write actions, or true impersonation remain separate design decisions; the attached JWT example is incompatible with the app’s opaque server-side session credentials and does not provide adequate auditability.
2. **Feature flags and usage limits:** Define the actual flags/metrics and override semantics first. Use typed, tenant-scoped entitlements with expiry and audit history; avoid arbitrary per-tenant constants.
3. **Billing portfolio and overrides:** Build after the separately scoped Stripe billing service exists. Plan changes, credits, and refunds must call idempotent billing operations and reconcile with provider state; do not add an unrelated admin-side balance table.
4. **Tenant termination/data erasure:** Define retention, export, recovery window, legal hold, backup handling, and evidence requirements. Do not provide instant hard deletion as a generic button.
5. **Integration/OAuth controls:** Add only when integrations and webhook credentials exist, with per-connection revoke/rotate controls.
6. **Infrastructure and multi-region configuration:** Keep secrets, deployment variables, and region routing in the infrastructure control plane. The app may expose safe versioned product settings, never secret values.
7. **Operational health dashboard:** Define supported health signals (for example, API availability, database connectivity, mail delivery age/failures, and recent error rates) and their authoritative sources before adding a dashboard. Do not infer health from organization counts.

## Design Recommendations

- Keep superadmin as the only platform role for now. The document’s support-admin and billing-admin rows describe future audiences, not permissions the current product can safely use today.
- Require strong administrator authentication and step-up verification before granting platform status or performing destructive operations. MFA is not currently implemented, so treat it as a prerequisite for impersonation and data erasure rather than implying it is already enforced.
- Treat platform_audit_events as application audit history, not independently immutable evidence. Restrict runtime database permissions to append/read as appropriate and consider external append-only export when compliance needs justify it.
- Use explicit organization-scoped operations for support work. Never use a global RLS bypass or an impersonation JWT that silently turns a platform administrator into the customer’s identity.
