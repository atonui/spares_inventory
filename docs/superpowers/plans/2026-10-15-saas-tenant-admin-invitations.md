# SaaS Tenant Administration and Invitations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver tenant-scoped company user/settings administration, strict platform-admin separation, and invitation-only company onboarding on PostgreSQL.

**Architecture:** Extend the immutable PostgreSQL migration chain with tenant invitations and a durable mail outbox. Resolve company and platform authority from server-side sessions through separate transaction boundaries. Keep existing SQLite behavior available until a separate legacy-data importer and cutover are reviewed; make SaaS-only routes explicitly PostgreSQL-only.

**Tech Stack:** FastAPI, Python 3.12, PostgreSQL 17, Psycopg 3.3.6, Pydantic v2, AlpineJS, pytest, Node-based frontend regression tests, Resend HTTP API, `cryptography==50.0.2` Fernet encryption.

**Spec:** `docs/superpowers/specs/2026-10-15-saas-tenant-admin-and-invitations-design.md`

## Global Constraints

- New companies are provisioned by a platform administrator and begin with an emailed invitation to their first company owner. There is no public company signup in the pilot.
- Each user account belongs to exactly one company in v1.
- Company roles are `owner`, `admin`, `manager`, and `engineer`; a separate `platform_admin` role does not itself grant routine access to company inventory.
- Company settings in this slice are limited to business timezone and organization display name; per-user display timezone remains a personal preference.
- Use the product's dedicated transactional sender and Resend as the first provider. Do not reuse credentials from another product.
- Invitation tokens are random, single-use, time-limited, bound to normalized email and organization, and never written to logs.
- Invitation links expire after 7 days. Invite creation is limited to 10 requests per actor per hour; acceptance is limited to 5 attempts per IP per minute.
- Mail delivery makes at most 6 attempts with retry delays of 60, 300, 1,200, 3,600, and 14,400 seconds; an exhausted message remains visible as terminal failure.
- Invitation, membership, settings, and audit paths use resolved tenant context and PostgreSQL RLS; request-supplied organization IDs never grant access by themselves.
- Keep legacy SQLite-mode behavior until the separate migration importer and cutover are reviewed; do not change production infrastructure in this plan.
- Add PostgreSQL migrations after v0003 and never edit checksummed migrations already merged in PR #135.
- Do not dual-write between SQLite and PostgreSQL, provision separate tenant databases, build billing/public signup, or start native mobile work in this plan.

## Review Focus

- A platform-only user or a tampered organization ID must never expose company data; cover in Tasks 2 and 5 with platform-only and invitation-context tests.
- Email normalization collisions and an email already assigned to another company must not create a second identity or membership; cover in Task 5.
- Replayed, expired, canceled, resent, or concurrently accepted tokens must not create duplicate memberships; cover in Task 5.
- Deactivated members and stale settings revisions must lose access or fail without changing another tenant; cover in Task 3.
- Worker crashes, provider outages, and missing/wrong encryption keys must not lose queued mail or disclose invitation tokens; cover in Tasks 1 and 4.

---

### Task 1: PostgreSQL invitation/outbox schema and protected mail payloads

**Files:**
- Create: `backend/postgres_migrations/v0004_tenant_administration.py`
- Modify: `backend/postgres_migrations/registry.py`
- Modify: `requirements.txt`
- Modify: `.env.example`
- Modify: `backend/config.py`
- Create: `backend/services/mail_payloads.py`
- Test: `regression_tests/test_postgres_migrations.py`
- Test: `regression_tests/test_mail_payloads.py`

**Interfaces:**
- Produces `encrypt_mail_payload(payload: dict, key: str) -> str` and `decrypt_mail_payload(ciphertext: str, key: str) -> dict` using Fernet; the configured `MAIL_PAYLOAD_ENCRYPTION_KEY` is separate from `SECRET_KEY`.
- Migration v0004 creates `organization_invitations` with organization, normalized email, company role, token hash, inviter, expiry, accepted/canceled timestamps, tenant-aware uniqueness, and RLS. It creates a global `mail_outbox` with encrypted payload, message type, recipient, idempotency key, status, attempt count, availability/lease/claim-token/sent timestamps, and sanitized last-error code.
- `organization_settings.revision` remains the revision for both timezone and organization display-name changes; no revision is added to an already applied migration.

- [ ] **Step 1: Write failing schema and encryption tests.** Add `test_v0004_pending_invitation_email_is_unique_per_organization`, asserting a duplicate pending normalized address is rejected while the same address may exist in a different organization. Add `test_invitation_rls_denies_reads_without_matching_context`. Add `test_mail_payload_round_trips_and_rejects_tampering`, asserting correct-key round-trip, wrong-key failure, and ciphertext alteration failure.
- [ ] **Step 2: Run the focused tests and confirm RED.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_postgres_migrations.py regression_tests/test_mail_payloads.py -q`. Expected: missing migration and mail-payload interfaces, not fixture/setup errors.
- [ ] **Step 3: Add v0004, registry registration, settings, dependency, and payload cipher.** Pin `cryptography==50.0.2`; make `MAIL_PAYLOAD_ENCRYPTION_KEY` optional for SQLite startup but mandatory and validated before PostgreSQL invitation enqueue or worker claim. Never log key material or decrypted payloads.
- [ ] **Step 4: Run the focused tests and confirm GREEN.** Re-run the command from Step 2; expected: schema constraints, tenant RLS, encryption, tamper, and wrong-key tests pass.
- [ ] **Step 5: Commit** as `feat: add tenant invitation and mail schema`.

### Task 2: Separate company and platform authorization transactions

**Files:**
- Create: `backend/services/platform_transactions.py`
- Modify: `backend/services/authorization.py`
- Modify: `backend/services/authenticated_transactions.py`
- Modify: `backend/services/tenant_context.py`
- Test: `regression_tests/test_authorization_guards.py`
- Test: `regression_tests/test_platform_transactions.py`

**Interfaces:**
- Produces `require_company_admin(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal`, allowing only active `owner` or `admin` company roles.
- Produces `require_platform_admin(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal`, checking the server-resolved `is_platform_admin` flag and never deriving platform status from a company role.
- Produces the context manager `authenticated_platform_transaction(get_connection, *, session_token: str | None, expected_user_id: int | None = None, readonly: bool = False)`, yielding `(conn, principal)` after validating the current session and platform record but without setting `app.organization_id`.
- Company database transactions continue to require a company principal and set transaction-local RLS context; legacy SQLite guards retain their current `admin`/`superadmin` compatibility.

- [ ] **Step 1: Write failing authorization tests.** Add `test_company_admin_guard_accepts_only_owner_and_admin`, `test_platform_admin_status_is_independent_of_company_role`, `test_platform_transaction_allows_platform_only_principal_without_tenant_context`, `test_platform_transaction_rejects_non_platform_user`, and `test_platform_only_principal_cannot_start_company_transaction`.
- [ ] **Step 2: Run focused tests and confirm RED.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_authorization_guards.py regression_tests/test_platform_transactions.py -q`. Expected: missing explicit platform transaction and incorrect guard results.
- [ ] **Step 3: Implement the separate platform transaction boundary and explicit role guards.** Keep global platform queries outside tenant context; company routes must continue to use authenticated tenant transactions.
- [ ] **Step 4: Run focused and compatibility tests.** Re-run Step 2 and `pytest regression_tests/test_superadmin_router.py regression_tests/test_users_router.py -q`; expected: platform-only denial/authorization coverage passes and SQLite superadmin behavior remains intact.
- [ ] **Step 5: Commit** as `feat: separate platform and company authorization`.

### Task 3: Tenant-scoped company users and organization settings API

**Files:**
- Modify: `backend/routes/users.py`
- Modify: `backend/schemas/users.py`
- Create: `backend/routes/organization_settings.py`
- Create: `backend/schemas/organization_settings.py`
- Modify: `backend/routes/timezone_settings.py`
- Modify: `main.py`
- Test: `regression_tests/test_tenant_user_administration.py`
- Test: `regression_tests/test_tenant_organization_settings.py`
- Test: `regression_tests/test_users_router.py`
- Test: `regression_tests/test_timezone_settings.py`

**Interfaces:**
- PostgreSQL `GET /api/users` returns company members with `company_role` as the response `role`; `PUT /api/users/{target_user_id}` updates the target user's profile fields and membership role only after confirming membership in the caller's organization.
- PostgreSQL `DELETE /api/users/{target_user_id}` deactivates that membership and revokes the user's active sessions; restore reactivates that same membership and does not restore stale sessions.
- Produces `OrganizationSettingsUpdate(name: str, business_timezone: str, expected_revision: int)` and `GET/PUT /api/organization/settings`; updates change organization name and business timezone under one revision check and tenant-scoped audit event.
- Produces owner-only `POST /api/organization/owner-transfer`; it atomically promotes one active member to owner and demotes the prior owner to admin. Generic role updates cannot assign or remove owner, and an organization always retains one active owner.
- Company admins may invite or manage managers/engineers; only owners may invite or change admin roles, deactivate admins, or transfer ownership.
- Existing `/api/timezone-context` and `/api/organisation/timezone` contracts remain supported. SQLite routes keep their current single-company behavior.

- [ ] **Step 1: Write failing tenant route tests.** Add `test_company_user_update_rejects_foreign_membership_id`, `test_company_role_update_changes_membership_not_global_user_role`, `test_member_deactivation_revokes_sessions`, `test_admin_cannot_modify_owner_or_admin_membership`, `test_owner_transfer_keeps_exactly_one_active_owner`, `test_manager_cannot_manage_users_or_settings`, `test_company_settings_update_is_revision_guarded`, and `test_company_settings_are_isolated_between_organizations`.
- [ ] **Step 2: Run focused tests and confirm RED.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_tenant_user_administration.py regression_tests/test_tenant_organization_settings.py -q`. Expected: tenant mutation and settings routes are missing or still use the legacy global role.
- [ ] **Step 3: Implement membership-aware user operations and settings routes.** In PostgreSQL paths, never query or write `users.role`; verify targets through the caller's `organization_memberships` row before changing global identity profile fields.
- [ ] **Step 4: Run focused and existing regressions.** Re-run Step 2 and `pytest regression_tests/test_users_router.py regression_tests/test_timezone_settings.py regression_tests/test_tenant_timezone_settings.py -q`; expected: tenant isolation and old SQLite contracts pass.
- [ ] **Step 5: Commit** as `feat: scope company users and settings`.

### Task 4: Durable invitation mail outbox and Resend worker

**Files:**
- Create: `backend/services/mail_outbox.py`
- Create: `backend/services/mail_delivery.py`
- Create: `backend/mail_worker.py`
- Modify: `backend/config.py`
- Modify: `.env.example`
- Test: `regression_tests/test_mail_outbox.py`
- Test: `regression_tests/test_mail_delivery.py`

**Interfaces:**
- Produces `enqueue_mail(conn, *, organization_id, message_type, recipient_email, encrypted_payload, idempotency_key) -> int`.
- Produces `claim_pending_mail(conn, *, now, lease_seconds: int = 60) -> dict | None`, `mark_mail_sent(conn, *, mail_id: int, claim_token: str) -> None`, and `mark_mail_failed(conn, *, mail_id: int, claim_token: str, retry_at, error_code: str, terminal: bool = False) -> None`.
- Produces `send_mail(message: dict, *, api_key: str, from_address: str, http_transport) -> None`; the initial adapter sends invitation mail through Resend and exposes only sanitized provider error codes.
- Worker entry point is `python -m backend.mail_worker`; it claims with a lease using PostgreSQL `FOR UPDATE SKIP LOCKED`, applies bounded retry/backoff, and resumes pending mail after restart.
- Retry delays are exactly 60, 300, 1,200, 3,600, and 14,400 seconds; after 6 failed attempts the row becomes terminal and remains inspectable by platform operations.

- [ ] **Step 1: Write failing outbox/worker tests.** Add `test_enqueue_and_claim_mail_preserves_payload_ciphertext`, `test_concurrent_workers_claim_distinct_messages`, `test_provider_failure_retries_then_marks_terminal_after_six_attempts`, `test_expired_claim_can_be_reclaimed`, `test_missing_payload_key_does_not_consume_pending_mail`, and `test_worker_logs_never_include_decrypted_invitation_token`.
- [ ] **Step 2: Run focused tests and confirm RED.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_mail_outbox.py regression_tests/test_mail_delivery.py -q`. Expected: missing queue/worker behavior or duplicate claims.
- [ ] **Step 3: Implement the queue service, Resend adapter, and worker command.** Use bounded retries; persist no provider response body or credential; use injected transport in tests so no external email is sent.
- [ ] **Step 4: Run focused tests and confirm GREEN.** Re-run Step 2; expected: lease, retry, restart, provider sanitization, and token-redaction tests pass.
- [ ] **Step 5: Commit** as `feat: deliver transactional mail from outbox`.

### Task 5: Invitation service and platform company provisioning API

**Files:**
- Create: `backend/services/invitations.py`
- Create: `backend/routes/invitations.py`
- Create: `backend/schemas/invitations.py`
- Create: `backend/routes/platform_organizations.py`
- Modify: `backend/routes/users.py`
- Modify: `backend/routes/superadmin.py`
- Modify: `backend/schemas/superadmin.py`
- Modify: `main.py`
- Test: `regression_tests/test_invitation_service.py`
- Test: `regression_tests/test_invitation_routes.py`
- Test: `regression_tests/test_platform_organizations.py`
- Test: `regression_tests/test_superadmin_router.py`

**Interfaces:**
- Produces `create_invitation(conn, *, organization_id, invited_by: int, email: str, company_role: str, frontend_url: str) -> dict`, storing only the token hash in the tenant invitation row and atomically enqueueing an encrypted invitation message.
- Produces `accept_invitation(conn, *, organization_id, token: str, name: str, password: str, password_hash, password_verify) -> dict`; organization ID is an untrusted lookup scope only, and acceptance succeeds only when the token hash matches an unexpired invitation under that same RLS context.
- Produces `create_organization_with_owner_invitation(conn, *, name: str, slug: str, owner_email: str, actor_user_id: int, frontend_url: str) -> dict`, creating organization, default settings, owner invitation, outbox message, and platform audit event atomically.
- Adds `POST /api/users/invitations`, `GET /api/users/invitations`, resend/cancel operations, `POST /api/invitations/accept`, `POST /api/platform/organizations`, `PUT /api/platform/organizations/{organization_id}/members/{user_id}/role`, and `PUT/DELETE /api/platform/admins/{user_id}`. PostgreSQL `POST /api/users` no longer creates password-bearing accounts; SQLite retains the legacy path until cutover.
- Existing `/api/superadmin` routes use the platform transaction and `platform_admins` on PostgreSQL. Global user/session controls use identity tables; global configuration, announcements, and audit views use platform tables. Platform dashboards do not aggregate tenant inventory. SQLite-only database backup/restore/vacuum and arbitrary SQL routes return explicit HTTP 503 on PostgreSQL until the operations slice supplies safe PostgreSQL mechanisms.
- Platform company-role changes require an explicit organization and update that organization's membership. Platform-admin grants/revocations change only `platform_admins`; the last active platform admin cannot remove their own status.
- Invitations allow an owner to invite admin/manager/engineer, and an admin to invite manager/engineer. Platform provisioning may invite the first owner. Acceptance creates an identity only after a valid token; if a global identity already exists, the submitted password must verify and the identity must have no membership in another company.
- Set `INVITATION_TTL_SECONDS = 604800`, invite rate limit `10/hour` per actor, and accept rate limit `5/minute` per IP. Email normalization lowercases and trims before identity/invitation checks.

- [ ] **Step 1: Write failing service/route tests.** Add `test_platform_provisioning_rolls_back_when_invitation_enqueue_fails`, `test_company_invite_uses_resolved_organization_not_body_id`, `test_invitation_acceptance_rejects_changed_organization_scope`, `test_invitation_is_single_use_and_email_bound`, `test_invitation_is_expired_after_seven_days`, `test_resend_cancels_previous_token`, `test_existing_identity_must_prove_password_and_cannot_join_second_company`, `test_company_admin_cannot_invite_admin_or_owner`, `test_invitation_errors_do_not_disclose_account_existence`, `test_invitation_response_and_logs_never_include_raw_token`, `test_platform_only_admin_gets_no_inventory_context`, `test_postgres_superadmin_routes_require_platform_admin`, `test_postgres_database_maintenance_routes_return_503`, `test_platform_dashboard_does_not_aggregate_inventory`, `test_platform_role_change_requires_explicit_organization`, and `test_last_platform_admin_cannot_remove_self`.
- [ ] **Step 2: Run focused tests and confirm RED.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_invitation_service.py regression_tests/test_invitation_routes.py regression_tests/test_platform_organizations.py regression_tests/test_superadmin_router.py -q`. Expected: invitation/provisioning routes and PostgreSQL platform separation checks are missing.
- [ ] **Step 3: Implement token, invitation, acceptance, provisioning, and audit flows.** Normalize email before lookup; rate-limit invite and acceptance endpoints; never return raw token values in API responses; set tenant context from the candidate organization only to constrain an exact token-hash lookup.
- [ ] **Step 4: Run focused tests and confirm GREEN.** Re-run Step 2; expected: tenant boundaries, atomic rollback, invitation replay/expiry, role restrictions, platform-route protection, and account proof tests pass.
- [ ] **Step 5: Commit** as `feat: add invitation-only tenant onboarding`.

### Task 6: Web invitation and platform-admin workflows

**Files:**
- Modify: `static/js/inventory/users-admin.js`
- Modify: `static/js/pages/superadmin.js`
- Modify: `static/index.html`
- Create: `static/accept_invitation.html`
- Create: `static/js/pages/accept-invitation.js`
- Test: `regression_tests/test_users_admin_ui.cjs`
- Test: `regression_tests/test_superadmin_ui.cjs`
- Test: `regression_tests/test_invitation_acceptance_ui.cjs`

**Interfaces:**
- Company admin UI invites by email and company role, lists pending invitations, and supports resend/cancel. It does not ask admins to set another user's password.
- Platform admin UI provisions an organization and initial owner invitation through `/api/platform/organizations`; platform dashboard actions remain separate from company inventory views.
- Invitation acceptance page reads only the invitation token and organization identifier from the link, collects name/password for a new identity or password proof for an existing identity, and submits to `/api/invitations/accept` without storing the token after completion.

- [ ] **Step 1: Write failing frontend tests.** Add `test_company_admin_invites_without_setting_password`, `test_platform_provision_form_calls_platform_endpoint`, and `test_invitation_acceptance_submits_token_once_and_clears_sensitive_fields`.
- [ ] **Step 2: Run frontend tests and confirm RED.** Run `node regression_tests/test_users_admin_ui.cjs && node regression_tests/test_superadmin_ui.cjs && node regression_tests/test_invitation_acceptance_ui.cjs`. Expected: invitation and acceptance states are absent.
- [ ] **Step 3: Implement the company invite, platform provisioning, and acceptance surfaces.** Keep existing CSRF handling, loading/error states, keyboard accessibility, and no local token persistence.
- [ ] **Step 4: Run frontend regressions.** Re-run Step 2 plus `node regression_tests/test_frontend_entrypoints.cjs`; expected: all UI behavior and script entrypoint checks pass.
- [ ] **Step 5: Commit** as `feat: add invitation administration screens`.

### Task 7: Full SaaS boundary verification

**Files:**
- Modify: `regression_tests/test_tenant_rls.py`
- Create: `regression_tests/test_tenant_isolation_matrix.py`
- Modify: `docs/session-authentication.md`
- Modify: `docs/environment.md`

**Interfaces:**
- Documents the app-only settings required for the invite outbox (`RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `INVITATION_BASE_URL`, `MAIL_PAYLOAD_ENCRYPTION_KEY`) and worker invocation without changing production values.
- Adds one end-to-end PostgreSQL isolation matrix for company admin, manager, engineer, platform-only, and platform-admin-with-company-membership principals across company users, settings, invitations, platform provisioning, and inventory access.

- [ ] **Step 1: Write the end-to-end isolation assertions.** Test the five principal classes above, confirm platform-only cannot access inventory, and confirm a candidate organization ID without a valid invitation token yields the same generic rejection as an invalid token.
- [ ] **Step 2: Run the focused matrix and confirm RED for any uncovered boundary.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests/test_tenant_isolation_matrix.py -q`.
- [ ] **Step 3: Add only the missing cross-route checks and document the app/worker settings.** Do not add production environment values or deployment changes.
- [ ] **Step 4: Run the full required CI suite.** Run `TEST_DATABASE_URL=postgresql://inventory_test:inventory_test@localhost:5432/inventory_test pytest regression_tests -q`; expected: all existing SQLite and PostgreSQL regressions pass.
- [ ] **Step 5: Commit** as `test: verify tenant administration boundaries`.

## Final Verification

- Run `git diff --check` and inspect `git status --short` before reporting completion.
- Confirm the new PostgreSQL migrations are append-only and the tests ran against a disposable database name ending in `_test`.
- Confirm no Railway deployment, production environment variable, customer database, SQLite-to-PostgreSQL importer, production cutover, or native mobile code was changed.
- Request a whole-branch code review after all tasks and tests pass; do not merge or deploy without the user's review.
