# SaaS Tenant Administration and Invitations Design

## Purpose

Continue the inventory SaaS API foundation after PR #135 by making company user administration and settings work with the PostgreSQL tenant model, separating platform administration from company permissions, and completing invitation-only access for new companies and staff. Keep the legacy SQLite deployment usable until a separately reviewed migration and cutover.

This design covers the first SaaS delivery slice. The legacy SQLite-to-PostgreSQL migration importer and the SaaS operational runbook remain later, separately reviewable slices. The existing CSV stock-balance import is a different feature and is not redesigned here.

## Current State

- `main` is at merge commit `b387845` for PR #135. The local checkout was clean before this design branch.
- PostgreSQL migration version 3 creates organizations, one-company-per-user memberships, platform-admin records, organization settings, company announcements, tenant constraints, and RLS policies.
- PostgreSQL authentication resolves an `AuthenticatedPrincipal` from the active session and membership. Tenant transactions set transaction-local organization context.
- The PostgreSQL branch of `GET /api/users` reads memberships, but user creation and updates still read or write `users.role`, which is not the PostgreSQL company-role model.
- `require_user_management` and `require_superadmin` still depend on the legacy global `users.role` value. Platform-only routes retain SQLite assumptions, including SQLite database backup and restore.
- PostgreSQL organization settings currently cover the business timezone and revision. User display timezone remains a personal preference.
- Password-reset email is currently synchronous SMTP. No durable outbound-mail queue or invitation workflow exists.
- The app supports SQLite for the current deployment and PostgreSQL for the new tenant foundation. PR #135 did not change production data or deployment configuration.

## Goals

1. Make company user listing, invitation, role changes, access revocation, and organization settings use the authenticated server-resolved organization and membership role.
2. Make invitation-only onboarding work end-to-end: platform administrators provision a company and invite its first owner; company owners and admins invite staff into their own company.
3. Store platform administrator status independently from company membership and role. Platform administrator status grants platform operations only; company inventory still requires an active company membership and company permission.
4. Deliver invitation emails through a durable transactional outbox with bounded retry and operationally visible delivery failures.
5. Preserve SQLite-mode behavior until the separate migration importer and cutover work are reviewed and approved. Do not change production infrastructure as part of this slice.
6. Preserve the shared PostgreSQL database design, stable organization UUIDs, and narrow tenant database-routing boundary so database-per-tenant remains a possible later migration project.

## Non-Goals

- Public company self-registration, billing, subscription enforcement, or multiple active company memberships per user.
- Migrating the existing production database or enabling PostgreSQL in production.
- Building the SQLite-to-PostgreSQL data importer in this slice. That is the next separate implementation slice.
- Reworking the CSV stock-balance importer. It receives its own tenant-isolation review after this slice.
- Email changes, general-purpose verification campaigns, marketing mail, stock-alert mail, or replacing every existing password-reset email path. The outbox is introduced for invitation delivery and designed to be extended later.
- Native mobile implementation, offline stock writes, or app-store submission.
- Company access to global system settings, platform announcements, platform audit records, backups, restores, or arbitrary database queries.

## Identity and Authorization Model

The global `users` table remains the identity record, with globally unique email. Company roles live only in `organization_memberships.company_role`; platform status lives only in `platform_admins`. Do not add a PostgreSQL `users.role` compatibility column or infer platform status from a company role.

The v1 uniqueness constraint remains one membership per user. Company roles are `owner`, `admin`, `manager`, and `engineer`. Platform administrators are platform-only identities and cannot have a company membership. A user must be transferred out of their company membership before platform administrator access is granted; a platform administrator must be revoked before the identity can join a company. A request-supplied organization ID is never proof of access.

Introduce explicit company-administration and platform-administration authorization boundaries:

- Company user and organization-setting operations require an active company principal. Owners and admins may manage company users and organization settings. Managers and engineers retain operational access only.
- Platform operations require a database-verified platform-admin record. They run without company tenant context unless an operation separately enters a company-scoped transaction after verifying an explicit target organization.
- Company admins cannot create, modify, or remove platform administrators. Platform role changes are never exposed through company user-management endpoints.
- Platform administrators have no automatic inventory access. To use tenant operations they must also have an active company membership with the required company role.
- The legacy SQLite path may continue to interpret existing `admin` and `superadmin` roles while SQLite mode is active. The PostgreSQL path must use membership and platform tables only.

For migration mapping later, the selected `superadmin` identity becomes a platform administrator with no company membership. A different legacy `admin` or `superadmin` identity must be selected as the first-organization owner. The importer requires both emails and rejects the same identity for both roles. Other legacy `admin`/`superadmin` users map to company admins, while `manager` and `engineer` map to their corresponding company roles. The PostgreSQL migration removes existing platform-admin memberships only when another active owner remains; otherwise it fails before changing the schema or data.

## Invitation and Provisioning Flow

There is no public signup. A platform administrator creates an organization and an invitation to its first owner as one logical operation. A company owner or admin invites staff only into the organization resolved from their authenticated principal.

The invitation record is tenant-owned and contains the organization, normalized invited email, intended company role, inviter, token hash, creation and expiry timestamps, and accepted or canceled state. Raw invitation tokens are random, single-use, time-limited, bound to the normalized email and organization, and never written to logs. Enforce one active invitation for a given organization and email; a resend invalidates the previous token before issuing a replacement. An invited email with an existing membership cannot be attached to another company in v1.

The acceptance endpoint verifies the token and invited email before creating an account or membership. A new user sets their name and password as part of acceptance. An existing identity must authenticate as the invited email before acceptance. Acceptance, membership creation, invitation consumption, and tenant audit recording occur atomically. Duplicate submissions are idempotently rejected or return the already-completed outcome without creating a second membership.

Company owners and admins may invite manager and engineer roles. Only the company owner may invite an admin. Company user-management operations may change or deactivate a company role, but cannot transfer platform status. Owner transfer is an explicit owner-only operation; an organization must retain an active owner. Staff membership deactivation revokes that user's active sessions so access is removed promptly.

Platform provisioning and company invitation records are auditable. Company user changes and invitation events are written to tenant-scoped activity logs. Platform provisioning and platform access changes are written to platform audit events, with organization scope when applicable.

## Transactional Email

Introduce a provider-neutral mail boundary and durable PostgreSQL outbox for invitation delivery. Use the product's dedicated transactional sender and Resend as the first provider, consistent with the previously agreed SaaS design. Do not reuse credentials from another product.

The organization and invitation are committed with a pending outbox message in one database transaction. A worker claims messages, sends them, and records delivery state, attempt count, and next retry time. Temporary errors receive bounded backoff; permanent or exhausted failures remain visible to platform operations. A provider outage does not create an active membership or lose the invitation. The worker resumes pending messages after restart. Concurrent workers cannot send the same message simultaneously.

The outbox must not expose invitation tokens in logs, metrics, API responses, or error details. Store only the token hash on the invitation record. If delivery requires retaining the raw link token between request and worker, encrypt the sensitive payload at rest with a dedicated mail-payload key and document key configuration; never store that raw token in ordinary JSON fields. Keep the mail adapter independent from the invitation service so later account-verification and reset flows can reuse it.

This slice does not migrate the existing password-reset flow to the outbox. It does not falsely mark existing migrated users as email-verified; invitation acceptance proves control of the invited address for the new membership.

## Organization Settings

Use `organizations` for company identity fields such as name and slug, and `organization_settings` for company-operational preferences. In this slice, company settings are limited to the existing business timezone and organization display name. Owners/admins may update them with revision checks and tenant-scoped audit events. Keep per-user display timezone on `users` as a personal preference.

All company settings reads and writes use the authenticated tenant transaction and RLS context. Company settings must not be stored in `system_settings`. Platform configuration and broadcasts remain exclusively in platform administration.

## API and Service Boundaries

Preserve existing web contracts where their semantics remain valid. On PostgreSQL, `/api/users` reads membership roles; mutations operate on membership rows and user identity fields rather than a nonexistent global company role. Invitation creation, resend, cancellation, and acceptance are explicit operations with response bodies that never return raw token values except as part of the emailed link.

Keep platform-provisioning and platform-user operations behind a dedicated platform router/service boundary. Do not make platform routes invoke tenant business queries under a caller's implicit platform role. A company-scoped platform action must declare and verify its target organization, set context inside its transaction, and record a platform audit event.

The PostgreSQL invitation and tenant-administration routes require PostgreSQL. When running in SQLite mode before cutover, preserve the existing legacy single-company routes and do not silently emulate tenant invitations against the old schema. Return an explicit service-unavailable response for SaaS-only operations that cannot safely run in SQLite mode.

Retain the current session cookie and CSRF protections for browser mutations. Invitation acceptance is the only unauthenticated token-bearing mutation and is rate-limited. Do not disclose whether an email address has an account or whether an invitation was valid in public responses beyond what the acceptance flow needs to proceed.

## Database and Migration Rules

- Add new PostgreSQL migrations after v0003; never edit the checksummed migrations already merged in PR #135.
- Keep tenant invitation rows under organization RLS. Keep mail delivery state in a narrowly scoped service boundary; any tenant-bearing outbox fields must not create a cross-tenant read path.
- Use organization-aware constraints for invitation and membership relationships.
- Do not add separate-database provisioning. Preserve stable organization IDs and the existing database-routing seam.
- Do not dual-write between SQLite and PostgreSQL.

## Error Handling and Security

- Invalid, expired, canceled, previously consumed, or email-mismatched invitation tokens cannot create users or memberships.
- Unauthenticated or platform-only callers cannot access company user/settings endpoints. Tenant A cannot observe or modify Tenant B users, invitations, settings, or audit events by changing path IDs, body values, filters, or tokens.
- Missing tenant context fails closed at the RLS layer. Reused connections cannot retain company context after transaction completion.
- Role escalation is rejected at both route/service authorization and database transaction boundaries. Only platform operations can change platform-admin membership.
- Mail failure cannot partially provision an organization, create a membership, or leak the invitation token.
- Passwords and raw tokens are never logged. Email addresses are normalized consistently before uniqueness and invite checks.
- Company membership removal or deactivation revokes sessions associated with that identity because v1 permits one company membership per user.

## Testing and Acceptance

PostgreSQL integration tests must prove:

1. Company owners/admins can manage only users and invitations in their own organization; managers and engineers are denied those operations.
2. Platform admins can provision organizations and initial-owner invitations, but platform status alone cannot read tenant inventory or company user lists.
3. Platform-admin and tenant membership are mutually exclusive in both provisioning routes and PostgreSQL constraints; a platform admin has no tenant principal.
4. Invitations are single-use, expiring, bound to the normalized email and organization, and safe under duplicate acceptance or resend races.
5. Email queue insertion is atomic with invitation creation; delivery retries are bounded and concurrent workers do not double-claim a message.
6. Invitation tokens and encrypted payloads do not appear in application logs or public responses.
7. Tenant RLS and constraints reject cross-organization invitation, membership, settings, and audit access.
8. Company settings revision conflicts are rejected; updates to one organization do not alter another.
9. Company-role changes cannot grant platform privileges, and platform-role changes cannot be performed through company APIs.
10. SQLite-mode legacy tests and existing authentication, CSRF, password-reset, user-management, and superadmin regression tests remain passing.

The slice is accepted when these tests pass, existing PostgreSQL tenant tests remain green, and no production database, Railway variable, deployment, or customer data has been changed.

## Delivery Sequence and Handover

1. **This slice — tenant administration and invitations:** company user/settings operations, explicit company/platform authorization, organization provisioning, invitation acceptance, and a minimal transactional outbox. Keep the work on PostgreSQL paths with safe legacy SQLite behavior.
2. **Legacy database migration importer:** build and rehearse the read-only SQLite snapshot import into an empty PostgreSQL target; preserve IDs/history/balances, map the first organization and roles, invalidate reset tokens, revoke sessions, and refuse unsafe or non-empty targets. The stock-balance CSV importer is separate.
3. **SaaS operational runbook:** document environment setup, restricted database roles, migrations, mail worker operations, monitoring, backup/restore, importer rehearsal, read-only cutover, validation gates, rollback, and incident recovery.
4. **Production cutover:** a separate decision after importer rehearsal, runbook review, verified restorable backup, and explicit approval. Do not dual-write.
5. **Native mobile:** separate design and implementation only after the tenant-aware API and authentication contracts are stable. Cover secure credentials, API contracts, idempotent stock writes, pagination, device testing, and app-store packaging.

Billing, public self-service signup, and multiple memberships remain out of scope.
