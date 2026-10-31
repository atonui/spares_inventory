# Inventory SaaS Foundation Design

## Purpose

Turn the existing single-company inventory application into an invitation-only SaaS pilot while preserving its current customer data and operational behavior. Build the tenant-aware backend and email onboarding foundation before starting the native mobile application. The web application and a future mobile client must use the same company permissions and inventory rules.

This document records the agreed SaaS scope and the handover boundary. It is a design, not an implementation plan or authorization to change production infrastructure.

## Current constraints

- The application is FastAPI with AlpineJS and SQLite, deployed on Railway.
- Users currently have one global role (`engineer`, `manager`, `admin`, or `superadmin`). There are no companies, memberships, or tenant ownership columns.
- Organization settings and site announcements are currently installation-wide.
- Authentication is based on server-side sessions in an HTTP-only cookie. Existing web mutations use CSRF protection.
- Email currently uses synchronous SMTP for password reset only. There is no invitation/verification workflow or durable mail queue.
- The application uses explicit SQLite migrations and raw SQL. This work is not a wholesale rewrite or ORM conversion.

## Agreed product scope

- New companies are provisioned by a platform administrator and begin with an emailed invitation to their first company owner. There is no public company signup in the pilot.
- Company owners and administrators can invite staff by email.
- Each user account belongs to exactly one company in v1. The database model should permit a later move to multiple memberships without requiring that feature now.
- Company roles are `owner`, `admin`, `manager`, and `engineer`. A separate `platform_admin` role handles SaaS operations and does not itself grant routine access to company inventory.
- The current installation becomes the first company. Existing users, company data, and company audit history move into it.
- Transactional email covers company invitations, email verification, email changes, and password resets. Marketing email and stock-alert email are out of scope.
- Subscription billing, public self-service signup, native mobile implementation, offline stock writes, and app-store submission are separate later work.

## Tenancy and database design

Move to PostgreSQL with a shared database and shared tables for the pilot. Every company-owned record carries an immutable `organization_id`. Organization IDs are stable UUIDs so tenant identity remains independent of local record IDs.

The authenticated user is resolved to their active company on the server. The application never trusts a request-supplied organization ID as proof of access. Tenant-scoped services and SQL include the resolved company, and PostgreSQL row-level security (RLS) provides a second enforcement layer. RLS is enabled on tenant tables and uses transaction-local tenant context so pooled connections cannot retain another request's company. The web application's database role is restricted and is not a table owner, superuser, or `BYPASSRLS` role. Migrations use a separate privileged role. Composite foreign keys or equivalent constraints prevent records from one company being linked to another company's records.

Keep a narrow database-routing boundary around tenant operations so a later move to one database per company remains possible. That later move is a planned data and operations project, not a transparent toggle. It will require moving tenant data, maintaining central identity and company routing, and handling cross-company reporting and database upgrades. The pilot does not provision separate databases.

Tenant data includes stores and store types, parts, inventory, work orders, stock movements, transfers, counts, equipment and equipment history, organization settings, company announcements, and company activity/audit events. All reads, writes, reports, imports, exports, and restores are company-scoped. Tenant data relationships must remain within the same organization. Natural-key uniqueness (such as part numbers, work-order numbers, and equipment serial numbers) is scoped to the organization rather than shared globally.

Global data includes user identities, login sessions, platform configuration, system logs, platform audit events, platform announcements, and organization provisioning records. Company timezone/default settings move from the current singleton setting to organization settings; per-user profile preferences remain with the user identity.

## Identity, roles, and onboarding

Email remains globally unique for user identity. A membership record binds a user to one organization and holds the company role. A uniqueness constraint enforces one membership per user in v1. Platform administrator status is stored separately from company role, so changing a company role cannot grant or revoke platform access.

The first company is created by platform administration. Its first owner accepts a single-use, expiring invitation. Company owners/admins can invite staff only into their own company. Invitation tokens are bound to the normalized invited email and organization, stored as hashes, and invalidated after acceptance or expiry. An invitation proves control of that email address. Invitation links do not create access to any other company.

Company owners control company membership and organization-wide settings. Company admins retain current admin functions within their company. Managers and engineers keep their existing operational permissions, scoped to their company. A permission audit is required because existing route checks often inspect the global role directly.

The selected `superadmin` account becomes a `platform_admin` and remains outside all company memberships. A separate legacy administrator is selected as the first company's `owner`; platform and tenant identities are mutually exclusive. Existing remaining `admin`, `manager`, and `engineer` accounts become company roles. Platform administrators can provision companies and operate global settings and broadcasts; they do not receive ordinary company inventory browsing through their platform role. Existing database-level tools remain platform-only and auditable; arbitrary SQL access must not be available to company users.

## Transactional email

Use a provider-neutral email service with Resend as the first provider, after verifying a sender domain dedicated to this product. Do not reuse another product's credentials or expose provider secrets in application responses or logs.

Persist outbound mail in a transactional outbox in the same database transaction as the action that requires the email. A worker claims pending messages, sends them, records delivery state, retries temporary failures with a bounded backoff, and exposes failures to platform operations without exposing tokens. A failed provider call must not leave a user or company half-created. The worker resumes pending messages after restart.

Verification and password-reset tokens are random, single-use, time-limited, stored as hashes, and excluded from logs. Email-change verification does not replace the existing address until the new address is verified. Password-reset requests return the same public response whether or not the account exists. Invitation and reset endpoints are rate-limited. New invitation acceptance and email changes require email proof. Existing migrated users are not falsely marked verified; their current login access is preserved during the pilot migration, while verification is required for email changes and future invitation flows.

## Data migration and cutover

The existing production SQLite database is the source for the initial organization. First rehearse against a copy of a current backup. The rehearsal must cover every table and setting, preserve IDs where practical, map company settings and announcements intentionally, and invalidate old password-reset tokens. Existing sessions are revoked at cutover so every user signs in again under the new company context.

Before production cutover, take and verify a restorable backup. Put the application into read-only maintenance mode, migrate the final SQLite snapshot to PostgreSQL, and verify row counts, inventory totals by store and part, movement/transfer states, user memberships, audit history, foreign-key integrity, and tenant isolation. Only reopen writes after the checks pass. Keep the original snapshot for rollback; do not dual-write to SQLite and PostgreSQL. If post-cutover writes have begun, rollback must first preserve/reconcile those writes rather than silently restore the old snapshot.

No data is consolidated or deleted as part of tenant assignment. All existing operational data goes into the first organization. Platform-only system logs remain global. Ambiguous legacy records must be identified in rehearsal and explicitly classified before cutover.

## Announcements and platform administration

The current site-wide announcement becomes a company announcement for the first organization because that is the audience it served before SaaS. Add a distinct platform announcement for messages intended for all companies or public visitors. Platform settings and broadcasts remain in platform administration; organization settings and company announcements are controlled within the company permission boundary.

Company users must not access platform-wide database backups, restores, system settings, account controls, or broadcasts. Platform actions that affect tenant data are logged with actor, company scope where applicable, action, result, and timestamp. Platform-wide backup/restore remains a privileged maintenance operation.

## Delivery sequence

1. **Tenant foundation:** PostgreSQL database boundary, organizations/memberships, tenant-scoped authorization, RLS, company roles, and separation of platform administration.
2. **Company onboarding and email:** organization provisioning, owner/staff invitations, email verification, password reset, and outbox worker.
3. **Migration and pilot cutover:** rehearsal, integrity and isolation verification, production cutover, and rollback procedure.
4. **Mobile handover:** after the tenant-aware API is stable, write a separate mobile design and plan. That work will cover native authentication and secure credential storage, API contracts, idempotent stock writes, pagination, phone testing, and store packaging. This document does not authorize or specify the mobile implementation.

No billing or subscription enforcement is included. The pilot is manually provisioned and does not charge tenants through the application.

## Acceptance criteria

- A user can access only the single company membership assigned to their account, regardless of path IDs, filters, imports, exports, or report parameters.
- RLS denies tenant reads and writes without a valid transaction-local company context; pooled connections cannot leak context between requests.
- Database constraints prevent cross-company references for every tenant relationship.
- Existing role behavior is preserved within the first company; platform permissions do not leak into company roles.
- An invitation creates exactly one company membership only after the invited user proves control of the invited email and accepts an unexpired token.
- Email provider outages leave messages queued for retry and do not partially create invitations/accounts or disclose account existence.
- A migration rehearsal preserves all expected records and inventory balances and verifies the rollback backup before production cutover.
- Platform announcements reach the configured global audience; the existing notice remains visible to the original company audience after migration.
- Tests cover cross-tenant reads and writes for every route family, background worker, report, import/export path, admin action, and tenant relationship.

## Handover

The first implementation plan should cover the tenant foundation and the SQLite-to-PostgreSQL migration. Email onboarding should have its own implementation plan once the foundation interfaces are agreed. Keep the native mobile project in a separate chat after this SaaS scope and the tenant-aware API contracts are established; this document is the shared starting point.
