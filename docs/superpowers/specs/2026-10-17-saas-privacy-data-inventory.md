# SaaS and Native App Privacy Data Inventory

**Status:** Initial source-code inventory for privacy and store-readiness review.
**Reviewed:** 2026-10-17.

This inventory records data flows evidenced in the repository and a read-only review of the current Railway project. Purposes are described from application behavior and may be inferred. It is not a privacy policy, legal retention schedule, or store disclosure. Runtime secrets, live records, provider retention settings, and built iOS/Android manifests were not inspected.

## Data stored by the backend

### Accounts and authentication

- **Fields:** user email, display name, password hash, territory, timezone, account/archive timestamps, login and lockout state, and password-reset token plus expiry. PostgreSQL SaaS schema: `backend/postgres_migrations/v0001_core_schema.py`; legacy SQLite schema: `backend/migrations/v0001_core_schema.py`.
- **Purpose:** account sign-in, account recovery, profile display, authorization, and locale/timezone behavior (inferred from routes and use). Passwords are stored as hashes; the native client submits the password to the sign-in endpoint over HTTPS.
- **Access and lifecycle:** profile requires authentication; company user-management is role-checked. Reset tokens have a one-hour expiry and are cleared after successful reset. No general account-erasure flow or user-row retention schedule exists. SaaS account deletion remains unimplemented.

### Company membership and organization records

- **Fields:** organization name and settings; membership user/organization IDs, company role, active status, and timestamps; platform-admin assignment and platform-audit events.
- **Purpose:** tenant isolation, company authorization and configuration, and platform administration.
- **Access and lifecycle:** operational tenant tables listed in the PostgreSQL RLS policies are scoped by server-derived organization context. The `organizations` and `organization_memberships` tables are not in that RLS list; request access relies on backend principal and role authorization. Removing a member removes the membership and revokes their sessions while preserving the global account and company history. This is not account or tenant deletion. No organization-deletion operation or tenant retention schedule is implemented.

### Operational inventory and work history

- **Fields:** parts/catalog identifiers and descriptions; store names, types and location details; inventory quantities and thresholds; work-order numbers and customer names; stock movements, notes and actor references; transfers; equipment serial numbers, calibration/service details, notes, assignment and equipment history; company announcements and dismissals.
- **Purpose:** inventory, stock movement, work-order, equipment and company operations (inferred from screens, routes and schemas).
- **Access and lifecycle:** SaaS tables are tenant-scoped under RLS. Several legacy records support reversible archiving by setting `archived_at`; archiving preserves data and is not an erasure schedule. No general tenant-data retention or deletion job exists.

### Sessions and security metadata

- **Fields:** session user ID, hashed token, expiry/absolute expiry, creation and activity times, active state, IP address and user-agent; native refresh-token hashes and issue/expiry/consumption metadata; reset tokens in the user record.
- **Purpose:** authentication, session renewal, revocation and security troubleshooting.
- **Access and lifecycle:** session tokens are hashed in PostgreSQL. Logout, password reset and membership removal revoke sessions. Refresh credentials are single-use and rotation history is stored; no general cleanup schedule for expired/inactive sessions or consumed refresh records was found. Session IP and user-agent are personal/security metadata.

### Invitations and email delivery

- **Invitation fields:** organization, normalized invited email, role, inviter, token hash, creation/expiry/accepted/canceled times and accepting user. Invitation links expire after seven days.
- **Outbox fields:** recipient email, encrypted message payload containing the invitation URL/token, idempotency key, status, attempt and scheduling/lease timestamps, and sanitized error code.
- **Purpose and recipients:** invitation and password-reset delivery. Invitation mail is sent by backend code to Resend's email API; this is a code-level integration, not confirmation that production is configured to use it. Password-reset mail uses a configured SMTP relay; the actual provider is unknown from the repository/runtime review.
- **Retention/deletion:** invitation and outbox records can remain after expiry or delivery; no routine purge or retention period was found. Organization deletion would cascade to invitations/outbox if performed, but no tenant deletion flow exists. The outbox is not in the PostgreSQL tenant RLS list; verify its database-role access before SaaS rollout. Reset-email logs may include the submitted email; SMTP exception text is logged.

### Activity, audit and application logs

- **Database fields:** actor ID and username, action/resource, details, IP, user-agent, status/error and timestamp in activity records; system-log level/component/message/details/timestamp; platform-audit actor, optional organization, action/result/details/timestamp.
- **Purpose:** application history, security review, support and platform administration (inferred from routes and consumers). Activity details may contain additional record values, so their exact contents depend on the action.
- **Retention/deletion:** an administrator-triggered activity cleanup defaults to 90 days and preserves protected actions; this is not an automatic retention job. Superadmin cleanup can purge eligible activity/system logs. Platform audit retention is unspecified. Local application/audit/error files rotate at 10 MiB with 10 rotated backups per log, not by age. Railway/platform log retention and access controls are unverified.

### Imports, exports and backups

- CSV exports are generated in the browser and downloaded to the user's device; export code does not upload the generated file. Exports include inventory/catalog/store data; the users export contains names, email addresses, roles and territories; activity-log export contains usernames, IP addresses, error messages and activity details. A comprehensive report can include current-user name/email and recent movement rows with actor names. The application cannot establish how a user's device stores or shares a download.
- CSV imports are read in browser memory and submitted to the API for validation and persistence; no external import processor is evidenced.
- The existing Railway application is SQLite-backed on a persistent volume. A read-only Railway check found no SaaS PostgreSQL service provisioned. The future SaaS PostgreSQL backup schedule, backup expiry, restore owner, and deletion-ledger recovery process therefore cannot yet be verified. The legacy SQLite restore flow creates a pre-restore database copy; no cleanup/retention period for those copies was found.

## Native client data

- Login collects email/password and a remember-me choice. The app sends the credentials to the API; the CSRF token is held for requests and is not persisted.
- The client stores the access token, refresh token and expiry in Expo SecureStore. User identity/role and inventory/search/login state otherwise appear to remain in process memory; no local database, inventory cache, analytics or crash-reporting SDK is evidenced in the direct mobile dependencies/source.
- The mobile inventory view receives item/part/store IDs and descriptions, quantity, minimum threshold, allocation state and work-order reference. It is read-only in the reviewed client.
- Logout or a rejected refresh clears the stored session; transient refresh/logout failures preserve it for retry. No client-side account/tenant deletion workflow exists.
- `app.json` contains no explicit camera, location, contacts, microphone, or photo-library permission declarations. This source inspection does not verify generated iOS privacy manifests/entitlements, Android merged permissions, EAS build behavior, or store-side declarations.

## Processors and external service boundaries evidenced by code

| Service/boundary | Data sent or handled | Verification state |
| --- | --- | --- |
| Railway hosting | Existing app service and mounted SQLite volume; deployment/runtime logs may also be handled by the platform | Current project inspected read-only; log retention/settings not verified. No SaaS PostgreSQL service is provisioned. |
| Resend API | Invitation recipient and invitation message/link sent from the mail worker | API integration is present in code; production configuration and Resend retention/region terms not verified. |
| SMTP relay | Password-reset recipient and reset link | Provider is configured through environment variables, but actual runtime provider/settings are not verified. |
| Expo / Apple / Google | Mobile app build and distribution | Direct mobile dependencies include Expo/React Native modules; actual built binary and store data declarations are not reviewed here. |
| Analytics/crash reporting | No direct app or backend analytics/crash SDK was found in the reviewed source/dependencies | Hosting-level diagnostics and platform telemetry are outside this repository audit. |

## Decisions and verification still required

- Set and approve retention periods and deletion behavior for accounts, organizations, sessions, invitations/outbox, activity/audit records, local log files, backups and restore copies. Existing cleanup mechanisms do not define a complete retention policy.
- Select and provision the SaaS PostgreSQL provider; verify actual backup schedule/expiry, restore procedure, access controls, operational owner, and a deletion ledger that survives restore.
- Identify the configured SMTP provider and verify its data processing, region, retention and access terms. Review the Resend terms/configuration for invitation mail before making a processor disclosure.
- Confirm whether activity details, customer/work-order fields, equipment notes and exports contain additional personal data in ordinary use; do not infer example production content from schema fields.
- Inspect production runtime logging/analytics configuration and retention without exposing secrets or customer data.
- Build the exact iOS/Android release artifacts and inspect generated manifests, SDKs and store declarations before completing Apple/Google privacy disclosures.
- Obtain the approved legal/business retention basis and public support contact before publishing a privacy policy or enabling account/tenant deletion.

## Source references

- PostgreSQL schema and tenant policies: `backend/postgres_migrations/v0001_core_schema.py`, `v0002_tenancy.py`, `v0003_tenant_policies.py`, `v0004_tenant_administration.py`, `v0005_hashed_sessions.py`, `v0006_native_refresh_credentials.py`.
- Authentication, users, invitations and logs: `backend/routes/auth.py`, `backend/routes/users.py`, `backend/routes/invitations.py`, `backend/app_activity.py`, `backend/services/activity.py`, `backend/routes/history.py`, `backend/routes/superadmin.py`.
- Mail and runtime: `backend/services/mail_payloads.py`, `backend/services/mail_delivery.py`, `backend/services/mail_outbox.py`, `backend/mail_worker.py`, `backend/email_service.py`, `backend/logging_config.py`, `docs/environment.md`, `docs/saas-cutover-runbook.md`.
- Browser exports/imports: `static/js/inventory/exports.js`, `static/js/inventory/stock-imports.js`.
- Native client: `mobile/package.json`, `mobile/app.json`, `mobile/src/api/client.ts`, `mobile/src/app/index.tsx`, `mobile/README.md`.
- Deletion policy status: `docs/superpowers/specs/2026-10-17-member-account-tenant-deletion-policy.md`.