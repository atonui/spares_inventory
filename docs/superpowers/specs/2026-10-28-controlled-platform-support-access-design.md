# Controlled Platform Support Access Design

**Status:** Approved for implementation on 2026-10-28. Implementation follows the approved task plan.

## Intent

Give platform administrators a narrow way to resolve customer account-access and inventory/equipment issues when the tenant cannot diagnose them. Support access is explicit, read-only, scoped to one organization, visible to the operator, and audited. Ordinary platform administration continues to reveal organization metadata only; tenant users and operational records remain unavailable until a support session is active.

## Decisions captured from the product discussion

- The first support slice covers both account-access and inventory/equipment troubleshooting.
- Use a temporary live support session scoped to one organization.
- Require the platform administrator to re-enter their password when starting a session. MFA is not currently implemented.
- Include equipment serial numbers and assigned staff names in the scoped operational view.

Other values below are design recommendations based on the current authorization model and least-privilege requirements. They need review as part of approval.

## Goals

- Let an authenticated platform administrator investigate an issue in one selected organization without becoming a tenant user or changing identity.
- Limit each session to approved read operations and approved fields for the account and operational support views.
- Make the active organization, operator, reason, and expiry obvious in the UI, with an immediate end action.
- Validate platform authority, current login session, support-session state, and target organization on every support request.
- Preserve PostgreSQL row-level security (RLS) by setting transaction-local context only to the organization recorded in the validated server-side support session.
- Record session creation, each successful data read, denied support access, and explicit session end in platform audit history without storing returned customer data in audit details.

## Non-goals and anti-goals

- No tenant impersonation, customer JWT, user-password use, writes, arbitrary SQL, generic tenant browser, export, attachment access, or access to more than one organization per session.
- No global user-directory search. A user search is available only inside the selected organization and only while its support session is active.
- No access to passwords, password hashes, reset tokens, raw session credentials, session IP addresses or user-agent strings, customer names, free-text work-order descriptions, or notes.
- No global RLS bypass, database-owner connection, `BYPASSRLS` role, or policy that grants platform administrators general tenant-table access.
- No claim that MFA or password-policy enforcement exists.

## Approaches

1. **Scoped live support session — selected.** The platform administrator selects one organization, gives a reason, confirms their password, and receives a short-lived read-only session. This is the most useful workflow for live account and stock troubleshooting while keeping each request constrained to one tenant and a fixed resource/field allowlist.
2. **Tenant-generated diagnostic bundle.** A tenant administrator generates a fixed export for support. It gives the platform team less direct access but depends on the tenant being available and may be stale, so it does not cover the selected live troubleshooting need.
3. **Impersonation or a broad platform data browser — rejected.** Both undermine the current separation between platform and tenant principals, expose more data than the stated support cases need, and conflict with the existing RLS model.

## Proposed session flow

1. From the platform organization directory, an administrator selects one organization and chooses **Start support session**.
2. The server verifies the live authenticated session and platform-admin status, checks the organization exists, validates a 10–500 character reason, and verifies the administrator's current password. Passwords are never logged or stored by the support-session feature.
3. The server creates a support-session record bound to the administrator, the current server-side authentication session, the selected organization, the reason, and an expiry 15 minutes after creation. One active support session is allowed per platform login session; there is no extension. Starting another requires ending or waiting out the current session and confirming the password again.
4. The UI enters a support view with a persistent banner naming the organization, showing the reason and expiry, and offering **End support session**. Navigation outside the support view does not hide or silently preserve access; returning to support shows the banner while the session remains valid.
5. Every read request supplies the support-session identifier. The server reloads the authenticated principal and checks that the same authentication session is active, the actor still has platform-admin access, the support session is live and unended, and the organization matches. It then sets `app.organization_id` transaction-locally to that session's organization and executes only the endpoint's fixed query.
6. Ending the session marks it ended server-side. Logout, password change/session revocation, or platform-admin revocation also invalidates or ends sessions bound to the affected login/admin. Expiry is enforced on every request; an expired support session cannot be extended or reused.

The support view is available for active or suspended organizations. This supports investigation of suspension and access problems; suspension does not grant extra resources or write capability. This is a design recommendation and should be revisited if product policy forbids support access to suspended tenants.

## Initial data allowlist

All operational-data queries include the support-session organization ID and run under RLS. The `users` and `organization_memberships` tables are not tenant-RLS tables in the current schema, so account lookups must use an explicit join through the active support-session organization and an exact email predicate; they must never query users globally. Lookup inputs and result sizes are bounded. Initial lookups are exact or prefix searches by tenant-local identifiers; they are not unfiltered organization-wide dumps.

| View | Allowed fields | Explicitly excluded |
|---|---|---|
| Account access | User ID, name, email, archived state; organization membership role and active state; failed-login count, lockout-until, and last-login timestamps | Password/hash, reset credentials, raw or hashed session credentials, session IP/user-agent, unrelated tenants' identities |
| Inventory and parts | Part number, description/category, store name/type/location, on-hand quantity, minimum threshold, update time, and related work-order number/status | Unit cost, customer name, free-text work-order description, notes |
| Equipment and calibration | Equipment name, make/model, serial number, status, calibration certificate number/authority/dates, assigned staff name, and relevant structured history fields | Free-text notes, attachments, broad employee roster |
| Stock movements/transfers | Movement type, part number, quantity, source/destination store, work-order number, timestamps, transfer status, and assigned/completing staff name where needed | Notes, completion notes, IP/user-agent, arbitrary activity-log details |

For account access, the administrator must search by an exact email or choose a user already surfaced by an exact in-tenant lookup. The result must not confirm whether that email belongs to a user in another organization. Operational lookups use a part number, equipment serial number, or work-order number and return a bounded page (proposed maximum 25 rows).

This allows staff names in the work record involved in the support case without adding an all-tenant or organization-wide staff directory.

## Authorization and persistence boundaries

- The current PostgreSQL auth model has stable server-side `sessions.id` values and stores only `session_token_hash` for web/native credentials. Token refresh rotates the hash while retaining the session row ID; logout, password change, and session revocation deactivate session rows. Bind a support session to that row ID, not to the rotating raw credential. `resolve_principal` already validates session activity/expiry and current `platform_admins` membership; reuse those checks on every request.
- `users` and `organization_memberships` are not in the current tenant RLS table set. Account lookups therefore require explicit organization membership joins and exact in-organization lookup predicates. Operational tables including stores, parts, work orders, inventory, movements, transfers, equipment, and equipment history have RLS policies on `app.organization_id`.
- Password confirmation can use the existing password-verification function and the administrator's stored password hash; never duplicate or alter password storage for this feature.
- There is currently no platform organization hard-delete route, and the core plan defers tenant deletion. If a future deletion workflow is approved, it must end support sessions before deleting the organization. Until then, an organization that disappears between support requests causes the request to fail closed and the UI to clear its cached support data.

- Add a platform-owned support-session table with a random UUID identifier, actor user ID, authentication-session ID, organization ID, reason, created/expiry timestamps, and nullable ended timestamp. Do not store the password or authentication token. The authentication-session ID is resolved server-side from the hashed current credential.
- Add a dedicated `authenticated_support_transaction` helper. It must resolve the caller from the current credential, require current platform-admin authority, verify the support row is bound to that caller and current authentication session, verify it is unexpired and unended, then set transaction-local tenant context from the support row only.
- Keep support routes separate from ordinary `authenticated_platform_transaction` and `authenticated_tenant_transaction`. They must not accept an organization ID as authority on each data request; the organization comes from the validated support row.
- Do not change tenant RLS policies to grant platform access. Test with the restricted runtime role described in `docs/saas-cutover-runbook.md`, never with the migration/table-owner role.
- Platform-admin revocation and logout/password change must prevent further reads from bound support sessions. End/revocation state should be changed in the same transaction as the corresponding platform-admin or authentication-session mutation when practical.

## Audit and failure behavior

- Use `platform_audit_events`; retain actor and organization in dedicated columns. Add allowlisted event actions for support-session start, support data read, denied access, and end. Store only the support-session ID, resource class, operation, outcome, reason where appropriate, and a server-generated request correlation ID. Do not store query strings, returned rows, emails, serials, notes, or password input in event details.
- Record the reason on session creation. Record each successful endpoint read after authorization and within the transaction that performed the read. Denied attempts by an authenticated platform administrator should be recorded where the actor and target organization are known, without echoing customer data. Because a rejected request rolls back its request transaction, persist denial events in a separate narrowly scoped audit transaction before returning the generic error. Unauthenticated attempts must not reveal whether a support session or tenant exists.
- When access is denied, return a generic 401/403/404 appropriate to authentication, authority, or absent support session. Do not fall back to normal platform or tenant query behavior.
- Enforce the 15-minute expiry in the authorization check even if no scheduled cleanup runs. The stored expiry timestamp is the authoritative expiry evidence; a later access attempt may additionally produce an expiry audit event. Do not claim an exact-time expiry event unless an expiry worker is added.
- If audit insertion fails, fail the support read closed; do not return tenant data without the corresponding read audit event.

## UI behavior

- Add a start-session confirmation that includes the selected organization, reason field, and password confirmation field. Clear the password from browser state immediately after the request completes.
- Keep the support workspace visually distinct from normal platform administration and show a persistent banner with organization, reason, expiry countdown, and end action.
- Show only the allowlisted account and operational lookup screens. Each screen has loading, empty, error, and retry states. Do not render data as HTML.
- On session expiry, logout, session invalidation, organization deletion, or platform-admin revocation, clear the support workspace data and return to the platform console.

## Acceptance criteria

- A platform administrator can start a support session only after valid password confirmation, a reason, and selection of one organization.
- A request without a valid, bound, unexpired support session returns no tenant data; wrong-organization IDs cannot widen the session.
- RLS denies tenant reads with no support context or a different organization context; the support helper can read only the selected organization's allowlisted data under the restricted runtime role.
- Session expiry, explicit end, logout, password change/session revocation, and platform-admin revocation prevent subsequent tenant reads.
- Tests prove that search results, joins, staff names, serials, history, pagination, and errors do not cross tenant boundaries or expose excluded fields.
- Successful reads and denied support attempts have curated audit events, and audit failures prevent data from being returned.
- The ordinary platform organization list and other platform screens continue to expose no tenant user roster or inventory data.

## Open implementation choices

- Whether the 15-minute maximum should be a constant or a future product setting. Recommendation: constant for the first release; do not add a configurable policy until there is an operational owner for it.
- Whether every read should be a separate audit row. Recommendation: yes for this low-volume, short-lived workflow; avoid coalescing reads until actual audit volume demonstrates a need.
- Whether a tenant administrator must separately approve a support session. Recommendation: no for this first slice because the stated goal includes helping when the customer cannot respond; require an explicit platform-admin reason and password step-up instead, and include all access in the tenant-facing audit surface only if/when one exists.
