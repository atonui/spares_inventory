# SaaS Email Change Verification Design

**Status:** Design approved in chat on 2026-10-17. Implementation plan is prepared separately for review; approval of this design does not authorize code changes.

## Goal

Require proof of control of a new email address before replacing an existing user's email in the PostgreSQL SaaS service. Keep the current address usable for sign-in and recovery until confirmation succeeds. Deliver verification and change notifications through the encrypted transactional mail outbox.

## Evidence from the current repository

- `backend/routes/auth.py` implements `PUT /api/profile`. In PostgreSQL mode, the current handler checks whether the submitted address is already in `users`, then updates `users.email` immediately. It also updates `display_timezone` in the same handler.
- `static/js/pages/profile.js` currently loads `/api/profile` and edits the display timezone through `PUT /api/profile`. The page shows the current email but has no email-change form or pending-verification state.
- The versioned native API is an allowlist in `backend/services/api_v1_openapi.py`. It currently exposes `GET /api/v1/csrf-token`, native login and refresh, `GET /api/v1/me`, inventory, and logout. It does not expose profile or email-change operations.
- The mail outbox currently permits `organization_invitation` and `password_reset` in `backend/services/mail_outbox.py` and the PostgreSQL check constraint in `backend/postgres_migrations/v0008_password_reset_mail.py`. Delivery templates are dispatched in `backend/services/mail_delivery.py`.
- The PostgreSQL SaaS runtime uses session-derived user and company context. Existing authentication dependencies and `authenticated_write_transaction` are used by profile writes. Email change is a user-account operation and must not accept a company ID from the client.
- The current native API uses opaque server-managed bearer access credentials and rotating refresh credentials. Email-change routes are not currently part of that contract.
- `docs/superpowers/specs/2026-10-15-saas-foundation-design.md` establishes the product requirement that email changes require proof, tokens are random, single-use, expiring, and stored as hashes, and the existing email remains until verification.

## Confirmed direction

These points are approved by the project owner and constrain the implementation plan:

1. The existing email remains the account's active email until the new address is verified.
2. A separate pending email-change request stores the proposal; it does not overwrite `users.email`.
3. Verification uses a random, single-use, expiring token. Only a hash of the token is persisted.
4. Verification mail uses the encrypted mail outbox.
5. Email uniqueness is rechecked when confirmation is processed, not only when a request is created.
6. After a successful change, notify the old address.
7. Preserve legacy SQLite behavior until the SaaS cutover. This design changes the PostgreSQL SaaS flow; it does not require turning the legacy SQLite email edit into a verification flow before cutover.

## Proposed user experience

### Request a change

- On the profile page, the user enters a proposed address and submits it while authenticated.
- Show the current verified address separately from the proposed address and a pending-verification message.
- Do not display the token or the complete verification URL in application logs, activity details, API responses, analytics, or browser storage.
- A successful response says that instructions were sent if the request could be processed. The message must not reveal whether another account owns the proposed address.
- A user may cancel the pending request from the profile page. Starting a replacement request invalidates the prior pending token.

### Confirm the change

- The verification link opens a simple confirmation page or app route that submits the token to the SaaS API.
- Confirmation does not require the user's old session: the token itself is the proof-of-control capability. It is scoped to one user and one proposed address, expires, and can be consumed once.
- On success, show that the email was changed and that the old address was notified. The user can sign in with the new address after the change.
- Invalid, expired, already-used, canceled, or superseded tokens return a safe generic response that does not reveal account or address ownership.

## Proposed data model and token lifecycle

Add a PostgreSQL table through an immutable migration, tentatively named `email_change_requests`:

| Field | Purpose |
|---|---|
| `id` | Request identity |
| `user_id` | Account whose email may change; foreign key to `users` |
| `proposed_email` | Proposed canonical email, not active until success |
| `token_hash` | Hash of a high-entropy random token; unique |
| `created_at`, `expires_at` | UTC instants |
| `consumed_at`, `canceled_at` | Terminal lifecycle markers |

Recommended constraints/indexes: unique token hash; lookup index on user and active state; database constraint or transaction logic ensuring at most one active request per user. Keep expired/canceled rows for operational/audit purposes only under the SaaS retention policy; no retention duration is decided by this design.

Recommended token behavior for review:

- Generate at least 32 bytes of cryptographically secure randomness and encode URL-safely.
- Store a cryptographic hash of the token; compare by hashing the presented token. Do not persist the raw token outside the encrypted mail payload.
- Expire after one hour, matching the current password-reset lifetime. This duration is a recommendation, not a confirmed product decision.
- A new request atomically cancels the user's previous active request and inserts a new one. A replay of a canceled or consumed token cannot change the address.
- At confirmation, lock the request and user rows in a single transaction, recheck the request is active and unexpired, recheck proposed-email uniqueness, update `users.email`, mark the request consumed, enqueue the old-address notification, and record a privacy-minimal audit event. If any required transaction step fails, none of those database changes commit.
- If the proposed address became occupied after the request was made, do not change the active email. Return a generic conflict/expired-style result; preserve enough status for the user to make a new request without disclosing who owns the address.

### Email canonicalization and uniqueness

The existing `users.email` column is unique, and profile validation uses Pydantic `EmailStr`, but this design does not establish that existing SaaS rows are consistently lowercased or that uniqueness is case-insensitive. Recommended behavior is trim and lowercase the proposed address before checking and storing it, and use a case-insensitive uniqueness check at both request and confirmation. Before implementation, inspect existing production/cutover data and settle whether a migration or normalization is needed; do not silently rewrite all existing addresses as part of this feature.

## Proposed HTTP API

Exact route names and response codes are proposed for review. They must be reflected in the v1 OpenAPI allowlist and generated contract if adopted.

| Method and path | Authentication | Purpose |
|---|---|---|
| `POST /api/v1/me/email-change-requests` | Native bearer; active authenticated user | Request verification for a proposed email |
| `GET /api/v1/me/email-change-request` | Native bearer; active authenticated user | Read the caller's pending status and expiration, without returning a token |
| `DELETE /api/v1/me/email-change-request` | Native bearer; active authenticated user | Cancel the caller's pending request |
| `POST /api/v1/auth/email-change/confirm` | No session required; valid one-time token required | Confirm the new email and notify the old address |

All authenticated routes derive user and tenant context from the server-side session. They must not accept `user_id`, `organization_id`, or company scope in request data. Company role is not an authorization gate: a user's own verified login address is account-level data. Platform administrators must use the same user-scoped verification process for their own account.

Proposed request/response examples:

```http
POST /api/v1/me/email-change-requests
Authorization: Bearer <access-token>
Content-Type: application/json

{"email":"person@example.com"}
```

```json
{"success":true,"message":"If this address can be used, verification instructions have been sent."}
```

```http
POST /api/v1/auth/email-change/confirm
Content-Type: application/json

{"token":"<single-use-token>"}
```

```json
{"success":true,"message":"Email address updated. A notice was sent to the previous address."}
```

The status endpoint should return only `pending`, proposed address masked for display, and UTC expiration time, or an empty/no-pending result. It must never return a token or verification URL. The cancellation endpoint returns a stable success result whether or not a request was pending. To prevent this endpoint from becoming an address-enumeration oracle, an already-registered target also gets a one-hour, non-deliverable pending record. The request response and pending status remain the same, but no verification mail is enqueued and confirmation rejects that record. Replacing or canceling the request invalidates it like any other pending request.

## Mail behavior and database permissions

- Add an `email_change_verification` message type. Its encrypted payload contains the verification URL and expiry needed by the template; the recipient is the proposed address.
- Add an `email_changed_notice` message type. Its encrypted payload contains the minimum details needed for the notification; the recipient is the old address. Do not include the verification token in this message.
- Keep URL construction restricted to the configured frontend base URL, following the password-reset mail helper. Do not trust a host or callback URL supplied by the client.
- Enqueue verification mail in the same transaction that creates/replaces the pending request. Enqueue the old-address notice in the same transaction as successful confirmation and email update.
- Extend both the application message-type allowlist and the PostgreSQL `mail_outbox` check constraint in a new migration. Update provider-independent template tests and ensure invalid URLs/payloads fail closed.
- Preserve the mail worker's separate database identity and current restricted permissions. Its grants must cover only the new message rows through the existing outbox columns; do not grant access to user or request tables.
- Avoid placing raw tokens or full verification URLs into logs, activity metadata, sanitized provider errors, or unencrypted database columns.

## Session and security behavior needing owner decision

**Recommendation:** keep existing sessions active after email change. The email is an identifier, not an authenticator, and the user has already authenticated to request the change and proved control of the new address. This matches the current session model and avoids unexpectedly logging the user out across devices.

This is not yet approved. Alternatives are revoking all user sessions or revoking all except the confirming session. If revocation is selected, native refresh credentials and browser sessions must be invalidated consistently in the same confirmation transaction, and the success UX must explain the sign-in requirement. The implementation plan must not assume a session policy until this choice is confirmed.

Other security requirements:

- Authenticated request and cancellation routes require CSRF validation for cookie-backed web calls; native bearer calls use the v1 bearer transport and do not depend on browser cookies.
- The unauthenticated confirmation route must be a POST and must not mutate state on GET, so link scanners do not consume tokens. The confirmation page may load on GET, then submit the token after an explicit user action. Put the token in the URL fragment rather than the query string: browsers do not send fragments in page requests or HTTP referrers. The page reads the token into memory and removes it from the visible URL before the user submits. Use `Referrer-Policy: no-referrer` and no third-party scripts on that page.
- Apply a request rate limit. Recommended starting limit: 3 requests per authenticated user per hour and a reasonable IP limit on confirmation attempts; exact thresholds are implementation/operations choices.
- Use generic responses for addresses already registered and for invalid confirmation tokens. Do not write the proposed address or token to routine application logs.
- Ensure DB transaction helpers enforce the existing SaaS row-level security and user/company context. The email-change operation is user-scoped; a caller can only mutate their own `users.email` and request row.
- A token is a bearer capability: protect it from URL referrer leakage, access logs, analytics, crash reporting, and browser history where feasible. The final UI should exchange it promptly and remove it from the visible URL after submission.

## Web profile behavior

- Keep the existing display-timezone save flow independent; changing timezone must not create or cancel an email-change request.
- Add a distinct email-change form and pending state. Display the current address as active until confirmation.
- Do not reuse the current `PUT /api/profile` email field for the verified SaaS flow. For PostgreSQL SaaS, reject/ignore direct email mutation through that legacy profile update path after the new endpoint is live. Preserve direct SQLite behavior until cutover as agreed.
- Provide cancel/retry affordances and accessible status/error text. Never indicate success before the verification token has been consumed and `users.email` updated.
- Add the confirmation page to the static app using the existing design tokens and brand styling; no workflow beyond email verification should change.

## SQLite compatibility and rollout

- PostgreSQL SaaS: use the new request/confirm flow.
- Legacy SQLite: retain the current direct profile email update until the separately planned SaaS cutover. Do not create SQLite-only token tables or pretend SQLite email changes have verification.
- The server must clearly branch by backend mode so the API cannot accidentally offer unverified direct email changes in PostgreSQL after rollout.
- The migration is additive: create the request table and extend the outbox message-type constraint. It must not rewrite `users.email` or existing session records.
- Operational provisioning remains separate from application migrations. Existing `DATABASE_URL`, `MAIL_WORKER_DATABASE_URL`, `MIGRATION_DATABASE_URL`, and mail encryption/provider configuration continue their current roles; no secret values belong in this document.

## Testing and acceptance criteria

Before merge, tests should prove:

1. Requesting a change leaves `users.email` unchanged and creates only one active pending request.
2. Raw tokens are absent from persistent request rows, logs, API responses, and activity metadata; only a hash is stored and the encrypted outbox contains the delivery payload.
3. A second request invalidates the first token; consumed, expired, canceled, malformed, and replayed tokens cannot change the email.
4. Confirmation updates the email and consumes the token exactly once, with uniqueness rechecked under concurrent confirmation/request activity.
5. A target address claimed by another user after request creation cannot be assigned; no partial user update or notification occurs.
6. Verification mail is enqueued atomically with request creation; old-address notice is enqueued atomically with successful email change. Outbox/provider failures do not partially update application state.
7. Authenticated routes can mutate only the current user; foreign user IDs and organization IDs are not accepted. PostgreSQL integration tests exercise actual RLS/transaction context and role grants.
8. Cookie-backed routes enforce CSRF; native v1 endpoints enforce bearer authentication; confirmation is token-authorized and GET does not consume tokens.
9. Rate limits, generic responses, and safe API error shapes are covered.
10. Profile timezone updates remain unchanged; PostgreSQL direct email edits are no longer possible through the old profile update path; SQLite compatibility is tested.
11. The OpenAPI v1 document includes all adopted endpoints, request and response schemas, auth requirements, error responses, and operation behavior.
12. Mail delivery tests cover both new message types without making live provider calls.

## Out of scope

- New-account email verification, invitation acceptance redesign, or broader account recovery changes.
- Account deletion, tenant lifecycle, membership cardinality, retention policy, or billing.
- Changing the email used by an existing invitation or rewriting historical activity.
- Mobile client implementation. The API contract should support native clients, but this work remains SaaS backend and web profile behavior.
- Production deployment, mail provider changes, or credential provisioning.

## Approved implementation decisions

The owner approved this design on 2026-10-17, including its recommendations to retain existing sessions, use a one-hour token lifetime, lowercase newly proposed email addresses, enforce case-insensitive uniqueness, and adopt the proposed v1 routes and status-response shape. Existing stored addresses must not be rewritten automatically. Before applying the case-insensitive unique index to any shared SaaS database, inspect existing rows for collisions and stop for separate remediation review if any are found.

The plan proposes an initial confirmation-attempt limit of 5 per IP per minute, matching the existing invitation-acceptance limit. That exact confirmation threshold was not specified in the approved design and remains a plan-level choice for review.
